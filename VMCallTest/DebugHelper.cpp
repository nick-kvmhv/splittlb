#include "stdafx.h"
#include "tlbsplit.h"
// Helper function for MH_CreateHookApi().
 
#define LOGGER_NAME "DebugHelper"

typedef BOOL (WINAPI *type_IsDebuggerPresent)(void);
type_IsDebuggerPresent ORIG_IsDebuggerPresent = NULL;
BOOL WINAPI my_IsDebuggerPresent(void) {
	CAPTURE_CALLER_IP
	pantheios::log(pantheios::debug, "IsDebuggerPresent called"
			," Caller:",pantheios::integer(calleraddress,16 | pantheios::fmt::fullHex));
	return true;
};

typedef BOOL (WINAPI *type_GetThreadContext)(
  _In_    HANDLE    hThread,
  _Inout_ LPCONTEXT lpContext
);
type_GetThreadContext ORIG_GetThreadContext = NULL;
BOOL WINAPI my_GetThreadContext(
  _In_    HANDLE    hThread,
  _Inout_ LPCONTEXT lpContext
) {
	CAPTURE_CALLER_IP
	BOOL result = (*ORIG_GetThreadContext)(hThread,lpContext);
	if (lpContext) {
		if ((lpContext->ContextFlags & 0x00000010L)!=0) //MinHook seems to spawn GetThreadContext calls when hooking
		{
			pantheios::log(pantheios::debug, "GetThreadContext called ContextFlags:",pantheios::integer(lpContext->ContextFlags, pantheios::fmt::hex)
				," Dr0:",pantheios::integer(lpContext->Dr0, pantheios::fmt::hex)
				," Dr1:",pantheios::integer(lpContext->Dr1, pantheios::fmt::hex)
				," Dr2:",pantheios::integer(lpContext->Dr2, pantheios::fmt::hex)
				," Dr3:",pantheios::integer(lpContext->Dr3, pantheios::fmt::hex)
				," Dr6:",pantheios::integer(lpContext->Dr6, pantheios::fmt::hex)
				," Dr7:",pantheios::integer(lpContext->Dr7, pantheios::fmt::hex)
				," Caller:",pantheios::integer(calleraddress, pantheios::fmt::fullHex)
			);
		}
		lpContext->ContextFlags &= ~0x7F;
		lpContext->Dr0 = 0;
		lpContext->Dr1 = 0;
		lpContext->Dr2 = 0;
		lpContext->Dr3 = 0;
		lpContext->Dr6 = 0;
		lpContext->Dr7 = 0;
	}
	return result;
};

void makeWritable(void* addr) {

	DWORD dwOldProtect;
	if (!VirtualProtect(addr,
		4096,    // Length, in bytes, of the set of pages 
				 //to change
		PAGE_EXECUTE_READWRITE, // What to change it to
		&dwOldProtect  // Place to store the old setting
	))
		printf("Virtual protect failed");

	size_t val = *(size_t*)addr;  //make a page copy in the process address space
	val++; val--;
	*(size_t*)addr = val;

}

int setupDebugHooks() 
{

 // Initialize MinHook.
    if (MH_Initialize() != MH_OK)
    {
		pantheios::log(pantheios::error, "MH_Initialize failed");

        return 1;
    }

	//pm.addPatch(&IsDebuggerPresent,10);
    if (MH_CreateHookApiEx(L"kernel32", "IsDebuggerPresent", &my_IsDebuggerPresent, &ORIG_IsDebuggerPresent) != MH_OK)
    {
		pantheios::log(pantheios::error, "MH_CreateHookApiEx IsDebuggerPresent failed");
        return 1;
    }

	printf("isProtected b4 %d\n", tlbsplit::isPageSplit(&IsDebuggerPresent));
	makeWritable(&IsDebuggerPresent);  //make a page copy in the process address space
	//*((BYTE*)&IsDebuggerPresent + 2) = 0x31;
	//*((BYTE*)&IsDebuggerPresent + 3) = 0xc0;
	printf("isProtected after %d\n", tlbsplit::isPageSplit(&IsDebuggerPresent));

    if (MH_EnableHook(&IsDebuggerPresent) != MH_OK)
    {
		pantheios::log(pantheios::error, "MH_EnableHook IsDebuggerPresent failed");
        return 1;
    }

	//pm.addPatch(&GetThreadContext,10);
	if (MH_CreateHookApiEx(L"kernel32", "GetThreadContext", &my_GetThreadContext, &ORIG_GetThreadContext) != MH_OK)
    {
		pantheios::log(pantheios::error, "MH_EnableHook GetThreadContext failed");
        return 1;
    }

	makeWritable(&GetThreadContext);

	if (MH_EnableHook(&GetThreadContext) != MH_OK)
    {
		pantheios::log(pantheios::error, "MH_EnableHook GetThreadContext failed");
        return 1;
    }

	pantheios::log(pantheios::informational, "DebugHelper hooks installed");
	return 0;
};

int releaseDebugHooks() 
{
    // Disable the hook for MessageBoxW.
    if (MH_DisableHook(&IsDebuggerPresent) != MH_OK)
    {
        return 1;
    }

    // Uninitialize MinHook.
    if (MH_Uninitialize() != MH_OK)
    {
        return 1;
    }

	return 0;
};