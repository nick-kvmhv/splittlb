#include "stdafx.h"

size_t edModuleOffset; 

void patchCodeArr(size_t addr, const BYTE* value, DWORD len, PatchManager& pm) {
	DWORD dwOldProtect;
	DWORD dwSize = len; 
	LPVOID realAddr = LPVOID(adjustOffset(addr));
	if (!VirtualProtect (realAddr,    
						 dwSize,    // Length, in bytes, of the set of pages 
									//to change
						PAGE_EXECUTE_READWRITE, // What to change it to
						 &dwOldProtect  // Place to store the old setting
						 ))
	{
		pantheios::log(pantheios::error, "patchCodeArr:VirtualProtect failed @",pantheios::integer(addr, pantheios::fmt::hex));
	} else {
		PBYTE curPtr = (PBYTE)realAddr, endPtr = (BYTE*)realAddr+len;
		DWORD cntr = 0;
		pm.addPatch(curPtr,len);
		while (curPtr < endPtr) {
			if (cntr>=len)
				cntr = 0;
			*(PBYTE)curPtr++ = value[cntr++];
		}
		pantheios::log(pantheios::informational, "patchCodeArr:patched @",pantheios::integer(addr, pantheios::fmt::hex));
	}
}

size_t adjustOffset(size_t offset) {
	return offset+edModuleOffset-defaultbase;
}

int initUtils() {
	edModuleOffset = (size_t)GetModuleHandle(NULL);
	pantheios::log(pantheios::informational, "initUtils:module base determined as:",pantheios::integer(edModuleOffset, pantheios::fmt::hex));
	char moduleFileName[500];
	if (GetModuleFileNameA((HMODULE)edModuleOffset,moduleFileName,sizeof moduleFileName)==0) {
        pantheios::log(pantheios::error, "GetModuleFileNameA returned error");
		return 1;
	}
	if (strstr(moduleFileName,"EliteDangerous64.exe")==NULL) {
		pantheios::log(pantheios::error, "Module name returned as ",moduleFileName, " exiting" );
		return 1;
	} else {
		pantheios::log(pantheios::informational, "Module name returned as ",moduleFileName, " proceeding" );
	}
	return 0;
}