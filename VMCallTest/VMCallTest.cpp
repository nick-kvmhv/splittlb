// VMCallTest.cpp : Command line test for TLB split calls in hypervisor 
//

#include "stdafx.h"
#include "TLBSplit.h"

#if defined _M_X64
#ifdef _DEBUG
#pragma comment(lib, "libMinHook-x64-v110-mtd.lib")
#else
#pragma comment(lib, "libMinHook-x64-v120-mt.lib")
#endif
#elif defined _M_IX86
#pragma comment(lib, "libMinHook.x86.lib") //Copy paste, should never happen
#endif

enum enum_commands {once,many,codendata,hook,write};

void __stdcall printit(int jmpCounter, void* address) {
		printf("Iteration: %d value: %x\n",jmpCounter,*(DWORD*)address);
}

int _tmain(int argc, _TCHAR* argv[])
{
  enum_commands command = once;
  DWORD count = 1;
  if (argc >= 2) {
	  if (wcscmp(argv[1],L"/once")==0)
		  command = once;
	  else if (wcscmp(argv[1],L"/many")==0) {
		  command = many;
		  count = 100;
	  } else if (wcscmp(argv[1],L"/codendata")==0)
		  command = codendata;
	  else if (wcscmp(argv[1],L"/hook")==0)
		  command = hook;
	  else if (wcscmp(argv[1],L"/write")==0)
		  command = write;
	  else {
		  printf("Invalid command: %S\n", argv[1]);
		  return 1;
	  }
	  if (argc == 3) {
			_TCHAR * errp;
			count = wcstoul (argv[2],&errp,10);
	  }
  }

  bool rc = false;
  size_t readval = 0;
  DWORD dwOldProtect = 0;
  size_t coderef = 0;
  int counter = 0;
  /* 
	Searching here for the immediate value that should be present somewhere in the code. Taking 2nd occurence because the first occurence is this loop. 
	Optimization has to be disabled for this to work or C++ gets smart and stores it in a register.
  */
  for (int i = 0; i < 4096; i++) {
	  if ( *(size_t*)(((size_t)&_tmain)+i) == 0x1234567890ui64) {
		  counter++;
		  if (counter==2) {
			  coderef = ((size_t)&_tmain)+i;
			  printf("Found it at %llx\n",coderef);
			  break;
		  }
	  }
  }
  if (coderef==0) {
	  printf("Not Found the pattern\n");
	  return 1;
  }
  
	if (!VirtualProtect ((void*)coderef,    
						 4096,    // Length, in bytes, of the set of pages 
									//to change
						PAGE_EXECUTE_READWRITE, // What to change it to
						 &dwOldProtect  // Place to store the old setting
						 ))
						 printf("Virtual protect failed");


  rc = tlbsplit::hypervisorSupportPresent();

  
	  if (command == once||command == many) {
		if (rc) {

			  size_t codevalue = coderef;
			  readval = *(size_t*)(codevalue);
			  *(size_t*)(codevalue) = readval;

			  printf("Value before VMCALL: %llx hypervisor support: %d\n",readval,rc);
			  rc = tlbsplit::setDataPage((void*)coderef,(void*)coderef);
			  if (!rc)
				  printf("tlbsplit::setDataPage failed\n",readval,rc);
			  else {
				  *((size_t*)codevalue) = 0x67890;
				  printf("tlbsplit::activatePage after patching %llx\n",*((DWORD*)codevalue));
				  rc = tlbsplit::activatePage((void*)coderef);
				  if (!rc)
					  printf("tlbsplit::activatePage failed\n");
				  else {
						int maxIteration = count;
						size_t *reads = new size_t[maxIteration];
						size_t *readsCode = new size_t[maxIteration];
						for (int i=0; i<maxIteration;i++) {
							size_t codeval;
							codeval = 0x1234567890ui64;   // Testing that we move in fact 0x67890 into codeval while reading the instruction shows 0x12345

							reads[i] = *(size_t*)(codevalue);
							readsCode[i] = codeval;
						}
						printf("Values:");
						for (int i=0; i<maxIteration;i++) {
							printf(" %llx/%llx",reads[i],readsCode[i]);
						}
						delete[] reads;
						delete[] readsCode;
						printf("\nValue before deactivation: %llx, iterations:%d \n",*(size_t*)(codevalue),maxIteration);
						rc = tlbsplit::deactivatePage((void*)coderef);
						if (!rc)
							printf("tlbsplit::deactivatePage failed\n");
						else
							printf("tlbsplit::deactivatePage succeeded, value after %llx\n",*(size_t*)(codevalue));
					  }
				  }
		  } else
			printf("No hypervisor support\n");
	  } else if (command == hook) {
/*
		Hooking IsDebuggerPresent function via minhooks, 
*/
			PatchManager pm;
			tlbsplit::deactivateAllPages();
			printf("At start %llx\n",*(size_t*)&IsDebuggerPresent);
			setupDebugHooks(pm);
			printf("After hooks %llx\n",*(size_t*)&IsDebuggerPresent);
			if (!pm.protectAll())
				printf("protectAll failed\n");
			else {
				printf("After protect %llx\n",*(size_t*)&IsDebuggerPresent);
				int ch = 0;
				  do {
 					  printf("Call to hooked IsDebuggerPresent:%d\n",IsDebuggerPresent());
					  if (ch=='r') {
						printf("Reding the function prologue:%llx\n",*(size_t*)&IsDebuggerPresent);
					  }
					  if (ch=='w') {
						printf("Triggering memory write :%llx\n",*(size_t*)&IsDebuggerPresent);
						  size_t val = *(size_t*)&IsDebuggerPresent;
						  val++; val--;
						  *(size_t*)&IsDebuggerPresent = val;
						printf("Value after write :%llx\n",*(size_t*)&IsDebuggerPresent);
					  }
				  } while ((ch=_getch()) != 'q');
			}
		  tlbsplit::deactivateAllPages();
	  }
  return 0;
}

