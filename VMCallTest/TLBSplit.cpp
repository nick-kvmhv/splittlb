#include "stdafx.h"
#include "TLBSplit.h"
extern "C" int checkhv();
extern "C" int setDataPagehv(void* pageAddr, void* data);
extern "C" int activatePagehv(void* pageAddr);
extern "C" int writeCodePagehv(void* _from, void* _to, size_t bytes);
extern "C" int deactivatePagehv(void* pageAddr);
extern "C" int deactivateAllPageshv();
extern "C" int isPageSplithv(void* pageAddr);

namespace tlbsplit {
int __forceinline IsInsideVPC_exceptionFilter(LPEXCEPTION_POINTERS ep)
{
  PCONTEXT ctx = ep->ContextRecord;

  ctx->Rax = 0; // Not running VPC
  ctx->Rip += 3; // skip past the "call VPC" opcodes
  return EXCEPTION_CONTINUE_EXECUTION; // we can safely resume execution since we skipped faulty instruction
};

bool hypervisorSupportPresent(){
   WORD result = 0;
 __try
  {
   result = checkhv();
  }
  // The except block shouldn't get triggered if VPC is running!!
  __except(IsInsideVPC_exceptionFilter(GetExceptionInformation()))
  {
  }
  return result==1;
};

bool setDataPage(void* pageAddr, void* data) {
	int rc = setDataPagehv(pageAddr,data);
	return rc!=0;
};

bool activatePage(void* pageAddr) {
	int rc = activatePagehv(pageAddr);
	return rc!=0;
};

bool writeCodePage(void* _from,void* _to, size_t bytes) {
	int rc = writeCodePagehv(_from,_to,bytes);
	return rc != 0;
};

bool deactivatePage(void* pageAddr) {
	int rc = deactivatePagehv(pageAddr);
	return rc!=0;
};

bool deactivateAllPages() {
	int rc = deactivateAllPageshv();
	return rc!=0;
};

bool isPageSplit(void* pageAddr) {
	int rc = isPageSplithv(pageAddr);
	return rc != 0;
};


}