#include "stdafx.h"
#include "TlbSplit.h"

#define PAGE_SHIFT	12
#define PAGE_SIZE	(1ui64 << PAGE_SHIFT)
#define PAGE_MASK	(~(PAGE_SIZE-1))

PatchManager::PatchManager() {
	hypervisor_support = tlbsplit::hypervisorSupportPresent();
};

bool PatchManager::addPatch(void* patchAddr, int patchSize) {
	bool result = false;
	size_t page_start = ((size_t)patchAddr)&PAGE_MASK;
	size_t page_end = (patchSize-1+(size_t)patchAddr)&PAGE_MASK;
	printf("addPatch for %llx-%llx\n",page_start,page_end);
	if (patches.find(page_start)==patches.end()) {
		printf( "patch registered for %llx\n",page_start);
		patches.insert(page_start);
		if (hypervisor_support) {
			ensureCopyOnWrite((PVOID)page_start);
			tlbsplit::setDataPage((PVOID)page_start,(PVOID)page_start);
		}
		result = true;
	}
	if (page_start!=page_end && patches.find(page_end)==patches.end()) {
		printf("patch registered for tail %llx\n",page_end);
		patches.insert(page_end);
		if (hypervisor_support) {
			ensureCopyOnWrite((PVOID)page_end);
			tlbsplit::setDataPage((PVOID)page_end,(PVOID)page_end);
		}
		result = true;
	}
	return result;
};

int PatchManager::protectAll() {
	if (hypervisor_support) {
		for (auto myit = patches.begin();myit!=patches.end();myit++) {
			size_t curval=*myit;
			printf("activating for %llx\n",curval);
			if (!tlbsplit::activatePage((PVOID)curval))
				return 0;
		}
		int result = (int)patches.size();
	    pantheios::log(pantheios::informational, "Total of ",pantheios::integer(result)," pages protected");
		return result;
	} else {
	    pantheios::log(pantheios::informational, "Total of ",pantheios::integer(patches.size())," pages registered. No hypervisor support found.");
	    return 0;
	}
};

void PatchManager::ensureCopyOnWrite(PVOID addr) {
	MEMORY_BASIC_INFORMATION mBuffer;
	VirtualQuery(addr,&mBuffer,sizeof mBuffer);
	if (mBuffer.Protect == PAGE_EXECUTE || mBuffer.Protect == PAGE_EXECUTE_READ || mBuffer.Protect == PAGE_EXECUTE_WRITECOPY) {
	    pantheios::log(pantheios::informational, "Page at ",pantheios::pointer(addr,pantheios::fmt::hex)," is protected ",pantheios::integer(mBuffer.Protect,pantheios::fmt::hex)," calling VirtualProtect");
		DWORD dwOldProtect;
		DWORD dwSize = 2; 
		if (!VirtualProtect (addr,    
						 dwSize,    // Length, in bytes, of the set of pages 
									//to change
						PAGE_EXECUTE_READWRITE, // What to change it to
						 &dwOldProtect  // Place to store the old setting
						 ))
			pantheios::log(pantheios::error, "Virtual protect failed at ",pantheios::pointer(addr,pantheios::fmt::hex));
		BYTE val = *(PBYTE)addr;
		*(PBYTE)addr = val;
	} else 
	    pantheios::log(pantheios::informational, "Page at ",pantheios::pointer(addr,pantheios::fmt::hex)," seeks OK: ",pantheios::integer(mBuffer.Protect,pantheios::fmt::hex)," leaving it 'as is'");
};