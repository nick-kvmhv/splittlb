#include "stdafx.h"
#include "genericHook.h"


#define MAX_HOOKS 100
//extern "C" void genericHookDispatch();
extern "C" void* genericHookDispatchBody;
extern "C" void* handlerAddress;
extern "C" void* jumpOutAddress;
extern "C" void* genericHookDispatchEnd;
extern "C" void captureXMMs(PVOID regs);
extern "C" void restoreXMMs(PVOID regs);

namespace genericHook {

	const int MEMORY_BLOCK_SIZE = 0x1000;
	const size_t MAX_MEMORY_RANGE = 0x40000000;

	class mem_block {
	public:
		LPBYTE addr;
		size_t offset = 0;

		bool has_bytes(size_t bytes) {
			return offset + bytes < MEMORY_BLOCK_SIZE;
		}
	};

	std::list<mem_block> blocks;

	LPVOID FindPrevFreeRegion(LPVOID pAddress, LPVOID pMinAddr, DWORD dwAllocationGranularity)
	{
		ULONG_PTR tryAddr = (ULONG_PTR)pAddress;

		// Round down to the allocation granularity.
		tryAddr -= tryAddr % dwAllocationGranularity;

		// Start from the previous allocation granularity multiply.
		tryAddr -= dwAllocationGranularity;

		while (tryAddr >= (ULONG_PTR)pMinAddr)
		{
			MEMORY_BASIC_INFORMATION mbi;
			if (VirtualQuery((LPVOID)tryAddr, &mbi, sizeof(mbi)) == 0)
				break;

			if (mbi.State == MEM_FREE)
				return (LPVOID)tryAddr;

			if ((ULONG_PTR)mbi.AllocationBase < dwAllocationGranularity)
				break;

			tryAddr = (ULONG_PTR)mbi.AllocationBase - dwAllocationGranularity;
		}

		return NULL;
	}

	static LPVOID FindNextFreeRegion(LPVOID pAddress, LPVOID pMaxAddr, DWORD dwAllocationGranularity)
	{
		ULONG_PTR tryAddr = (ULONG_PTR)pAddress;

		// Round down to the allocation granularity.
		tryAddr -= tryAddr % dwAllocationGranularity;

		// Start from the next allocation granularity multiply.
		tryAddr += dwAllocationGranularity;

		while (tryAddr <= (ULONG_PTR)pMaxAddr)
		{
			MEMORY_BASIC_INFORMATION mbi;
			if (VirtualQuery((LPVOID)tryAddr, &mbi, sizeof(mbi)) == 0)
				break;

			if (mbi.State == MEM_FREE)
				return (LPVOID)tryAddr;

			tryAddr = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;

			// Round up to the next allocation granularity.
			tryAddr += dwAllocationGranularity - 1;
			tryAddr -= tryAddr % dwAllocationGranularity;
		}

		return NULL;
	}

	mem_block* get_mem_block(void* pOrigin, size_t size) {
		ULONG_PTR minAddr;
		ULONG_PTR maxAddr;
		SYSTEM_INFO si;
		LPVOID allocated_address = NULL;

		GetSystemInfo(&si);
		minAddr = (ULONG_PTR)si.lpMinimumApplicationAddress;
		maxAddr = (ULONG_PTR)si.lpMaximumApplicationAddress;

		// pOrigin ± 512MB
		if ((ULONG_PTR)pOrigin > MAX_MEMORY_RANGE && minAddr < (ULONG_PTR)pOrigin - MAX_MEMORY_RANGE)
			minAddr = (ULONG_PTR)pOrigin - MAX_MEMORY_RANGE;

		if (maxAddr >(ULONG_PTR)pOrigin + MAX_MEMORY_RANGE)
			maxAddr = (ULONG_PTR)pOrigin + MAX_MEMORY_RANGE;

		// Make room for MEMORY_BLOCK_SIZE bytes.
		maxAddr -= MEMORY_BLOCK_SIZE - 1;

		for (std::list<mem_block>::iterator i = blocks.begin(); i != blocks.end(); ++i) {
			if ((ULONG_PTR)i->addr < minAddr || (ULONG_PTR)i->addr >= maxAddr)
				continue;
			if (i->has_bytes(size)) {
				return &(*i);
			}
		}

		// Alloc a new block above if not found.
		{
			LPVOID pAlloc = pOrigin;
			while ((ULONG_PTR)pAlloc >= minAddr)
			{
				pAlloc = FindPrevFreeRegion(pAlloc, (LPVOID)minAddr, si.dwAllocationGranularity);
				if (pAlloc == NULL)
					break;

				allocated_address = VirtualAlloc(
					pAlloc, MEMORY_BLOCK_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
				if (allocated_address != NULL)
					break;
			}
		}

		// Alloc a new block below if not found.
		if (allocated_address == NULL)
		{
			LPVOID pAlloc = pOrigin;
			while ((ULONG_PTR)pAlloc <= maxAddr)
			{
				pAlloc = FindNextFreeRegion(pAlloc, (LPVOID)maxAddr, si.dwAllocationGranularity);
				if (pAlloc == NULL)
					break;

				allocated_address = VirtualAlloc(
					pAlloc, MEMORY_BLOCK_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
				if (allocated_address != NULL)
					break;
			}
		}

		if (allocated_address != NULL) {
			blocks.push_back(mem_block());
			mem_block * result = &(blocks.back());
			result->addr = (LPBYTE)allocated_address;
			return result;
		}
		else
			return NULL;

	};

	bool createGenericHook(void* addrtohook, genericHookRoutine subroutine) {

		/*DWORD dwOldProtect;
		if (!VirtualProtect(&jumpOutAddress,
			4096,    // Length, in bytes, of the set of pages 
					 //to change
			PAGE_EXECUTE_READWRITE, // What to change it to
			&dwOldProtect  // Place to store the old setting
		))
			printf("Virtual protect failed");*/
		size_t copy_size = (ULONG_PTR)&genericHookDispatchEnd - (ULONG_PTR)&genericHookDispatchBody;

		if (copy_size > MEMORY_BLOCK_SIZE) {
			pantheios::log(pantheios::error, "createGenericHook:copy_size > MEMORY_BLOCK_SIZE\n");
			return false;
		}

		mem_block* block = get_mem_block(addrtohook, copy_size);

		if (block == NULL) {
			pantheios::log(pantheios::error, "createGenericHook:Memory block allocation failed for %llx\n", pantheios::pointer(addrtohook, 16 | pantheios::fmt::fullHex));
			return false;
		}

		LPBYTE targetAddr = block->addr + block->offset;
		block->offset += copy_size;
		memcpy(targetAddr, &genericHookDispatchBody, copy_size);

		size_t handlerAddress_offset = (ULONG_PTR)&handlerAddress - (ULONG_PTR)&genericHookDispatchBody;
		size_t jumpOutAddress_offset = (ULONG_PTR)&jumpOutAddress - (ULONG_PTR)&genericHookDispatchBody;

		*(genericHookRoutine*)(targetAddr + handlerAddress_offset) = subroutine;

		if (MH_CreateHookEx(addrtohook, targetAddr, (void**)(targetAddr+jumpOutAddress_offset)) != MH_OK)
		{
			pantheios::log(pantheios::error, "MH_CreateHookEx for generic hook failed");
			return false;
		}

		return true;
	}

	bool activateGenericHook(void* addrtohook) {
		if (MH_EnableHook(addrtohook) != MH_OK)
		{
			pantheios::log(pantheios::error, "activateGenericHook MH_EnableHook failed for ",pantheios::pointer(addrtohook, 16 | pantheios::fmt::fullHex));
			return false;
		}
		return true;
	}

	bool deactivateGenericHook(void* addrtohook) {

		if (MH_DisableHook(addrtohook) != MH_OK)
		{
			pantheios::log(pantheios::error, "deactivateGenericHook MH_DisableHook failed for ", pantheios::pointer(addrtohook, 16 | pantheios::fmt::fullHex));
			return false;
		}

		return true;
	}

	void captureXMMregs(XMMREGSTRUCT* regs) {
		captureXMMs(regs);
	};
	void restoreXMMregs(XMMREGSTRUCT* regs) {
		restoreXMMs(regs);
	};


}