#include "stdafx.h"
#include "PEHeaderParser.h"


PEHeaderParser::PEHeaderParser(void)
{
	HMODULE handle = GetModuleHandle(NULL);
	DWORD msdos_size = *(PDWORD)((size_t)handle+0x3C);
	pPeHeader = (PeHeader*)((size_t)handle+msdos_size);
	if (pPeHeader->mSizeOfOptionalHeader >= sizeof Pe32OptionalHeader)
		pPe32OptionalHeader = (Pe32OptionalHeader*)(((size_t)pPeHeader)+sizeof PeHeader);
	pSections = (IMAGE_SECTION_HEADER*)(((size_t)pPeHeader)+sizeof PeHeader+pPeHeader->mSizeOfOptionalHeader);
	for (int i = 0; i < pPeHeader->mNumberOfSections; i++)
		sections[std::string(pSections[i].mName)] = pSections+i;
}


PEHeaderParser::~PEHeaderParser(void)
{
}
