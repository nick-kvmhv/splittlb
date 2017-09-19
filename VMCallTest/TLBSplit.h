namespace tlbsplit {
	bool hypervisorSupportPresent();
	bool setDataPage(void* pageAddr, void* data);
	bool activatePage(void* pageAddr);
	bool writeCodePage(void* _from, void* _to, size_t bytes);
	bool deactivatePage(void* pageAddr);
	bool deactivateAllPages();
	bool isPageSplit(void* pageAddr);
	void setAdjuster();
}