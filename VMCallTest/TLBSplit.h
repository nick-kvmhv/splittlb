namespace tlbsplit {
	bool hypervisorSupportPresent();
	bool setDataPage(void* pageAddr, void* data);
	bool activatePage(void* pageAddr);
	bool deactivatePage(void* pageAddr);
	bool deactivateAllPages();
}