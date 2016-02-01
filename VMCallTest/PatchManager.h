
class PatchManager {
private:
		std::set<size_t> patches;
		bool hypervisor_support;
		void ensureCopyOnWrite(PVOID addr);
public:
	PatchManager();
	bool addPatch(void* patchAddr, int patchSize);
	int protectAll();
};