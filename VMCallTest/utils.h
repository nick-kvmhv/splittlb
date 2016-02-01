void patchCodeArr(size_t addr, const BYTE* value, DWORD len, PatchManager& pm);
int initUtils();
size_t adjustOffset(size_t offset);
extern size_t edModuleOffset; 

const size_t defaultbase = 0x0000000140000000i64;


template <typename T>
inline MH_STATUS MH_CreateHookApiEx(LPCWSTR pszModule, LPCSTR pszProcName, LPVOID pDetour, T** ppOriginal)
{
    return MH_CreateHookApi(pszModule, pszProcName, pDetour, reinterpret_cast<LPVOID*>(ppOriginal));
}

template <typename T>
inline MH_STATUS MH_CreateHookEx(LPVOID pTarget, LPVOID pDetour, T** ppOriginal)
{
    return MH_CreateHook(pTarget, pDetour, reinterpret_cast<LPVOID*>(ppOriginal));
}

#define CAPTURE_CALLER_IP 	void  * __callers_stack[ 2 ];\
	CaptureStackBackTrace(0,2,__callers_stack,NULL);\
	size_t calleraddress = (size_t)__callers_stack[1]-edModuleOffset+defaultbase; //Normalized

inline float decryptFloat(__int64 encrypted) {
	float f;
	DWORD *ff = (DWORD *)&f;
	*ff = DWORD(encrypted) ^ DWORD(encrypted >> 32);
	return f;
}

inline bool ends_with(std::string const & value, std::string const & ending)
{
    if (ending.size() > value.size()) return false;
    return std::equal(ending.rbegin(), ending.rend(), value.rbegin());
}


