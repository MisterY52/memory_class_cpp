#include <Windows.h>
#include <tlhelp32.h>
#include <iostream>

#define INRANGE(x,a,b)		(x >= a && x <= b) 
#define getBits( x )		(INRANGE(x,'0','9') ? (x - '0') : ((x&(~0x20)) - 'A' + 0xa))
#define getByte( x )		(getBits(x[0]) << 4 | getBits(x[1]))

inline bool isMatch(const PBYTE addr, const PBYTE pat, const PBYTE msk)
{
	size_t n = 0;
	while (addr[n] == pat[n] || msk[n] == (BYTE)'?')
	{
		if (!msk[++n])
		{
			return true;
		}
	}
	return false;
}

size_t findPattern(const PBYTE rangeStart, size_t len, const char* pattern);

typedef struct Process
{
	HANDLE hProcess = NULL;
	uint64_t baseaddr = NULL;
}Process;

enum class process_status : BYTE
{
	NOT_FOUND,
	FOUND_NO_ACCESS,
	FOUND_READY
};

class Memory
{
private:
	Process proc;
	process_status status = process_status::NOT_FOUND;
public:
	~Memory() { if (proc.hProcess) CloseHandle(proc.hProcess); }

	uint64_t get_proc_baseaddr();

	process_status get_proc_status();

	void check_proc();

	void open_proc(const wchar_t* name);

	void close_proc();

	uint64_t GetModuleBaseAddress(DWORD procId, const wchar_t* modName);

	template<typename T>
	bool Read(uint64_t address, T& out);

	template<typename T>
	bool ReadArray(uint64_t address, T out[], size_t len);

	template<typename T>
	bool Write(uint64_t address, const T& value);

	template<typename T>
	bool WriteArray(uint64_t address, const T value[], size_t len);

	uint64_t ScanPointer(uint64_t ptr_address, const uint32_t offsets[], int level);

	bool InjectDll(const char* DllAbsPath);

	uint64_t* RegionPatternScan(uint64_t start_addr, size_t size, const char* pattern, size_t max_results = 1, DWORD page_prot = 0);
};

template<typename T>
inline bool Memory::Read(uint64_t address, T& out)
{
	size_t bytesread = 0;

	return ReadProcessMemory(proc.hProcess, (LPCVOID)address, &out, sizeof(T), &bytesread) != 0 && bytesread == sizeof(T);
}

template<typename T>
inline bool Memory::ReadArray(uint64_t address, T out[], size_t len)
{
	size_t bytesread = 0;

	return ReadProcessMemory(proc.hProcess, (LPCVOID)address, out, sizeof(T) * len, &bytesread) != 0 && bytesread == (sizeof(T) * len);
}

template<typename T>
inline bool Memory::Write(uint64_t address, const T& value)
{
	size_t byteswritten = 0;

	return WriteProcessMemory(proc.hProcess, (LPVOID)address, &value, sizeof(T), &byteswritten) != 0 && byteswritten == sizeof(T);
}

template<typename T>
inline bool Memory::WriteArray(uint64_t address, const T value[], size_t len)
{
	size_t byteswritten = 0;

	return WriteProcessMemory(proc.hProcess, (LPVOID)address, value, sizeof(T) * len, &byteswritten) != 0 && byteswritten == (sizeof(T) * len);
}