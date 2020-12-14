#include <Windows.h>
#include <tlhelp32.h>
#include <iostream>

#define INRANGE(x,a,b)		(x >= a && x <= b) 
#define getBits( x )		(INRANGE(x,'0','9') ? (x - '0') : ((x&(~0x20)) - 'A' + 0xa))
#define getByte( x )		(getBits(x[0]) << 4 | getBits(x[1]))

typedef struct Process
{
	HANDLE hProcess = NULL;
	uint64_t baseaddr = NULL;
}Process;

class Memory
{
private:
	Process proc;
	bool found = false;
public:
	~Memory() { if (proc.hProcess) CloseHandle(proc.hProcess); }

	uint64_t get_proc_baseaddr();

	bool ready();

	void check_proc();

	void open_proc(const wchar_t* name);

	uintptr_t GetModuleBaseAddress(DWORD procId, const wchar_t* modName);

	template<typename T>
	bool Read(uint64_t address, T& out);

	template<typename T>
	bool ReadArray(uint64_t address, T out[], size_t len);

	template<typename T>
	bool Write(uint64_t address, const T& value);

	template<typename T>
	bool WriteArray(uint64_t address, const T value[], size_t len);

	bool isMatch(const PBYTE addr, const PBYTE pat, const PBYTE msk);

	uint64_t ScanPointer(uint64_t ptr_address, uint32_t offsets[], int level);

	bool InjectDll(const char* DllAbsPath);

	DWORD findPattern(const PBYTE rangeStart, DWORD len, const char* pattern);
};

template<typename T>
inline bool Memory::Read(uint64_t address, T& out)
{
	if (!address)
		return false;
	return ReadProcessMemory(proc.hProcess, (LPCVOID)address, &out, sizeof(T), NULL) != 0;
}

template<typename T>
inline bool Memory::ReadArray(uint64_t address, T out[], size_t len)
{
	if (!address)
		return false;
	return ReadProcessMemory(proc.hProcess, (LPCVOID)address, out, sizeof(T) * len, NULL) != 0;
}

template<typename T>
inline bool Memory::Write(uint64_t address, const T& value)
{
	if (!address)
		return false;
	return WriteProcessMemory(proc.hProcess, (LPVOID)address, &value, sizeof(T), NULL) != 0;
}

template<typename T>
inline bool Memory::WriteArray(uint64_t address, const T value[], size_t len)
{
	if (!address)
		return false;
	return WriteProcessMemory(proc.hProcess, (LPVOID)address, value, sizeof(T) * len, NULL) != 0;
}

inline bool Memory::isMatch(const PBYTE addr, const PBYTE pat, const PBYTE msk)
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