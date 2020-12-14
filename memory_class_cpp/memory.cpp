#include "memory.h"

uint64_t Memory::get_proc_baseaddr()
{
	return proc.baseaddr;
}

bool Memory::ready()
{
	return found;
}

void Memory::check_proc()
{
	bool c;
	found = Read<bool>(proc.baseaddr, c);

	if (!found && proc.hProcess)
	{
		CloseHandle(proc.hProcess);
		proc.hProcess = NULL;
		proc.baseaddr = NULL;
	}
}

void Memory::open_proc(const wchar_t* name)
{
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (Process32First(snapshot, &entry) == TRUE)
	{
		while (Process32Next(snapshot, &entry) == TRUE)
		{
			if (wcscmp(entry.szExeFile, name) == 0)
			{
				proc.hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, entry.th32ProcessID);
				proc.baseaddr = GetModuleBaseAddress(entry.th32ProcessID, name);
				found = true;
			}
		}
	}

	CloseHandle(snapshot);
}

uintptr_t Memory::GetModuleBaseAddress(DWORD procId, const wchar_t* modName)
{
	uintptr_t modBaseAddr = 0;
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, procId);
	if (hSnap != INVALID_HANDLE_VALUE)
	{
		MODULEENTRY32 modEntry;
		modEntry.dwSize = sizeof(modEntry);
		if (Module32First(hSnap, &modEntry))
		{
			do
			{
				if (!_wcsicmp(modEntry.szModule, modName))
				{
					modBaseAddr = (uintptr_t)modEntry.modBaseAddr;
					break;
				}
			} while (Module32Next(hSnap, &modEntry));
		}
	}
	CloseHandle(hSnap);
	return modBaseAddr;
}

uint64_t Memory::ScanPointer(uint64_t ptr_address, uint32_t offsets[], int level)
{
	if (!ptr_address)
		return NULL;

	uint64_t lvl = ptr_address;

	for (int i = 0; i < level; i++)
	{
		if (!Read<uint64_t>(lvl, lvl))
			return NULL;
		lvl += offsets[i];
	}

	return lvl;
}

bool Memory::InjectDll(const char* DllAbsPath)
{
	LPVOID LoadLibAddr = NULL;
	HMODULE k32m = GetModuleHandleA("kernel32.dll");
	if (k32m)
		LoadLibAddr = (LPVOID)GetProcAddress(k32m, "LoadLibraryA");

	if (!LoadLibAddr)
	{
		printf("LoadLibraryA address not found\nError: 0x%x\n", GetLastError());
		return false;
	}

	LPVOID pDllPath = VirtualAllocEx(proc.hProcess, 0, strlen(DllAbsPath), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (!pDllPath)
	{
		printf("Failed to allocate memory\nError: 0x%x\n", GetLastError());
		return false;
	}

	if (!WriteArray<char>((uint64_t)pDllPath, DllAbsPath, strlen(DllAbsPath)))
	{
		printf("Failed to write memory\nError: 0x%x\n", GetLastError());
		return false;
	}

	HANDLE hThread = CreateRemoteThread(proc.hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLibAddr, pDllPath, 0, NULL);

	if (!hThread)
	{
		printf("CreateRemoteThread failed\nError: 0x%x\n", GetLastError());
		return false;
	}

	WaitForSingleObject(hThread, INFINITE);
	VirtualFreeEx(proc.hProcess, pDllPath, 0, MEM_RELEASE);
	CloseHandle(hThread);

	return true;
}

//Credits: learn_more, stevemk14ebr
DWORD Memory::findPattern(const PBYTE rangeStart, DWORD len, const char* pattern)
{
	size_t l = strlen(pattern);
	PBYTE patt_base = static_cast<PBYTE>(_malloca(l >> 1));
	PBYTE msk_base = static_cast<PBYTE>(_malloca(l >> 1));
	PBYTE pat = patt_base;
	PBYTE msk = msk_base;
	if (pat && msk)
	{
		l = 0;
		while (*pattern)
		{
			if (*pattern == ' ')
				pattern++;
			if (!*pattern)
				break;
			if (*(PBYTE)pattern == (BYTE)'\?')
			{
				*pat++ = 0;
				*msk++ = '?';
				pattern += ((*(PWORD)pattern == (WORD)'\?\?') ? 2 : 1);
			}
			else
			{
				*pat++ = getByte(pattern);
				*msk++ = 'x';
				pattern += 2;
			}
			l++;
		}
		*msk = 0;
		pat = patt_base;
		msk = msk_base;
		for (DWORD n = 0; n < (len - l); ++n)
		{
			if (isMatch(rangeStart + n, patt_base, msk_base))
			{
				_freea(patt_base);
				_freea(msk_base);
				return n;
			}
		}
		_freea(patt_base);
		_freea(msk_base);
	}
	return -1;
}