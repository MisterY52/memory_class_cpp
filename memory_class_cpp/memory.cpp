#include "memory.h"

//Credits: learn_more, stevemk14ebr
size_t findPattern(const PBYTE rangeStart, size_t len, const char* pattern)
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
		for (size_t n = 0; n < (len - l); ++n)
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

uint64_t Memory::get_proc_baseaddr()
{
	return proc.baseaddr;
}

process_status Memory::get_proc_status()
{
	return status;
}

void Memory::check_proc()
{
	if (status == process_status::FOUND_READY)
	{
		bool c;

		if (!Read<bool>(proc.baseaddr, c))
		{
			status = process_status::FOUND_NO_ACCESS;
			close_proc();
		}
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
				if (proc.hProcess <= 0)
				{
					proc.hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, entry.th32ProcessID);

					if (proc.hProcess > 0)
					{
						proc.baseaddr = GetModuleBaseAddress(entry.th32ProcessID, name);

						if (proc.baseaddr)
						{
							status = process_status::FOUND_READY;
							proc.pid = entry.th32ProcessID;
						}
						else
						{
							status = process_status::FOUND_NO_ACCESS;
							close_proc();
						}
					}
					else
					{
						status = process_status::FOUND_NO_ACCESS;
						close_proc();
					}
				}

				CloseHandle(snapshot);
				return;
			}
		}
	}

	status = process_status::NOT_FOUND;
	close_proc();

	CloseHandle(snapshot);
}

HANDLE Memory::open_thread(DWORD pid)
{
	THREADENTRY32 threadEntry = { sizeof(THREADENTRY32) };
	HANDLE threadHandle = NULL;
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, 0);

	if (Thread32First(snapshot, &threadEntry))
	{
		do
		{
			if (threadEntry.th32OwnerProcessID == pid)
			{
				CloseHandle(snapshot);
				return OpenThread(THREAD_ALL_ACCESS, TRUE, threadEntry.th32ThreadID);
			}
		} while (Thread32Next(snapshot, &threadEntry));
	}
	CloseHandle(snapshot);
	return 0;
}

void* Memory::allocate_mem(size_t size, DWORD prot)
{
	void* alloc_addr = VirtualAllocEx(proc.hProcess, 0, size, MEM_COMMIT | MEM_RESERVE, prot);
	if (!alloc_addr)
	{
		printf("Can't allocate memory\n");
		return 0;
	}
	return alloc_addr;
}

bool Memory::free_mem(void* alloc_addr)
{
	return VirtualFreeEx(proc.hProcess, alloc_addr, 0, MEM_RELEASE);
}

bool Memory::execute_payload(byte* payload, size_t p_size, void* payload_addr)
{
	WriteArray<byte>((uint64_t)payload_addr, payload, p_size);
	HANDLE thr = open_thread(proc.pid);

	if (!thr)
	{
		printf("Can't open the thread\n");
		return false;
	}
	else
	{
		LPVOID NtQueueApcThread = NULL;
		HMODULE ntdll = GetModuleHandleA("ntdll.dll");
		if (ntdll)
			NtQueueApcThread = (LPVOID)GetProcAddress(ntdll, "NtQueueApcThread");
		if (NtQueueApcThread)
		{
			fnNtQueueApcThread ntq = (fnNtQueueApcThread)NtQueueApcThread;
			PTHREAD_START_ROUTINE apcRoutine = (PTHREAD_START_ROUTINE)payload_addr;
			ntq(thr, (PAPCFUNC)apcRoutine, nullptr, nullptr, nullptr);
		}
		else
		{
			printf("Can't execute payload\n");
		}

		CloseHandle(thr);
	}
	return true;
}

void Memory::close_proc()
{
	if (proc.hProcess > 0)
		CloseHandle(proc.hProcess);
	proc.hProcess = NULL;
	proc.baseaddr = NULL;
}

uint64_t Memory::GetModuleBaseAddress(DWORD procId, const wchar_t* modName)
{
	uint64_t modBaseAddr = 0;
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
					modBaseAddr = (uint64_t)modEntry.modBaseAddr;
					break;
				}
			} while (Module32Next(hSnap, &modEntry));
		}
	}
	CloseHandle(hSnap);
	return modBaseAddr;
}

uint64_t Memory::ScanPointer(uint64_t ptr_address, const uint32_t offsets[], int level)
{
	if (!ptr_address)
		return NULL;

	uint64_t lvl = ptr_address;

	for (int i = 0; i < level; i++)
	{
		if (!Read<uint64_t>(lvl, lvl) || !lvl)
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

uint64_t* Memory::RegionPatternScan(uint64_t start_addr, size_t size, const char* pattern, size_t max_results, DWORD page_prot)
{
	uint64_t match_addr = 0;
	BYTE* buffer = NULL;
	MEMORY_BASIC_INFORMATION mbi = { 0 };
	uint64_t* result_addr = new uint64_t[max_results]{ 0 };
	size_t r = 0, index = 0, index_sum = 0;

	for (uint64_t addr = start_addr; addr < start_addr + size; addr += mbi.RegionSize)
	{
		if (!VirtualQueryEx(proc.hProcess, (LPCVOID)addr, &mbi, sizeof(mbi)))
		{
			break;
		}

		if (mbi.State != MEM_COMMIT || mbi.Protect == PAGE_NOACCESS || mbi.Protect == PAGE_GUARD)
			continue;

		if (page_prot && mbi.Protect != page_prot)
			continue;

		delete[] buffer;
		buffer = new BYTE[mbi.RegionSize];

		if (!ReadArray<BYTE>((uint64_t)mbi.BaseAddress, buffer, mbi.RegionSize))
			continue;

		index = 0;
		index_sum = 0;

		while (index != -1)
		{
			index = findPattern(buffer + index_sum, mbi.RegionSize - index_sum, pattern);

			if (index != -1)
			{
				index_sum += index;
				match_addr = addr + index_sum;
				result_addr[r] = match_addr;
				r++;

				if (r == max_results)
				{
					delete[] buffer;
					return result_addr;
				}

				index_sum += 1;
			}
		}
	}

	delete[] buffer;

	if (r > 0)
		return result_addr;

	delete[] result_addr;
	return NULL;
}