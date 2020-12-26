#include "memory.h"
#include <thread>

Memory m;

static void check_proc_t()
{
	const wchar_t proc_name[] = L"notepad.exe";

	while (true)
	{
		if (m.get_proc_status() != process_status::FOUND_READY)
		{
			m.open_proc(proc_name);
		}
		else
		{
			m.check_proc();
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
	}
}

int main()
{
	std::thread check_proc(check_proc_t);
	check_proc.detach();

	printf("Waiting for process...\n");

	while (m.get_proc_status() != process_status::FOUND_READY)
	{
		std::this_thread::sleep_for(std::chrono::milliseconds(1));
	}

	printf("Process found\n");

	//Reading
	int out;
	if (m.Read<int>(m.get_proc_baseaddr() + 0x12345, out))
		printf("Value read: %d\n", out);
	
	//Writing
	int k = 123;
	if (m.Write<int>(m.get_proc_baseaddr() + 0x12345, k))
		printf("Value written\n");

	//Simple pattern scan
	BYTE arr[2048];
	if (m.ReadArray<BYTE>(m.get_proc_baseaddr() + 0x12345, arr, 2048))
	{
		size_t index = findPattern(arr, 2048, "74 20 ?? 65 ?? 72");
		if (index != -1)
		{
			printf("Pattern found at: %p\n", (void*)(m.get_proc_baseaddr() + 0x12345 + index));
		}
	}

	//Pattern scan through memory regions with a specific protection
	uint64_t* results = m.RegionPatternScan(0x20000000000, 0x50000000000, "74 20 ?? 65 ?? 72", 10, PAGE_EXECUTE_READWRITE);

	if (results)
	{
		int c = 0;
		for (int i = 0; i < 10; i++)
		{
			if (results[i])
			{
				printf("%p\n", (void*)results[i]);
				c++;
			}
		}
		printf("Found %d results\n", c);
		delete[] results;
	}
	

	//Get the final address from a multi-level pointer
	uint64_t add = m.ScanPointer(m.get_proc_baseaddr() + 0x12345, new uint32_t[2]{ 0x1d2, 0x345 }, 2);
	if (add)
		printf("Address: %p\n", (void*)add);

	//DLL inject (LoadLibrary)
	char path[260] = { 0 };
	GetFullPathNameA("test.dll", 260, path, NULL);
	if (strlen(path) > 0)
	{
		if (m.InjectDll(path))
			printf("DLL injected\n");
	}
	else
	{
		printf("DLL not found\n");
	}

    std::getchar();
}
