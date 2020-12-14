#include "memory.h"
#include <thread>

Memory m;
const wchar_t proc_name[] = L"notepad.exe";

static void check_proc_t()
{
	while (true)
	{
		if (!m.ready())
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
	while (!m.ready())
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

	//Pattern scan
	BYTE arr[2048];
	if (m.ReadArray<BYTE>(m.get_proc_baseaddr() + 0x12345, arr, 2048))
	{
		DWORD index = m.findPattern(arr, 2048, "74 20 ?? 65 ?? 72");
		if (index != -1)
		{
			printf("Pattern found at: %p\n", (void*)(m.get_proc_baseaddr() + 0x12345 + index));
		}
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
