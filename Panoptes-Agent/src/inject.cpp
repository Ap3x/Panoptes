#include "inject.hpp"

BOOL inject::InjectDLL(DWORD pid)
{
	LPWSTR dllPath = utils::GetCurrentDir();
	wcscat_s(dllPath,MAX_PATH, L"Panoptes.dll");
	wprintf(L"DLL Path: %s\n", dllPath);

	HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, pid);
	if (hProcess == NULL) {
		printf("Can't open handle, error: %lu\n", GetLastError());
		return FALSE;
	}

	FARPROC loadLibAddress = GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
	if (loadLibAddress == NULL) {
		printf("Could not find LoadLibraryW, error: %lu\n", GetLastError());
		return FALSE;
	}

	LPVOID vae_buffer = VirtualAllocEx(hProcess, NULL, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (vae_buffer == NULL) {
		printf("Can't allocate memory, error: %lu\n", GetLastError());
		CloseHandle(hProcess);
		return FALSE;
	}

	SIZE_T bytesWritten;
	if (!WriteProcessMemory(hProcess, vae_buffer, dllPath, MAX_PATH, &bytesWritten)) {
		printf("Can't write into memory, error: %lu\n", GetLastError());
		VirtualFreeEx(hProcess, vae_buffer, MAX_PATH, MEM_RELEASE);
		CloseHandle(hProcess);
		return FALSE;
	}

	// Creating a thread that will call LoadLibraryA and the path of the MyDUMBEDRDLL to load as argument
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibAddress, vae_buffer, 0, NULL);
	if (hThread == NULL) {
		printf("Can't launch remote thread, error: %lu\n", GetLastError());
		VirtualFreeEx(hProcess, vae_buffer, MAX_PATH, MEM_RELEASE);
		CloseHandle(hProcess);
		return FALSE;
	}

	return TRUE;
}