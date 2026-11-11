// Tests the Hooked_NtAllocateVirtualMemory and Hooked_NtAllocateVirtualMemoryEx post-call check:
// a successful allocation with an executable protection is reported with the API, the base and
// size the kernel returned, whether the target is the current process, and the protection.
// The Ex cases call ntdll directly, because which export the Win32 wrappers use varies between
// Windows versions.
#include "hook_test_harness.hpp"

typedef NTSTATUS(NTAPI* NtAllocateVirtualMemoryEx_t)(HANDLE ProcessHandle, PVOID* BaseAddress,
	PSIZE_T RegionSize, ULONG AllocationType, ULONG PageProtection,
	PMEM_EXTENDED_PARAMETER ExtendedParameters, ULONG ExtendedParameterCount);

/// @brief Allocates through NtAllocateVirtualMemoryEx.
static PVOID AllocEx(HANDLE process, SIZE_T size, ULONG allocationType, ULONG protection) {
	auto allocate = NtdllFunction<NtAllocateVirtualMemoryEx_t>("NtAllocateVirtualMemoryEx");
	PVOID base = NULL;
	if (allocate == NULL) {
		fprintf(stderr, "    NtAllocateVirtualMemoryEx is not exported by this ntdll\n");
		return NULL;
	}
	allocate(process, &base, &size, allocationType, protection, NULL, 0);
	return base;
}

/// @brief Copies the hook DLL this test loaded into a folder under %TEMP% and loads the copy, as
/// happens when the hook tests run on a machine where the driver already injected the installed
/// DLL. Returns NULL on failure.
static HMODULE LoadCopy(const char* folderName) {
	char source[MAX_PATH];
	char folder[MAX_PATH];
	char destination[MAX_PATH];
	HMODULE first = GetModuleHandleA(HOOK_DLL_NAME);
	if (first == NULL || GetModuleFileNameA(first, source, MAX_PATH) == 0 || GetTempPathA(MAX_PATH, folder) == 0) {
		fprintf(stderr, "    cannot locate %s\n", HOOK_DLL_NAME);
		return NULL;
	}
	strcat_s(folder, folderName);
	CreateDirectoryA(folder, NULL);
	sprintf_s(destination, "%s\\%s", folder, HOOK_DLL_NAME);
	HMODULE second = CopyFileA(source, destination, FALSE) ? LoadLibraryA(destination) : NULL;
	if (second == NULL || second == first) {
		fprintf(stderr, "    failed to load a second copy from %s (error %lu)\n", destination, GetLastError());
		return NULL;
	}
	return second;
}

static const std::vector<HookTestCase> g_Cases = {
	// A second copy of the DLL wraps the first copy's hooks; it silences the first copy so each
	// call is reported once, and the first copy reports again once the second unloads. Unloading
	// the copy unmaps an executable image, which the first copy reports.
	{
		"Second copy of the DLL reports each call once",
		[](HookTestContext&) {
			HMODULE second = LoadCopy("PanoptesSecondCopy");
			VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			if (second != NULL) {
				FreeLibrary(second);
			}
			VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		},
		{
			"NtAllocateVirtualMemory: 4096 executable bytes allocated at * in the current process (protection 0x40)",
			"NtUnmapViewOfSection: executable image at * unmapped from the current process",
			"NtAllocateVirtualMemory: 4096 executable bytes allocated at * in the current process (protection 0x40)",
		},
	},
	{
		// Three copies, as on a machine where the driver injected the installed DLL and this test
		// loaded its own build: only the newest reports, and each unload hands reporting to the
		// next newest. Copies are unloaded newest first, because Detours hooks have to be removed
		// in the reverse of the order they were placed
		"Three copies of the DLL report each call once",
		[](HookTestContext&) {
			HMODULE second = LoadCopy("PanoptesSecondCopy");
			HMODULE third = LoadCopy("PanoptesThirdCopy");
			VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			if (third != NULL) {
				FreeLibrary(third);
			}
			VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			if (second != NULL) {
				FreeLibrary(second);
			}
			VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		},
		{
			"NtAllocateVirtualMemory: 4096 executable bytes allocated at * in the current process (protection 0x40)",
			"NtUnmapViewOfSection: executable image at * unmapped from the current process",
			"NtAllocateVirtualMemory: 4096 executable bytes allocated at * in the current process (protection 0x40)",
			"NtUnmapViewOfSection: executable image at * unmapped from the current process",
			"NtAllocateVirtualMemory: 4096 executable bytes allocated at * in the current process (protection 0x40)",
		},
	},

	// NtAllocateVirtualMemory

	{
		"RWX in current process",
		[](HookTestContext&) {
			VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		},
		{ "NtAllocateVirtualMemory: 4096 executable bytes allocated at * in the current process (protection 0x40)" },
	},
	{
		"RX in current process",
		[](HookTestContext&) {
			VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ);
		},
		{ "NtAllocateVirtualMemory: 4096 executable bytes allocated at * in the current process (protection 0x20)" },
	},
	{
		"Execute-only in current process",
		[](HookTestContext&) {
			VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE);
		},
		{ "NtAllocateVirtualMemory: 4096 executable bytes allocated at * in the current process (protection 0x10)" },
	},
	{
		// The kernel rounds the size up to whole pages, and the event reports the rounded size
		"Size is reported rounded up to whole pages",
		[](HookTestContext&) {
			VirtualAlloc(NULL, 0x1001, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		},
		{ "NtAllocateVirtualMemory: 8192 executable bytes allocated at * in the current process (protection 0x40)" },
	},
	{
		// Reserving with an executable protection succeeds, so it is reported though nothing is
		// committed yet
		"Reserve-only RWX in current process",
		[](HookTestContext&) {
			VirtualAlloc(NULL, 0x1000, MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		},
		{ "NtAllocateVirtualMemory: 4096 executable bytes allocated at * in the current process (protection 0x40)" },
	},
	{
		"RWX in current process through a real handle to self",
		[](HookTestContext&) {
			HANDLE self = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
			VirtualAllocEx(self, NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			CloseHandle(self);
		},
		{ "NtAllocateVirtualMemory: 4096 executable bytes allocated at * in the current process (protection 0x40)" },
	},
	{
		"RWX in remote process",
		[](HookTestContext& context) {
			VirtualAllocEx(context.RemoteProcess(), NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		},
		{ "NtAllocateVirtualMemory: 4096 executable bytes allocated at * in the remote process (protection 0x40)" },
	},
	{
		"RX in remote process",
		[](HookTestContext& context) {
			VirtualAllocEx(context.RemoteProcess(), NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ);
		},
		{ "NtAllocateVirtualMemory: 4096 executable bytes allocated at * in the remote process (protection 0x20)" },
	},
	{
		"RW allocation is not reported",
		[](HookTestContext&) {
			VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		},
		{},
	},
	{
		"Remote RW allocation is not reported",
		[](HookTestContext& context) {
			VirtualAllocEx(context.RemoteProcess(), NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		},
		{},
	},
	{
		// This executable's image already occupies the requested address
		"Failed RWX allocation is not reported",
		[](HookTestContext&) {
			VirtualAlloc(GetModuleHandleA(NULL), 0x1000, MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		},
		{},
	},
	{
		"RWX allocation through a handle without PROCESS_VM_OPERATION is not reported",
		[](HookTestContext&) {
			HANDLE self = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, GetCurrentProcessId());
			VirtualAllocEx(self, NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			CloseHandle(self);
		},
		{},
	},

	// NtAllocateVirtualMemoryEx

	{
		"Ex: RWX in current process",
		[](HookTestContext&) {
			AllocEx(GetCurrentProcess(), 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		},
		{ "NtAllocateVirtualMemoryEx: 4096 executable bytes allocated at * in the current process (protection 0x40)" },
	},
	{
		"Ex: RX in remote process",
		[](HookTestContext& context) {
			AllocEx(context.RemoteProcess(), 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ);
		},
		{ "NtAllocateVirtualMemoryEx: 4096 executable bytes allocated at * in the remote process (protection 0x20)" },
	},
	{
		"Ex: RW allocation is not reported",
		[](HookTestContext&) {
			AllocEx(GetCurrentProcess(), 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		},
		{},
	},
	{
		// An allocation type of 0 is invalid
		"Ex: failed RWX allocation is not reported",
		[](HookTestContext&) {
			AllocEx(GetCurrentProcess(), 0x1000, 0, PAGE_EXECUTE_READWRITE);
		},
		{},
	},
};

int main(int argc, char** argv) {
	return RunHookTests(argc, argv, "NtAllocateVirtualMemory", g_Cases);
}
