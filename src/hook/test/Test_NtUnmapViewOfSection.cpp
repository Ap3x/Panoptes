// Tests the Hooked_NtUnmapViewOfSection and Hooked_NtUnmapViewOfSectionEx checks. The view is
// queried before the call (pre-check), because once it is unmapped its protection is gone, and
// reported only if the unmap then succeeds (post-check). A view with any executable page is
// reported with the API, whether the target is the current process, the address passed in, and
// whether it was an image. The whole view is walked, so an image unmapped by its base, whose
// first page is the read-only PE header, still counts as executable.
#include "hook_test_sections.hpp"
#include <winternl.h>

static const std::vector<HookTestCase> g_Cases = {
	// NtUnmapViewOfSection

	{
		"RWX view unmapped from current process",
		[](HookTestContext&) {
			UnmapView(GetCurrentProcess(), MapView(CreatePageSection(PAGE_EXECUTE_READWRITE), GetCurrentProcess(), PAGE_EXECUTE_READWRITE));
		},
		{ "NtUnmapViewOfSection: executable view at * unmapped from the current process" },
	},
	{
		"RX view unmapped from current process",
		[](HookTestContext&) {
			UnmapView(GetCurrentProcess(), MapView(CreatePageSection(PAGE_EXECUTE_READWRITE), GetCurrentProcess(), PAGE_EXECUTE_READ));
		},
		{ "NtUnmapViewOfSection: executable view at * unmapped from the current process" },
	},
	{
		"Image unmapped from current process by its base",
		[](HookTestContext&) {
			UnmapView(GetCurrentProcess(), MapView(CreateImageSection(), GetCurrentProcess(), PAGE_READONLY));
		},
		{ "NtUnmapViewOfSection: executable image at * unmapped from the current process" },
	},
	{
		// Any address inside a view unmaps the whole view
		"Image unmapped from current process by an address inside it",
		[](HookTestContext&) {
			BYTE* base = (BYTE*)MapView(CreateImageSection(), GetCurrentProcess(), PAGE_READONLY);
			UnmapView(GetCurrentProcess(), base + 0x1000);
		},
		{ "NtUnmapViewOfSection: executable image at * unmapped from the current process" },
	},
	{
		"RWX view unmapped through a real handle to self",
		[](HookTestContext&) {
			HANDLE self = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
			UnmapView(self, MapView(CreatePageSection(PAGE_EXECUTE_READWRITE), self, PAGE_EXECUTE_READWRITE));
			CloseHandle(self);
		},
		{ "NtUnmapViewOfSection: executable view at * unmapped from the current process" },
	},
	{
		// The pre-check queries the view with the caller's handle, so the handle needs query access
		"RWX view unmapped through a handle with only limited query access",
		[](HookTestContext&) {
			PVOID view = MapView(CreatePageSection(PAGE_EXECUTE_READWRITE), GetCurrentProcess(), PAGE_EXECUTE_READWRITE);
			HANDLE self = OpenProcess(PROCESS_VM_OPERATION | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, GetCurrentProcessId());
			UnmapView(self, view);
			CloseHandle(self);
		},
		{ "NtUnmapViewOfSection: executable view at * unmapped from the current process" },
	},
	{
		// Mapping into the target is reported by the map hook first
		"Image unmapped from remote process",
		[](HookTestContext& context) {
			HANDLE remote = context.RemoteProcess();
			UnmapView(remote, MapView(CreateImageSection(), remote, PAGE_READONLY));
		},
		{
			"NtMapViewOfSection: *-byte image mapped into a remote process at * (protection 0x2, executable)",
			"NtUnmapViewOfSection: executable image at * unmapped from the remote process",
		},
	},
	{
		"RW view unmapped from current process is not reported",
		[](HookTestContext&) {
			UnmapView(GetCurrentProcess(), MapView(CreatePageSection(PAGE_READWRITE), GetCurrentProcess(), PAGE_READWRITE));
		},
		{},
	},
	{
		"RW view of an RWX section unmapped from current process is not reported",
		[](HookTestContext&) {
			UnmapView(GetCurrentProcess(), MapView(CreatePageSection(PAGE_EXECUTE_READWRITE), GetCurrentProcess(), PAGE_READWRITE));
		},
		{},
	},
	{
		// The pre-check sees executable memory, but private memory is not a view, so the unmap
		// fails and nothing is reported. The allocation itself is reported by the allocate hook
		"Failed unmap of executable private memory is not reported",
		[](HookTestContext&) {
			UnmapView(GetCurrentProcess(), VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
		},
		{ "NtAllocateVirtualMemory: 4096 executable bytes allocated at * in the current process (protection 0x40)" },
	},
	{
		"Failed unmap through a handle without PROCESS_VM_OPERATION is not reported",
		[](HookTestContext&) {
			PVOID view = MapView(CreatePageSection(PAGE_EXECUTE_READWRITE), GetCurrentProcess(), PAGE_EXECUTE_READWRITE);
			HANDLE self = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, GetCurrentProcessId());
			UnmapView(self, view);
			CloseHandle(self);
		},
		{},
	},

	// NtUnmapViewOfSectionEx

	{
		"Ex: RWX view unmapped from current process",
		[](HookTestContext&) {
			UnmapViewEx(GetCurrentProcess(), MapView(CreatePageSection(PAGE_EXECUTE_READWRITE), GetCurrentProcess(), PAGE_EXECUTE_READWRITE));
		},
		{ "NtUnmapViewOfSectionEx: executable view at * unmapped from the current process" },
	},
	{
		"Ex: image unmapped from remote process",
		[](HookTestContext& context) {
			HANDLE remote = context.RemoteProcess();
			UnmapViewEx(remote, MapView(CreateImageSection(), remote, PAGE_READONLY));
		},
		{
			"NtMapViewOfSection: *-byte image mapped into a remote process at * (protection 0x2, executable)",
			"NtUnmapViewOfSectionEx: executable image at * unmapped from the remote process",
		},
	},
	{
		"Ex: RW view unmapped from current process is not reported",
		[](HookTestContext&) {
			UnmapViewEx(GetCurrentProcess(), MapView(CreatePageSection(PAGE_READWRITE), GetCurrentProcess(), PAGE_READWRITE));
		},
		{},
	},
	{
		"Ex: failed unmap of executable private memory is not reported",
		[](HookTestContext&) {
			UnmapViewEx(GetCurrentProcess(), VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
		},
		{ "NtAllocateVirtualMemory: 4096 executable bytes allocated at * in the current process (protection 0x40)" },
	},

	// Last, because it unmaps the remote target's own image

	{
		// The first step of process hollowing: find the target's image base in its PEB, then
		// unmap it. Reading the PEB is reported by the read hook
		"Remote process's main image unmapped (process hollowing)",
		[](HookTestContext& context) {
			HANDLE remote = context.RemoteProcess();
			PROCESS_BASIC_INFORMATION info{};
			NtdllFunction<decltype(&NtQueryInformationProcess)>("NtQueryInformationProcess")(
				remote, ProcessBasicInformation, &info, sizeof(info), NULL);
			PVOID imageBase = NULL;
			SIZE_T bytesRead;
			ReadProcessMemory(remote, (BYTE*)info.PebBaseAddress + 2 * sizeof(void*), &imageBase, sizeof(imageBase), &bytesRead);
			UnmapView(remote, imageBase);
		},
		{
			std::string("NtReadVirtualMemory: ") + (sizeof(void*) == 8 ? "8" : "4") +
				" bytes read from the PEB of the remote process at offset " + (sizeof(void*) == 8 ? "0x10" : "0x8"),
			"NtUnmapViewOfSection: executable image at * unmapped from the remote process",
		},
	},
};

int main(int argc, char** argv) {
	return RunHookTests(argc, argv, "NtUnmapViewOfSection", g_Cases);
}
