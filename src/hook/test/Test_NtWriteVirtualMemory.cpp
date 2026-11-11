// Tests the Hooked_NtWriteVirtualMemory post-call checks, which only run when the write succeeds:
//  - A buffer starting with the "MZ" magic bytes is reported, with whether the target is the
//    current process and whether the destination is executable.
//  - A write overlapping the target's PEB page is reported, with the offset into the PEB. From
//    x64, a WOW64 target's 32-bit PEB counts too.
#include "hook_test_harness.hpp"
#include <winternl.h>

static BYTE* Alloc(DWORD protection) {
	return (BYTE*)VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, protection);
}

/// @brief Gets a process's PEB address, or its 32-bit PEB address when Wow64 is set.
static BYTE* QueryPeb(HANDLE process, bool wow64 = false) {
	auto query = NtdllFunction<decltype(&NtQueryInformationProcess)>("NtQueryInformationProcess");
	if (wow64) {
		ULONG_PTR peb32 = 0;
		query(process, ProcessWow64Information, &peb32, sizeof(peb32), NULL);
		return (BYTE*)peb32;
	}
	PROCESS_BASIC_INFORMATION info{};
	query(process, ProcessBasicInformation, &info, sizeof(info), NULL);
	return (BYTE*)info.PebBaseAddress;
}

typedef NTSTATUS(NTAPI* NtReadWriteVirtualMemory_t)(HANDLE ProcessHandle, PVOID BaseAddress,
	PVOID Buffer, SIZE_T NumberOfBytes, PSIZE_T NumberOfBytesTransferred);

/// @brief Rewrites Size bytes at Address in a process with their current value, so the write is
/// real but changes nothing. The read goes through NtReadVirtualMemory, so a PEB rewrite is
/// reported by the read hook first. Both calls go to ntdll directly: ReadProcessMemory and
/// WriteProcessMemory add their own reads for some targets (e.g. of a WOW64 target's PEB).
static void RewriteInPlace(HANDLE process, BYTE* address, SIZE_T size) {
	BYTE value[16];
	SIZE_T transferred;
	NtdllFunction<NtReadWriteVirtualMemory_t>("NtReadVirtualMemory")(process, address, value, size, &transferred);
	NtdllFunction<NtReadWriteVirtualMemory_t>("NtWriteVirtualMemory")(process, address, value, size, &transferred);
}

// Offsets of PEB fields, which differ by architecture
#define PEB_BEING_DEBUGGED_OFFSET 0x2
#ifdef _WIN64
#define PEB_IMAGE_BASE_OFFSET 0x10
#define PEB_IMAGE_BASE_OFFSET_TEXT "0x10"
#else
#define PEB_IMAGE_BASE_OFFSET 0x8
#define PEB_IMAGE_BASE_OFFSET_TEXT "0x8"
#endif
#define POINTER_SIZE_TEXT (sizeof(void*) == 8 ? "8" : "4")

static const std::vector<HookTestCase> g_Cases = {
	// PE image writes

	{
		"PE into current process RW memory (pseudo-handle)",
		[](HookTestContext& context) {
			SIZE_T written;
			WriteProcessMemory(GetCurrentProcess(), Alloc(PAGE_READWRITE), context.PEImage(), context.PESize, &written);
		},
		{ "NtWriteVirtualMemory: PE image written to * in the current process, destination not executable" },
	},
	{
		"PE into current process RW memory (real handle to self)",
		[](HookTestContext& context) {
			HANDLE self = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
			SIZE_T written;
			WriteProcessMemory(self, Alloc(PAGE_READWRITE), context.PEImage(), context.PESize, &written);
			CloseHandle(self);
		},
		{ "NtWriteVirtualMemory: PE image written to * in the current process, destination not executable" },
	},
	{
		"PE into current process RWX memory",
		[](HookTestContext& context) {
			SIZE_T written;
			WriteProcessMemory(GetCurrentProcess(), Alloc(PAGE_EXECUTE_READWRITE), context.PEImage(), context.PESize, &written);
		},
		{
			"NtAllocateVirtualMemory: 4096 executable bytes allocated at * in the current process (protection 0x40)",
			"NtWriteVirtualMemory: PE image written to * in the current process, destination executable",
		},
	},
	{
		// WriteProcessMemory makes the RX page writable for the write and restores it afterwards;
		// both protection changes go through NtProtectVirtualMemory and are reported by that hook
		"PE into current process RX memory",
		[](HookTestContext& context) {
			SIZE_T written;
			WriteProcessMemory(GetCurrentProcess(), Alloc(PAGE_EXECUTE_READ), context.PEImage(), context.PESize, &written);
		},
		{
			"NtAllocateVirtualMemory: 4096 executable bytes allocated at * in the current process (protection 0x20)",
			"NtProtectVirtualMemory: PE image at * in the current process made executable (0x20 -> *)",
			"NtWriteVirtualMemory: PE image written to * in the current process, destination executable",
			"NtProtectVirtualMemory: PE image at * in the current process made executable (0x40 -> *)",
		},
	},
	{
		"PE into remote process RW memory",
		[](HookTestContext& context) {
			HANDLE remote = context.RemoteProcess();
			BYTE* destination = (BYTE*)VirtualAllocEx(remote, NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			SIZE_T written;
			WriteProcessMemory(remote, destination, context.PEImage(), context.PESize, &written);
		},
		{ "NtWriteVirtualMemory: PE image written to * in the remote process, destination not executable" },
	},
	{
		"PE into remote process RWX memory",
		[](HookTestContext& context) {
			HANDLE remote = context.RemoteProcess();
			BYTE* destination = (BYTE*)VirtualAllocEx(remote, NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			SIZE_T written;
			WriteProcessMemory(remote, destination, context.PEImage(), context.PESize, &written);
		},
		{
			"NtAllocateVirtualMemory: 4096 executable bytes allocated at * in the remote process (protection 0x40)",
			"NtWriteVirtualMemory: PE image written to * in the remote process, destination executable",
		},
	},
	{
		// Only the magic bytes are checked, so a DOS header with no PE signature still counts
		"MZ without a PE signature is reported",
		[](HookTestContext&) {
			BYTE buffer[0x1000] = { 'M', 'Z' };
			SIZE_T written;
			WriteProcessMemory(GetCurrentProcess(), Alloc(PAGE_READWRITE), buffer, sizeof(buffer), &written);
		},
		{ "NtWriteVirtualMemory: PE image written to * in the current process, destination not executable" },
	},
	{
		"Just the two MZ bytes are reported",
		[](HookTestContext& context) {
			SIZE_T written;
			WriteProcessMemory(GetCurrentProcess(), Alloc(PAGE_READWRITE), context.PEImage(), 2, &written);
		},
		{ "NtWriteVirtualMemory: PE image written to * in the current process, destination not executable" },
	},
	{
		"A single M byte is not reported",
		[](HookTestContext& context) {
			SIZE_T written;
			WriteProcessMemory(GetCurrentProcess(), Alloc(PAGE_READWRITE), context.PEImage(), 1, &written);
		},
		{},
	},
	{
		"ZM (byte-swapped magic) is not reported",
		[](HookTestContext&) {
			BYTE buffer[0x1000] = { 'Z', 'M' };
			SIZE_T written;
			WriteProcessMemory(GetCurrentProcess(), Alloc(PAGE_READWRITE), buffer, sizeof(buffer), &written);
		},
		{},
	},
	{
		"Non-PE data is not reported",
		[](HookTestContext&) {
			BYTE buffer[0x1000];
			memset(buffer, 0x90, sizeof(buffer));
			SIZE_T written;
			WriteProcessMemory(GetCurrentProcess(), Alloc(PAGE_READWRITE), buffer, sizeof(buffer), &written);
		},
		{},
	},
	{
		"Failed write of a PE is not reported",
		[](HookTestContext& context) {
			// Reserved but not committed, so the write fails
			BYTE* reserved = (BYTE*)VirtualAlloc(NULL, 0x1000, MEM_RESERVE, PAGE_READWRITE);
			SIZE_T written;
			WriteProcessMemory(GetCurrentProcess(), reserved, context.PEImage(), context.PESize, &written);
		},
		{},
	},

	// PEB writes

	{
		"Write to current process PEB (pseudo-handle)",
		[](HookTestContext&) {
			BYTE* peb = (BYTE*)NtCurrentTeb()->ProcessEnvironmentBlock;
			RewriteInPlace(GetCurrentProcess(), peb + PEB_BEING_DEBUGGED_OFFSET, 1);
		},
		{
			"NtReadVirtualMemory: 1 bytes read from the PEB of the current process at offset 0x2",
			"NtWriteVirtualMemory: 1 bytes written to the PEB of the current process at offset 0x2",
		},
	},
	{
		"Write to current process PEB (real handle to self)",
		[](HookTestContext&) {
			HANDLE self = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
			RewriteInPlace(self, QueryPeb(self) + PEB_BEING_DEBUGGED_OFFSET, 1);
			CloseHandle(self);
		},
		{
			"NtReadVirtualMemory: 1 bytes read from the PEB of the current process at offset 0x2",
			"NtWriteVirtualMemory: 1 bytes written to the PEB of the current process at offset 0x2",
		},
	},
	{
		// The PEB is checked as a whole page, so the last byte of the page still counts
		"Write to the last byte of the PEB page",
		[](HookTestContext&) {
			BYTE* peb = (BYTE*)NtCurrentTeb()->ProcessEnvironmentBlock;
			RewriteInPlace(GetCurrentProcess(), peb + 0xFFF, 1);
		},
		{
			"NtReadVirtualMemory: 1 bytes read from the PEB of the current process at offset 0xfff",
			"NtWriteVirtualMemory: 1 bytes written to the PEB of the current process at offset 0xfff",
		},
	},
	{
		// What process hollowing does after mapping its own image into the target
		"Write to remote process PEB ImageBaseAddress",
		[](HookTestContext& context) {
			HANDLE remote = context.RemoteProcess();
			RewriteInPlace(remote, QueryPeb(remote) + PEB_IMAGE_BASE_OFFSET, sizeof(void*));
		},
		{
			std::string("NtReadVirtualMemory: ") + POINTER_SIZE_TEXT +
				" bytes read from the PEB of the remote process at offset " PEB_IMAGE_BASE_OFFSET_TEXT,
			std::string("NtWriteVirtualMemory: ") + POINTER_SIZE_TEXT +
				" bytes written to the PEB of the remote process at offset " PEB_IMAGE_BASE_OFFSET_TEXT,
		},
	},
#ifdef _WIN64
	{
		"Write to remote WOW64 process 32-bit PEB",
		[](HookTestContext& context) {
			HANDLE remote = context.Wow64RemoteProcess();
			RewriteInPlace(remote, QueryPeb(remote, true) + PEB_BEING_DEBUGGED_OFFSET, 1);
		},
		{
			"NtReadVirtualMemory: 1 bytes read from the PEB of the remote process at offset 0x2",
			"NtWriteVirtualMemory: 1 bytes written to the PEB of the remote process at offset 0x2",
		},
	},
#endif
	{
		"Write next to the PEB is not reported",
		[](HookTestContext&) {
			// The TEB is a separate allocation, so a write to it is outside the PEB's page
			BYTE* teb = (BYTE*)NtCurrentTeb();
			RewriteInPlace(GetCurrentProcess(), teb + 0x100, 1);
		},
		{},
	},
	{
		// The handle can read but not write, so only the read hook reports
		"Failed write to the PEB is not reported",
		[](HookTestContext&) {
			HANDLE self = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, GetCurrentProcessId());
			RewriteInPlace(self, QueryPeb(self) + PEB_BEING_DEBUGGED_OFFSET, 1);
			CloseHandle(self);
		},
		{ "NtReadVirtualMemory: 1 bytes read from the PEB of the current process at offset 0x2" },
	},
};

int main(int argc, char** argv) {
	return RunHookTests(argc, argv, "NtWriteVirtualMemory", g_Cases);
}
