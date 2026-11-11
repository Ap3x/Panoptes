// Tests the Hooked_NtReadVirtualMemory post-call check: a successful read overlapping the
// target's PEB page is reported with the size, whether the target is the current process, and
// the offset into the PEB. From x64, a WOW64 target's 32-bit PEB counts too.
#include "hook_test_harness.hpp"
#include <winternl.h>

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

static void Read(HANDLE process, const BYTE* address, SIZE_T size) {
	BYTE buffer[0x1000];
	SIZE_T bytesRead;
	ReadProcessMemory(process, address, buffer, size, &bytesRead);
}

static BYTE* CurrentPeb() {
	return (BYTE*)NtCurrentTeb()->ProcessEnvironmentBlock;
}

// Offsets of PEB fields, which differ by architecture
#ifdef _WIN64
#define PEB_LDR_OFFSET 0x18
#define PEB_LDR_OFFSET_TEXT "0x18"
#define PEB_PARAMETERS_OFFSET 0x20
#define PEB_PARAMETERS_OFFSET_TEXT "0x20"
#else
#define PEB_LDR_OFFSET 0xC
#define PEB_LDR_OFFSET_TEXT "0xc"
#define PEB_PARAMETERS_OFFSET 0x10
#define PEB_PARAMETERS_OFFSET_TEXT "0x10"
#endif
#define POINTER_SIZE_TEXT (sizeof(void*) == 8 ? "8" : "4")

static const std::vector<HookTestCase> g_Cases = {
	{
		"Read of current process PEB (pseudo-handle)",
		[](HookTestContext&) {
			Read(GetCurrentProcess(), CurrentPeb(), 0x40);
		},
		{ "NtReadVirtualMemory: 64 bytes read from the PEB of the current process at offset 0x0" },
	},
	{
		"Read of current process PEB (real handle to self)",
		[](HookTestContext&) {
			HANDLE self = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, GetCurrentProcessId());
			Read(self, QueryPeb(self) + PEB_LDR_OFFSET, sizeof(void*));
			CloseHandle(self);
		},
		{ std::string("NtReadVirtualMemory: ") + POINTER_SIZE_TEXT +
			" bytes read from the PEB of the current process at offset " PEB_LDR_OFFSET_TEXT },
	},
	{
		// How tools find a process's command line: PEB->ProcessParameters
		"Read of remote process PEB ProcessParameters",
		[](HookTestContext& context) {
			HANDLE remote = context.RemoteProcess();
			Read(remote, QueryPeb(remote) + PEB_PARAMETERS_OFFSET, sizeof(void*));
		},
		{ std::string("NtReadVirtualMemory: ") + POINTER_SIZE_TEXT +
			" bytes read from the PEB of the remote process at offset " PEB_PARAMETERS_OFFSET_TEXT },
	},
	{
		"Read of the whole remote PEB page",
		[](HookTestContext& context) {
			HANDLE remote = context.RemoteProcess();
			Read(remote, QueryPeb(remote), 0x1000);
		},
		{ "NtReadVirtualMemory: 4096 bytes read from the PEB of the remote process at offset 0x0" },
	},
	{
		"Read of the last byte of the PEB page",
		[](HookTestContext&) {
			Read(GetCurrentProcess(), CurrentPeb() + 0xFFF, 1);
		},
		{ "NtReadVirtualMemory: 1 bytes read from the PEB of the current process at offset 0xfff" },
	},
#ifdef _WIN64
	{
		"Read of remote WOW64 process 32-bit PEB",
		[](HookTestContext& context) {
			HANDLE remote = context.Wow64RemoteProcess();
			Read(remote, QueryPeb(remote, true) + 0x10, 4);
		},
		{ "NtReadVirtualMemory: 4 bytes read from the PEB of the remote process at offset 0x10" },
	},
	{
		"Read of remote WOW64 process 64-bit PEB",
		[](HookTestContext& context) {
			HANDLE remote = context.Wow64RemoteProcess();
			Read(remote, QueryPeb(remote) + 0x10, 8);
		},
		{ "NtReadVirtualMemory: 8 bytes read from the PEB of the remote process at offset 0x10" },
	},
#endif
	{
		"Read of the TEB is not reported",
		[](HookTestContext&) {
			Read(GetCurrentProcess(), (const BYTE*)NtCurrentTeb(), 0x40);
		},
		{},
	},
	{
		"Read of ordinary memory is not reported",
		[](HookTestContext& context) {
			Read(GetCurrentProcess(), context.PEImage(), 0x40);
		},
		{},
	},
	{
		"Read of remote ordinary memory is not reported",
		[](HookTestContext& context) {
			HANDLE remote = context.RemoteProcess();
			BYTE* page = (BYTE*)VirtualAllocEx(remote, NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			Read(remote, page, 0x40);
		},
		{},
	},
	{
		"Failed read of the PEB is not reported",
		[](HookTestContext&) {
			// The handle can query the PEB's address but not read memory
			HANDLE self = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, GetCurrentProcessId());
			Read(self, QueryPeb(self), 0x40);
			CloseHandle(self);
		},
		{},
	},
};

int main(int argc, char** argv) {
	return RunHookTests(argc, argv, "NtReadVirtualMemory", g_Cases);
}
