// Tests the Hooked_NtProtectVirtualMemory post-call check: a successful change to any executable
// protection (PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE or PAGE_EXECUTE_WRITECOPY,
// with or without modifiers) is reported with whether the target is the current process and the
// old and new protection. The region's contents are not checked, so a region without a PE image
// is reported too, under the event's "PE image" wording.
#include "hook_test_harness.hpp"

/// @brief Allocates a RW page in this process and copies a PE image into it. memcpy rather than
/// WriteProcessMemory, so only the protect hook is exercised.
static BYTE* AllocWithPE(const HookTestContext& context) {
	BYTE* page = (BYTE*)VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	memcpy(page, context.PEImage(), context.PESize);
	return page;
}

static const std::vector<HookTestCase> g_Cases = {
	{
		"PE in current process made RX",
		[](HookTestContext& context) {
			DWORD old;
			VirtualProtect(AllocWithPE(context), 0x1000, PAGE_EXECUTE_READ, &old);
		},
		{ "NtProtectVirtualMemory: PE image at * in the current process made executable (0x4 -> 0x20)" },
	},
	{
		"PE in current process made RWX",
		[](HookTestContext& context) {
			DWORD old;
			VirtualProtect(AllocWithPE(context), 0x1000, PAGE_EXECUTE_READWRITE, &old);
		},
		{ "NtProtectVirtualMemory: PE image at * in the current process made executable (0x4 -> 0x40)" },
	},
	{
		"PE in current process made execute-only",
		[](HookTestContext& context) {
			DWORD old;
			VirtualProtect(AllocWithPE(context), 0x1000, PAGE_EXECUTE, &old);
		},
		{ "NtProtectVirtualMemory: PE image at * in the current process made executable (0x4 -> 0x10)" },
	},
	{
		// PAGE_GUARD is a modifier on top of the base protection, which is still executable
		"PE in current process made RX with PAGE_GUARD",
		[](HookTestContext& context) {
			DWORD old;
			VirtualProtect(AllocWithPE(context), 0x1000, PAGE_EXECUTE_READ | PAGE_GUARD, &old);
		},
		{ "NtProtectVirtualMemory: PE image at * in the current process made executable (0x4 -> 0x120)" },
	},
	{
		"PE in current process made RX through a real handle to self",
		[](HookTestContext& context) {
			HANDLE self = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
			DWORD old;
			VirtualProtectEx(self, AllocWithPE(context), 0x1000, PAGE_EXECUTE_READ, &old);
			CloseHandle(self);
		},
		{ "NtProtectVirtualMemory: PE image at * in the current process made executable (0x4 -> 0x20)" },
	},
	{
		// Writing the PE goes through WriteProcessMemory, so the write hook reports it first
		"PE in remote process made RX",
		[](HookTestContext& context) {
			HANDLE remote = context.RemoteProcess();
			BYTE* page = (BYTE*)VirtualAllocEx(remote, NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			SIZE_T written;
			WriteProcessMemory(remote, page, context.PEImage(), context.PESize, &written);
			DWORD old;
			VirtualProtectEx(remote, page, 0x1000, PAGE_EXECUTE_READ, &old);
		},
		{
			"NtWriteVirtualMemory: PE image written to * in the remote process, destination not executable",
			"NtProtectVirtualMemory: PE image at * in the remote process made executable (0x4 -> 0x20)",
		},
	},
	{
		"Region without a PE made RX is reported",
		[](HookTestContext&) {
			BYTE* page = (BYTE*)VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			memset(page, 0x90, 0x1000);
			DWORD old;
			VirtualProtect(page, 0x1000, PAGE_EXECUTE_READ, &old);
		},
		{ "NtProtectVirtualMemory: PE image at * in the current process made executable (0x4 -> 0x20)" },
	},
	{
		"Remote region without a PE made RX is reported",
		[](HookTestContext& context) {
			HANDLE remote = context.RemoteProcess();
			BYTE* page = (BYTE*)VirtualAllocEx(remote, NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			DWORD old;
			VirtualProtectEx(remote, page, 0x1000, PAGE_EXECUTE_READ, &old);
		},
		{ "NtProtectVirtualMemory: PE image at * in the remote process made executable (0x4 -> 0x20)" },
	},
	{
		"PE made non-executable is not reported",
		[](HookTestContext& context) {
			DWORD old;
			VirtualProtect(AllocWithPE(context), 0x1000, PAGE_READONLY, &old);
		},
		{},
	},
	{
		"Executable region made non-executable is not reported",
		[](HookTestContext& context) {
			BYTE* page = AllocWithPE(context);
			DWORD old;
			VirtualProtect(page, 0x1000, PAGE_EXECUTE_READ, &old);
			VirtualProtect(page, 0x1000, PAGE_READWRITE, &old);
		},
		{ "NtProtectVirtualMemory: PE image at * in the current process made executable (0x4 -> 0x20)" },
	},
	{
		"Failed protection change is not reported",
		[](HookTestContext&) {
			// Reserved but not committed, so the protection change fails
			BYTE* reserved = (BYTE*)VirtualAlloc(NULL, 0x1000, MEM_RESERVE, PAGE_READWRITE);
			DWORD old;
			VirtualProtect(reserved, 0x1000, PAGE_EXECUTE_READ, &old);
		},
		{},
	},
	{
		// Private memory cannot be made copy-on-write, so the call fails
		"Failed change to PAGE_EXECUTE_WRITECOPY is not reported",
		[](HookTestContext& context) {
			DWORD old;
			VirtualProtect(AllocWithPE(context), 0x1000, PAGE_EXECUTE_WRITECOPY, &old);
		},
		{},
	},
	{
		"Protection change through a handle without PROCESS_VM_OPERATION is not reported",
		[](HookTestContext& context) {
			HANDLE self = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, GetCurrentProcessId());
			DWORD old;
			VirtualProtectEx(self, AllocWithPE(context), 0x1000, PAGE_EXECUTE_READ, &old);
			CloseHandle(self);
		},
		{},
	},
};

int main(int argc, char** argv) {
	return RunHookTests(argc, argv, "NtProtectVirtualMemory", g_Cases);
}
