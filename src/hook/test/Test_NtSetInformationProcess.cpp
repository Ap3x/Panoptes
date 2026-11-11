// Tests the Hooked_NtSetInformationProcess check. Setting ProcessProtectionInformation (61) is
// reported whether or not the call succeeds: only the kernel can change a process's protection,
// so from user mode the call always fails and the attempt itself is the signal. The event carries
// the status the call returned. Other information classes are not reported.
#include "hook_test_harness.hpp"
#include <winternl.h>

#define TEST_PROCESS_PROTECTION_INFORMATION ((PROCESSINFOCLASS)61)

/// The Win32 PROCESS_INFORMATION_CLASS value of ProcessProtectionLevelInfo, which in the native
/// enum is ProcessDebugPort. It must not be mistaken for the protection class
#define TEST_WIN32_PROTECTION_LEVEL_INFO ((PROCESSINFOCLASS)7)

typedef NTSTATUS(NTAPI* NtSetInformationProcess_t)(HANDLE ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength);

static void SetInformation(HANDLE process, PROCESSINFOCLASS informationClass, PVOID information, ULONG length) {
	NtdllFunction<NtSetInformationProcess_t>("NtSetInformationProcess")(process, informationClass, information, length);
}

/// @brief Asks to make a process a full protected process (PS_PROTECTION: WinTcb, Protected).
static void SetProtection(HANDLE process) {
	UCHAR protection = 0x62;
	SetInformation(process, TEST_PROCESS_PROTECTION_INFORMATION, &protection, sizeof(protection));
}

static const std::vector<HookTestCase> g_Cases = {
	{
		"Protection set on current process (pseudo-handle)",
		[](HookTestContext&) {
			SetProtection(GetCurrentProcess());
		},
		{ "NtSetInformationProcess: attempt to set the protection of the current process, status 0xc*" },
	},
	{
		"Protection set on current process (real handle to self)",
		[](HookTestContext&) {
			HANDLE self = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
			SetProtection(self);
			CloseHandle(self);
		},
		{ "NtSetInformationProcess: attempt to set the protection of the current process, status 0xc*" },
	},
	{
		"Protection set on remote process",
		[](HookTestContext& context) {
			SetProtection(context.RemoteProcess());
		},
		{ "NtSetInformationProcess: attempt to set the protection of the remote process, status 0xc*" },
	},
	{
		"Protection set through a handle without PROCESS_SET_INFORMATION",
		[](HookTestContext& context) {
			HANDLE remote = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, GetProcessId(context.RemoteProcess()));
			SetProtection(remote);
			CloseHandle(remote);
		},
		{ "NtSetInformationProcess: attempt to set the protection of the remote process, status 0xc*" },
	},
	{
		"Other information class that succeeds is not reported",
		[](HookTestContext&) {
			// Goes through NtSetInformationProcess(ProcessPriorityBoost)
			SetProcessPriorityBoost(GetCurrentProcess(), FALSE);
		},
		{},
	},
	{
		"Win32 ProcessProtectionLevelInfo value (native ProcessDebugPort) is not reported",
		[](HookTestContext&) {
			HANDLE port = NULL;
			SetInformation(GetCurrentProcess(), TEST_WIN32_PROTECTION_LEVEL_INFO, &port, sizeof(port));
		},
		{},
	},
};

int main(int argc, char** argv) {
	return RunHookTests(argc, argv, "NtSetInformationProcess", g_Cases);
}
