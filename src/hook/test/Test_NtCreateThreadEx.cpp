// Tests the Hooked_NtCreateThreadEx post-call check: a thread successfully created in another
// process is reported with its start address and THREAD_CREATE_FLAGS_*. The target is taken from
// the ProcessHandle argument. Threads created in the current process are not reported.
#include "hook_test_harness.hpp"

typedef NTSTATUS(NTAPI* NtCreateThreadEx_t)(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
	PVOID ObjectAttributes, HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument,
	ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PVOID AttributeList);

#define THREAD_CREATE_FLAGS_CREATE_SUSPENDED 0x1

/// @brief A start address valid in the remote target: kernel32 is mapped at the same address in
/// every process of the same architecture. The remote threads are created suspended and never run.
static LPTHREAD_START_ROUTINE RemoteStart() {
	return (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("kernel32.dll"), "ExitThread");
}

static DWORD WINAPI ReturnImmediately(LPVOID) {
	return 0;
}

/// @brief Waits for a thread to finish, then closes its handle.
static void Join(HANDLE thread) {
	if (thread != NULL) {
		WaitForSingleObject(thread, INFINITE);
		CloseHandle(thread);
	}
}

static const std::vector<HookTestCase> g_Cases = {
	{
		"Suspended thread created in remote process",
		[](HookTestContext& context) {
			HANDLE thread = CreateRemoteThread(context.RemoteProcess(), NULL, 0, RemoteStart(), NULL, CREATE_SUSPENDED, NULL);
			if (thread != NULL) {
				CloseHandle(thread);
			}
		},
		{ "NtCreateThreadEx: thread created in a remote process, start *, flags 0x1" },
	},
	{
		"Suspended thread created in remote process through ntdll",
		[](HookTestContext& context) {
			HANDLE thread = NULL;
			NtdllFunction<NtCreateThreadEx_t>("NtCreateThreadEx")(&thread, THREAD_ALL_ACCESS, NULL,
				context.RemoteProcess(), (PVOID)RemoteStart(), NULL, THREAD_CREATE_FLAGS_CREATE_SUSPENDED, 0, 0, 0, NULL);
			if (thread != NULL) {
				CloseHandle(thread);
			}
		},
		{ "NtCreateThreadEx: thread created in a remote process, start *, flags 0x1" },
	},
	{
		"Thread created in current process is not reported",
		[](HookTestContext&) {
			Join(CreateThread(NULL, 0, ReturnImmediately, NULL, 0, NULL));
		},
		{},
	},
	{
		"Thread created through a real handle to self is not reported",
		[](HookTestContext&) {
			HANDLE self = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
			Join(CreateRemoteThread(self, NULL, 0, ReturnImmediately, NULL, 0, NULL));
			CloseHandle(self);
		},
		{},
	},
	{
		// An invalid handle is not the current process, so this exercises the post-call check:
		// the call fails and nothing is reported. (A handle opened with only
		// PROCESS_QUERY_LIMITED_INFORMATION is not a reliable failure: on Windows 10 22H2,
		// CreateRemoteThread through one succeeds.)
		"Failed remote thread creation is not reported",
		[](HookTestContext&) {
			HANDLE thread = CreateRemoteThread((HANDLE)(ULONG_PTR)0x7FFC, NULL, 0, RemoteStart(), NULL, CREATE_SUSPENDED, NULL);
			if (thread != NULL) {
				CloseHandle(thread);
			}
		},
		{},
	},
};

int main(int argc, char** argv) {
	return RunHookTests(argc, argv, "NtCreateThreadEx", g_Cases);
}
