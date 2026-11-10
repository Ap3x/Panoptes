// Tests the Hooked_NtQueueApcThread and Hooked_NtQueueApcThreadEx2 post-call check: an APC
// successfully queued to a thread in another process is reported with the API, the APC routine
// and the QUEUE_USER_APC_FLAGS_*. The thread's process is found with GetProcessIdOfThread, so a
// handle without THREAD_QUERY_LIMITED_INFORMATION is treated as remote. APCs queued to threads
// of the current process are not reported.
//
// KernelBase's QueueUserAPC and QueueUserAPC2 call NtQueueApcThreadEx2, passing ntdll's APC
// dispatcher as the routine, so the routine reported for them is the dispatcher rather than the
// caller's function.
#include "hook_test_harness.hpp"

typedef VOID(NTAPI* PS_APC_ROUTINE_t)(PVOID ApcArgument1, PVOID ApcArgument2, PVOID ApcArgument3);
typedef NTSTATUS(NTAPI* NtQueueApcThread_t)(HANDLE ThreadHandle, PS_APC_ROUTINE_t ApcRoutine,
	PVOID ApcArgument1, PVOID ApcArgument2, PVOID ApcArgument3);
typedef NTSTATUS(NTAPI* NtQueueApcThreadEx2_t)(HANDLE ThreadHandle, HANDLE ReserveHandle,
	ULONG ApcFlags, PS_APC_ROUTINE_t ApcRoutine, PVOID ApcArgument1, PVOID ApcArgument2, PVOID ApcArgument3);

#define TEST_SPECIAL_USER_APC 0x1

static VOID NTAPI NtApc(PVOID, PVOID, PVOID) {}
static VOID CALLBACK UserApc(ULONG_PTR) {}

static void QueueNt(HANDLE thread) {
	NtdllFunction<NtQueueApcThread_t>("NtQueueApcThread")(thread, NtApc, NULL, NULL, NULL);
}

static NTSTATUS QueueNtEx2(HANDLE thread, ULONG flags) {
	auto queue = NtdllFunction<NtQueueApcThreadEx2_t>("NtQueueApcThreadEx2");
	if (queue == NULL) {
		fprintf(stderr, "    NtQueueApcThreadEx2 is not exported by this ntdll\n");
		return (NTSTATUS)0xC0000002; // STATUS_NOT_IMPLEMENTED
	}
	return queue(thread, NULL, flags, NtApc, NULL, NULL, NULL);
}

/// @brief Runs any APCs queued to the current thread, so none are left for later cases.
static void DrainApcs() {
	SleepEx(0, TRUE);
}

// The remote thread is suspended, so the APCs queued to it never run
static const std::vector<HookTestCase> g_Cases = {
	// NtQueueApcThread

	{
		"APC queued to a remote thread",
		[](HookTestContext& context) {
			QueueNt(context.RemoteThread());
		},
		{ "NtQueueApcThread: APC queued to a thread in the remote process, routine *, flags 0x0" },
	},
	{
		"APC queued to the current thread (pseudo-handle) is not reported",
		[](HookTestContext&) {
			QueueNt(GetCurrentThread());
			DrainApcs();
		},
		{},
	},
	{
		"APC queued through a real handle to the current thread is not reported",
		[](HookTestContext&) {
			HANDLE thread = OpenThread(THREAD_SET_CONTEXT | THREAD_QUERY_LIMITED_INFORMATION, FALSE, GetCurrentThreadId());
			QueueNt(thread);
			CloseHandle(thread);
			DrainApcs();
		},
		{},
	},
	{
		// Without query access the thread's process cannot be found, so it is reported as remote
		// rather than missed
		"APC queued through a local thread handle without query access is reported as remote",
		[](HookTestContext&) {
			HANDLE thread = OpenThread(THREAD_SET_CONTEXT, FALSE, GetCurrentThreadId());
			QueueNt(thread);
			CloseHandle(thread);
			DrainApcs();
		},
		{ "NtQueueApcThread: APC queued to a thread in the remote process, routine *, flags 0x0" },
	},
	{
		"Failed APC queue to a remote thread is not reported",
		[](HookTestContext& context) {
			// The handle lacks THREAD_SET_CONTEXT
			HANDLE thread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, GetThreadId(context.RemoteThread()));
			QueueNt(thread);
			CloseHandle(thread);
		},
		{},
	},

	// NtQueueApcThreadEx2

	{
		"Ex2: APC queued to a remote thread",
		[](HookTestContext& context) {
			QueueNtEx2(context.RemoteThread(), 0);
		},
		{ "NtQueueApcThreadEx2: APC queued to a thread in the remote process, routine *, flags 0x0" },
	},
#ifdef _WIN64
	{
		// Special user APCs run without the thread entering an alertable wait
		"Ex2: special user APC queued to a remote thread",
		[](HookTestContext& context) {
			QueueNtEx2(context.RemoteThread(), TEST_SPECIAL_USER_APC);
		},
		{ "NtQueueApcThreadEx2: APC queued to a thread in the remote process, routine *, flags 0x1" },
	},
#else
	{
		// Special user APCs are not supported for WOW64 processes, so the call fails
		// (STATUS_NOT_SUPPORTED) and the post-call check reports nothing
		"Ex2: special user APC to a 32-bit remote thread fails and is not reported",
		[](HookTestContext& context) {
			NTSTATUS status = QueueNtEx2(context.RemoteThread(), TEST_SPECIAL_USER_APC);
			if (status != (NTSTATUS)0xC00000BB) {
				fprintf(stderr, "    expected STATUS_NOT_SUPPORTED, got 0x%08lx\n", (unsigned long)status);
			}
		},
		{},
	},
#endif
	{
		"Ex2: APC queued to the current thread is not reported",
		[](HookTestContext&) {
			QueueNtEx2(GetCurrentThread(), 0);
			DrainApcs();
		},
		{},
	},
	{
		"Ex2: failed APC queue to a remote thread is not reported",
		[](HookTestContext& context) {
			HANDLE thread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, GetThreadId(context.RemoteThread()));
			QueueNtEx2(thread, 0);
			CloseHandle(thread);
		},
		{},
	},

	// The Win32 API, which goes through NtQueueApcThreadEx2

	{
		"QueueUserAPC to a remote thread",
		[](HookTestContext& context) {
			if (!QueueUserAPC(UserApc, context.RemoteThread(), 0)) {
				fprintf(stderr, "    QueueUserAPC failed (error %lu)\n", GetLastError());
			}
		},
		{ "NtQueueApcThreadEx2: APC queued to a thread in the remote process, routine *, flags 0x0" },
	},
	{
		"QueueUserAPC to the current thread is not reported",
		[](HookTestContext&) {
			QueueUserAPC(UserApc, GetCurrentThread(), 0);
			DrainApcs();
		},
		{},
	},
};

int main(int argc, char** argv) {
	return RunHookTests(argc, argv, "NtQueueApcThread", g_Cases);
}
