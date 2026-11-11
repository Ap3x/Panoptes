#pragma once
// Shared harness for the hook detection tests. Each test executable lists its cases and calls
// RunHookTests. The executable relaunches itself as a debuggee: the child loads the hook DLL and
// runs each case, and the parent, acting as the child's debugger, captures the "[Panoptes]"
// OutputDebugString messages the hooks emit and checks each case produced exactly the expected
// messages. The hooks only emit these messages in Debug builds, so in other configurations the
// tests report SKIPPED.
#include <Windows.h>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#ifdef _WIN64
#define HOOK_ARCH "x64"
#else
#define HOOK_ARCH "x86"
#endif

#define HOOK_DLL_NAME "PanoptesDLL" HOOK_ARCH ".dll"

/// @brief Looks up an ntdll export. Calls through the result go through the hooks, because the
/// hooks patch the export itself.
template <typename T>
inline T NtdllFunction(const char* name) {
	return (T)GetProcAddress(GetModuleHandleA("ntdll.dll"), name);
}

/// @brief Starts a suspended process. Returns an empty PROCESS_INFORMATION on failure.
inline PROCESS_INFORMATION StartSuspended(const std::string& commandLine) {
	std::string mutableLine = commandLine;
	STARTUPINFOA si{ sizeof(si) };
	PROCESS_INFORMATION pi{};
	if (!CreateProcessA(NULL, &mutableLine[0], NULL, NULL, FALSE, CREATE_SUSPENDED | CREATE_NO_WINDOW,
		NULL, NULL, &si, &pi)) {
		fprintf(stderr, "    failed to start %s (error %lu)\n", commandLine.c_str(), GetLastError());
		pi = {};
	}
	return pi;
}

/// @brief Resources shared by the cases of one test run, created in the child process. The
/// remote processes are started by Start, before the first case, so what process creation itself
/// triggers (CreateProcess writes to the child's PEB) is reported as setup rather than
/// attributed to a case.
class HookTestContext {
public:
	~HookTestContext() {
		Stop(m_remote);
		Stop(m_wow64Remote);
	}

	/// @brief Starts the remote targets. Called by the harness before the first case.
	void Start() {
		m_remote = StartSuspended("cmd.exe /c exit");
#ifdef _WIN64
		char wow64Dir[MAX_PATH];
		if (GetSystemWow64DirectoryA(wow64Dir, MAX_PATH) != 0) {
			m_wow64Remote = StartSuspended(std::string("\"") + wow64Dir + "\\cmd.exe\" /c exit");
		}
#endif
	}

	/// @brief A buffer holding a real PE image: this executable's own mapped headers.
	const BYTE* PEImage() const { return (const BYTE*)GetModuleHandleA(NULL); }

	/// @brief The number of PEImage() bytes the cases copy, one page.
	static constexpr SIZE_T PESize = 0x1000;

	/// @brief A suspended cmd.exe of the same architecture to use as a remote target.
	HANDLE RemoteProcess() const { return m_remote.hProcess; }

	/// @brief The suspended main thread of RemoteProcess.
	HANDLE RemoteThread() const { return m_remote.hThread; }

	/// @brief A suspended 32-bit cmd.exe, started only by x64 runs: from x64, a WOW64 target has
	/// both a 64-bit and a 32-bit PEB.
	HANDLE Wow64RemoteProcess() const { return m_wow64Remote.hProcess; }

private:
	static void Stop(PROCESS_INFORMATION& process) {
		if (process.hProcess != NULL) {
			TerminateProcess(process.hProcess, 0);
			CloseHandle(process.hThread);
			CloseHandle(process.hProcess);
			process = {};
		}
	}

	PROCESS_INFORMATION m_remote{};
	PROCESS_INFORMATION m_wow64Remote{};
};

/// @brief One test case. Run executes in the child with the hooks placed. Expected lists the
/// "[Panoptes] " messages (without that prefix) the case must produce, in order; '*' matches any
/// run of characters, e.g. for addresses.
struct HookTestCase {
	const char* Name;
	void (*Run)(HookTestContext& context);
	std::vector<std::string> Expected;
};

namespace hook_test_detail {

constexpr const char* kCaseMarker = "@@PANO_CASE ";
constexpr const char* kEndMarker = "@@PANO_END";
constexpr const char* kMessagePrefix = "[Panoptes] ";

/// @brief Matches text against a pattern where '*' matches any run of characters.
inline bool WildcardMatch(const char* pattern, const char* text) {
	if (*pattern == '\0') {
		return *text == '\0';
	}
	if (*pattern == '*') {
		for (const char* t = text;; t++) {
			if (WildcardMatch(pattern + 1, t)) {
				return true;
			}
			if (*t == '\0') {
				return false;
			}
		}
	}
	return *pattern == *text && WildcardMatch(pattern + 1, text + 1);
}

/// @brief Child side: loads the hook DLL from bin/<config>, one directory above the tests
/// folder, then runs every case, announcing each with a marker message.
inline int RunChild(const std::vector<HookTestCase>& cases) {
	char dllPath[MAX_PATH];
	DWORD length = GetModuleFileNameA(NULL, dllPath, MAX_PATH);
	char* lastSlash = (length != 0 && length < MAX_PATH) ? strrchr(dllPath, '\\') : NULL;
	if (lastSlash == NULL) {
		fprintf(stderr, "    unexpected executable path\n");
		return 1;
	}
	*(lastSlash + 1) = '\0';
	strcat_s(dllPath, MAX_PATH, "..\\" HOOK_DLL_NAME);

	if (LoadLibraryA(dllPath) == NULL) {
		fprintf(stderr, "    failed to load %s (error %lu)\n", dllPath, GetLastError());
		return 1;
	}

	// Start the remote targets before the first case marker, so anything process creation itself
	// triggers is reported as setup rather than attributed to a case
	HookTestContext context;
	context.Start();

	for (size_t i = 0; i < cases.size(); i++) {
		std::string marker = kCaseMarker + std::to_string(i);
		OutputDebugStringA(marker.c_str());
		cases[i].Run(context);
	}

	// What follows (terminating the targets, unloading DLLs and removing the hooks at exit) is
	// teardown, not part of the last case
	OutputDebugStringA(kEndMarker);
	return 0;
}

/// @brief Parent side: runs the child under a debug loop and returns the hook messages it
/// emitted, grouped by case. Returns false if the child could not be run or did not exit cleanly.
inline bool CaptureChild(const char* exePath, size_t caseCount, std::vector<std::vector<std::string>>& messages) {
	messages.assign(caseCount, {});

	char commandLine[MAX_PATH + 32];
	sprintf_s(commandLine, "\"%s\" --child", exePath);

	// The child's stdout goes to NUL: Debug builds of Detours trace to it while placing hooks.
	// The harness reports child errors on stderr, which is passed through.
	SECURITY_ATTRIBUTES inherit{ sizeof(inherit), NULL, TRUE };
	HANDLE nul = CreateFileA("NUL", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &inherit, OPEN_EXISTING, 0, NULL);
	STARTUPINFOA si{ sizeof(si) };
	si.dwFlags = STARTF_USESTDHANDLES;
	si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
	si.hStdOutput = nul;
	si.hStdError = GetStdHandle(STD_ERROR_HANDLE);

	PROCESS_INFORMATION pi{};
	BOOL started = CreateProcessA(NULL, commandLine, NULL, NULL, TRUE, DEBUG_ONLY_THIS_PROCESS, NULL, NULL, &si, &pi);
	DWORD startError = GetLastError();
	if (nul != INVALID_HANDLE_VALUE) {
		CloseHandle(nul);
	}
	if (!started) {
		printf("failed to start the test child (error %lu)\n", startError);
		return false;
	}

	bool clean = true;
	bool ended = false;
	size_t currentCase = SIZE_MAX;
	DWORD exitCode = 1;
	for (;;) {
		DEBUG_EVENT event;
		if (!WaitForDebugEvent(&event, INFINITE)) {
			clean = false;
			break;
		}

		DWORD continueStatus = DBG_CONTINUE;
		switch (event.dwDebugEventCode) {
		case OUTPUT_DEBUG_STRING_EVENT: {
			// Only ANSI strings are emitted by the hooks and the harness
			char text[512] = {};
			SIZE_T toRead = event.u.DebugString.nDebugStringLength;
			if (toRead > sizeof(text) - 1) {
				toRead = sizeof(text) - 1;
			}
			SIZE_T bytesRead = 0;
			ReadProcessMemory(pi.hProcess, event.u.DebugString.lpDebugStringData, text, toRead, &bytesRead);
			text[bytesRead] = '\0';

			std::string line(text);
			while (!line.empty() && (line.back() == '\n' || line.back() == '\r' || line.back() == '\0')) {
				line.pop_back();
			}

			if (line.rfind(kCaseMarker, 0) == 0) {
				currentCase = strtoul(line.c_str() + strlen(kCaseMarker), NULL, 10);
			}
			else if (line == kEndMarker) {
				ended = true;
				currentCase = SIZE_MAX;
			}
			else if (line.rfind(kMessagePrefix, 0) == 0) {
				if (currentCase < caseCount) {
					messages[currentCase].push_back(line.substr(strlen(kMessagePrefix)));
				}
				else if (!ended) {
					// Emitted during setup (loading the DLL, starting the remote processes).
					// Teardown messages are not printed: they are the hooks reacting to the DLL
					// unloading and Detours removing them
					printf("  [setup] %s\n", line.c_str() + strlen(kMessagePrefix));
				}
			}
			break;
		}
		case EXCEPTION_DEBUG_EVENT:
			if (event.u.Exception.ExceptionRecord.ExceptionCode != EXCEPTION_BREAKPOINT) {
				if (!event.u.Exception.dwFirstChance) {
					printf("test child crashed with exception 0x%08lx\n", event.u.Exception.ExceptionRecord.ExceptionCode);
					clean = false;
				}
				continueStatus = DBG_EXCEPTION_NOT_HANDLED;
			}
			break;
		case CREATE_PROCESS_DEBUG_EVENT:
			if (event.u.CreateProcessInfo.hFile != NULL) {
				CloseHandle(event.u.CreateProcessInfo.hFile);
			}
			break;
		case LOAD_DLL_DEBUG_EVENT:
			if (event.u.LoadDll.hFile != NULL) {
				CloseHandle(event.u.LoadDll.hFile);
			}
			break;
		case EXIT_PROCESS_DEBUG_EVENT:
			exitCode = event.u.ExitProcess.dwExitCode;
			break;
		}

		ContinueDebugEvent(event.dwProcessId, event.dwThreadId, continueStatus);
		if (event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
			break;
		}
	}

	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);

	if (exitCode != 0) {
		printf("test child exited with code %lu\n", exitCode);
		clean = false;
	}
	return clean;
}

} // namespace hook_test_detail

/// @brief Runs the cases and prints a PASS/FAIL line for each. Call from main.
/// @return The process exit code: 0 if every case passed (or the run was skipped), 1 otherwise.
inline int RunHookTests(int argc, char** argv, const char* apiName, const std::vector<HookTestCase>& cases) {
	using namespace hook_test_detail;

	if (argc >= 2 && strcmp(argv[1], "--child") == 0) {
		return RunChild(cases);
	}

	printf("%s hook tests (%s)\n", apiName, HOOK_ARCH);

#ifndef _DEBUG
	printf("SKIPPED: the hooks only emit detection messages in Debug builds\n");
	return 0;
#else
	char exePath[MAX_PATH];
	DWORD length = GetModuleFileNameA(NULL, exePath, MAX_PATH);
	if (length == 0 || length == MAX_PATH) {
		printf("failed to get the executable path (error %lu)\n", GetLastError());
		return 1;
	}

	std::vector<std::vector<std::string>> messages;
	bool clean = CaptureChild(exePath, cases.size(), messages);

	int failures = 0;
	for (size_t i = 0; i < cases.size(); i++) {
		const HookTestCase& testCase = cases[i];
		const std::vector<std::string>& actual = messages[i];

		bool passed = actual.size() == testCase.Expected.size();
		for (size_t m = 0; passed && m < actual.size(); m++) {
			passed = WildcardMatch(testCase.Expected[m].c_str(), actual[m].c_str());
		}

		printf("  [%s] %s\n", passed ? "PASS" : "FAIL", testCase.Name);
		if (!passed) {
			failures++;
			for (const std::string& expected : testCase.Expected) {
				printf("      expected: %s\n", expected.c_str());
			}
			if (testCase.Expected.empty()) {
				printf("      expected: no messages\n");
			}
			for (const std::string& line : actual) {
				printf("      actual:   %s\n", line.c_str());
			}
			if (actual.empty()) {
				printf("      actual:   no messages\n");
			}
		}
	}

	if (!clean) {
		failures++;
	}

	printf("%s\n", failures == 0 ? "PASS" : "FAIL");
	return failures == 0 ? 0 : 1;
#endif
}
