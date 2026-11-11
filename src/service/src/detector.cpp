// winsock2.h has to come before Windows.h (which pulls in the older winsock.h)
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <winternl.h>

#include "detector.h"
#include "panoptes.pb.h"
#include "containers.h"
#include "driver.h"
#include "error_message.h"
#include "grpc.hpp"
#include "utils.h"
#include "Configuration.hpp"
#include <vector>

#pragma region Peer Check

// The port at the end of a gRPC peer string: "ipv4:127.0.0.1:50123" or "ipv6:%5B::1%5D:50123"
static bool PeerPort(const std::string& peer, USHORT& port)
{
	size_t colon = peer.find_last_of(':');
	if (colon == std::string::npos || colon + 1 == peer.size()) {
		return false;
	}
	unsigned long value = 0;
	for (size_t i = colon + 1; i < peer.size(); i++) {
		if (peer[i] < '0' || peer[i] > '9') {
			return false;
		}
		value = value * 10 + (peer[i] - '0');
		if (value > 0xFFFF) {
			return false;
		}
	}
	port = (USHORT)value;
	return true;
}

// The TCP tables hold ports in network byte order in the low 16 bits
static USHORT TablePort(DWORD port)
{
	return _byteswap_ushort((USHORT)port);
}

// Finds the process that owns the client end of a connection to serverPort from clientPort
static bool FindConnectionOwner(ULONG family, USHORT clientPort, USHORT serverPort, DWORD& processId)
{
	std::vector<BYTE> buffer;
	DWORD size = 0;
	DWORD result;
	do {
		buffer.resize(size);
		result = GetExtendedTcpTable(buffer.empty() ? NULL : buffer.data(), &size, FALSE, family,
			TCP_TABLE_OWNER_PID_CONNECTIONS, 0);
	} while (result == ERROR_INSUFFICIENT_BUFFER);
	if (result != NO_ERROR) {
		return false;
	}

	if (family == AF_INET) {
		auto table = (const MIB_TCPTABLE_OWNER_PID*)buffer.data();
		for (DWORD i = 0; i < table->dwNumEntries; i++) {
			const auto& row = table->table[i];
			if (TablePort(row.dwLocalPort) == clientPort && TablePort(row.dwRemotePort) == serverPort) {
				processId = row.dwOwningPid;
				return true;
			}
		}
	}
	else {
		auto table = (const MIB_TCP6TABLE_OWNER_PID*)buffer.data();
		for (DWORD i = 0; i < table->dwNumEntries; i++) {
			const auto& row = table->table[i];
			if (TablePort(row.dwLocalPort) == clientPort && TablePort(row.dwRemotePort) == serverPort) {
				processId = row.dwOwningPid;
				return true;
			}
		}
	}
	return false;
}

static std::wstring ProcessImagePath(HANDLE process)
{
	WCHAR path[MAX_PATH * 2];
	DWORD length = ARRAYSIZE(path);
	return QueryFullProcessImageNameW(process, 0, path, &length) ? std::wstring(path, length) : L"";
}

bool IsDetectorPeer(const std::string& peer, int serverPort, std::string& why)
{
	USHORT clientPort = 0;
	if (!PeerPort(peer, clientPort)) {
		why = "unrecognized peer " + peer;
		return false;
	}

	DWORD processId = 0;
	if (!FindConnectionOwner(AF_INET, clientPort, (USHORT)serverPort, processId) &&
		!FindConnectionOwner(AF_INET6, clientPort, (USHORT)serverPort, processId)) {
		why = "no local process owns the connection from " + peer;
		return false;
	}

	HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
	if (process == NULL) {
		why = "cannot open process " + std::to_string(processId);
		return false;
	}
	std::wstring image = ProcessImagePath(process);
	CloseHandle(process);

	std::wstring expected = DetectorExecutablePath();
	if (image.empty() || expected.empty() || _wcsicmp(image.c_str(), expected.c_str()) != 0) {
		why = "process " + std::to_string(processId) + " (" + ToString(image) + ") is not " + ToString(expected);
		return false;
	}
	return true;
}

#pragma endregion

#pragma region Response

// ProcessBreakOnTermination: the process is critical, and ending it stops the system
#define PANO_PROCESS_BREAK_ON_TERMINATION 29

typedef NTSTATUS(NTAPI* NtQueryInformationProcess_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);

// Whether ending the process would bug check the machine. Unknown counts as critical
static bool IsCriticalProcess(HANDLE process)
{
	static auto query = (NtQueryInformationProcess_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess");
	ULONG critical = 0;
	if (query == NULL || query(process, PANO_PROCESS_BREAK_ON_TERMINATION, &critical, sizeof(critical), NULL) < 0) {
		return true;
	}
	return critical != 0;
}

// Ends a detected process. Returns what happened; terminated says whether it was ended
static std::string TerminateDetectedProcess(const Detection& detection, HANDLE& process, bool& terminated,
	std::wstring& image)
{
	terminated = false;
	DWORD processId = detection.process_id();
	if (processId == 0 || processId == 4) {
		return "refused: system process";
	}
	if (processId == GetCurrentProcessId()) {
		return "refused: the service itself";
	}

	process = OpenProcess(PROCESS_QUERY_INFORMATION | SYNCHRONIZE, FALSE, processId);
	if (process == NULL) {
		DWORD error = GetLastError();
		return (error == ERROR_INVALID_PARAMETER) ? "not needed: the process has exited"
			: "refused: cannot open the process (error " + std::to_string(error) + ")";
	}
	if (WaitForSingleObject(process, 0) == WAIT_OBJECT_0) {
		return "not needed: the process has exited";
	}
	if (IsServiceChildProcess(process)) {
		return "refused: a process the service started";
	}
	if (IsCriticalProcess(process)) {
		return "refused: critical system process";
	}

	// The detection reaches the service seconds after the events. If the process was created
	// after the last matching event, its ID belonged to another process that has since exited
	FILETIME created, exited, kernel, user;
	FILETIME matched;
	matched.dwLowDateTime = (DWORD)(detection.timestamp() & 0xFFFFFFFF);
	matched.dwHighDateTime = (DWORD)((UINT64)detection.timestamp() >> 32);
	if (detection.timestamp() == 0) {
		return "refused: the detection has no event time";
	}
	if (!GetProcessTimes(process, &created, &exited, &kernel, &user) || CompareFileTime(&created, &matched) > 0) {
		return "refused: the process ID was reused after the match";
	}

	image = ProcessImagePath(process);
	ERRORCODE result = TerminateProcessByDriver(processId);
	if (result != PANO_SUCCESS) {
		return "kill failed (error " + std::to_string(result) + ")";
	}
	terminated = true;
	return "terminated";
}

std::string RespondToDetection(const Detection& detection, const Configuration& configuration)
{
	if (detection.action() != DETECTION_ACTION_KILL && detection.action() != DETECTION_ACTION_QUARANTINE) {
		return "alerted";
	}
	if (!configuration.m_enforceDetectionActions) {
		return "alerted (EnforceDetectionActions is off)";
	}

	HANDLE process = NULL;
	bool terminated = false;
	std::wstring imagePath;
	std::string outcome = TerminateDetectedProcess(detection, process, terminated, imagePath);
	if (detection.action() == DETECTION_ACTION_QUARANTINE && terminated) {
		// The image is resolved by the service rather than taken from the detection, whose path
		// comes from the event and may be empty
		std::string image = ToString(imagePath);
		// A running image cannot be moved, so wait for the kill to complete
		WaitForSingleObject(process, 5000);
		if (image.empty()) {
			outcome += "; not quarantined: image path unknown";
		}
		else if (Configuration::IsPathInList(configuration.m_exclusions, image)) {
			outcome += "; not quarantined: " + image + " is in Exclusions";
		}
		else {
			outcome += MoveFileToQuarantine(image) ? "; quarantined " + image : "; quarantine of " + image + " failed";
		}
	}
	if (process != NULL) {
		CloseHandle(process);
	}
	return outcome;
}

#pragma endregion
