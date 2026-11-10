#include "driver_events.h"
#include "pano_events.h"
#include "error_message.h"
#include "grpc.hpp"
#include "pano_log.h"
#include "utils.h"
#include <nlohmann/json.hpp>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

// Number of IOCTL_PANOPTES_GET_EVENT requests kept pending in the driver at once, so
// events keep flowing while one completion is being processed
#define PANO_PENDING_EVENT_REQUESTS 4

// Writes are coalesced into one FileModified event per file. The event is logged (and a PE
// file scanned) once the file goes PANO_WRITE_SETTLE_MS without a write, so files are
// scanned once complete. Files that never stop being written are still reported every
// PANO_WRITE_MAX_WINDOW_MS
#define PANO_WRITE_SETTLE_MS 2000
#define PANO_WRITE_MAX_WINDOW_MS 30000
#define PANO_WRITE_POLL_MS 500

typedef struct _PANO_EVENT_REQUEST
{
	OVERLAPPED Overlapped;
	BYTE Buffer[PANO_MAX_EVENT_SIZE];
} PANO_EVENT_REQUEST, *PPANO_EVENT_REQUEST;

static HANDLE g_Device = INVALID_HANDLE_VALUE;
static HANDLE g_CompletionPort = NULL;
static PANO_EVENT_REQUEST g_Requests[PANO_PENDING_EVENT_REQUESTS];
static std::thread g_ReaderThread;
static std::thread g_ScanThread;
static std::atomic<bool> g_Stopping = false;

// Writes to one file since its last FileModified event
typedef struct _PANO_WRITTEN_FILE
{
	ULONGLONG FirstWriteTick;
	ULONGLONG LastWriteTick;
	FILETIME FirstWriteTime;
	UINT64 ProcessId; // the most recent writer
	UINT64 Writes;
	UINT64 Bytes;
	bool IsDosPath;
} PANO_WRITTEN_FILE;

static std::mutex g_WrittenFilesLock;
static std::unordered_map<std::string, PANO_WRITTEN_FILE> g_WrittenFiles;

// Files the reader thread wants scanned. Checking whether a file is a PE opens and reads it,
// so WrittenFileScanThread does that rather than the reader, which must keep up with the driver
static std::mutex g_PendingScansLock;
static std::vector<std::string> g_PendingScans;

#ifdef _DEBUG
// Debug builds echo each logged event to the console. Writing to a console is slow, so lines
// are collected here and printed in batches by ConsoleEchoThread rather than by the thread
// that logged them. Past PANO_MAX_ECHO_BUFFER bytes, lines are left out of the echo (never
// the log file) and counted
#define PANO_MAX_ECHO_BUFFER (4 * 1024 * 1024)
static std::mutex g_EchoLock;
static std::condition_variable g_EchoReady;
static std::string g_EchoBuffer;
static UINT64 g_EchoSkipped = 0;
static bool g_EchoStopping = false;
static std::thread g_EchoThread;
#endif

// NT device prefixes (e.g. "\Device\HarddiskVolume3") mapped to drive letters ("C:")
static std::vector<std::pair<std::wstring, std::wstring>> g_DeviceMap;

// Path patterns from the LogExclusions setting. Matching events are not logged, but the
// files are still scanned
static std::vector<std::string> g_LogExclusions;

static bool IsLogExcluded(const std::string &path)
{
	return Configuration::IsPathInList(g_LogExclusions, path);
}

#pragma region Path Conversion

static void BuildDeviceMap()
{
	g_DeviceMap.clear();
	WCHAR drive[] = L"A:";
	WCHAR target[MAX_PATH];
	for (WCHAR letter = L'A'; letter <= L'Z'; letter++)
	{
		drive[0] = letter;
		if (QueryDosDeviceW(drive, target, MAX_PATH) != 0)
		{
			g_DeviceMap.emplace_back(target, drive);
		}
	}
}

// Converts a name reported by the minifilter (an NT path) into a path the rest of the
// service can open. Returns an empty string when there is no DOS equivalent.
static std::wstring ToDosPath(const std::wstring &ntPath)
{
	for (const auto &[device, drive] : g_DeviceMap)
	{
		if (ntPath.size() > device.size() &&
			ntPath[device.size()] == L'\\' &&
			_wcsnicmp(ntPath.c_str(), device.c_str(), device.size()) == 0)
		{
			return drive + ntPath.substr(device.size());
		}
	}

	const std::wstring mupPrefix = L"\\Device\\Mup\\";
	if (_wcsnicmp(ntPath.c_str(), mupPrefix.c_str(), mupPrefix.size()) == 0)
	{
		return L"\\\\" + ntPath.substr(mupPrefix.size());
	}

	return L"";
}

// Named pipes and mailslots are shown the way programs open them (\\.\pipe\name), which is
// also the form LogExclusions patterns use. Other NT paths are returned unchanged. These are
// not DOS paths: nothing is scanned under them
static std::wstring ToPipeOrMailslotPath(const std::wstring &ntPath)
{
	static const std::pair<std::wstring, std::wstring> prefixes[] = {
		{L"\\Device\\NamedPipe\\", L"\\\\.\\pipe\\"},
		{L"\\Device\\Mailslot\\", L"\\\\.\\mailslot\\"},
	};
	for (const auto &[device, display] : prefixes)
	{
		if (_wcsnicmp(ntPath.c_str(), device.c_str(), device.size()) == 0)
		{
			return display + ntPath.substr(device.size());
		}
	}
	return ntPath;
}

#pragma endregion

#pragma region Event Handling

static const char *EventTypeName(UINT32 type)
{
	switch (type)
	{
	case PANO_EVENT_FILE_CREATED:
		return "FileCreated";
	case PANO_EVENT_FILE_OPENED:
		return "FileOpened";
	case PANO_EVENT_FILE_OVERWRITTEN:
		return "FileOverwritten";
	case PANO_EVENT_FILE_SUPERSEDED:
		return "FileSuperseded";
	case PANO_EVENT_FILE_WRITE:
		return "FileWrite";
	case PANO_EVENT_NAMED_PIPE_CREATE:
		return "NamedPipeCreate";
	case PANO_EVENT_NAMED_PIPE_OPEN:
		return "NamedPipeOpen";
	case PANO_EVENT_MAILSLOT_CREATE:
		return "MailslotCreate";
	case PANO_EVENT_MAILSLOT_OPEN:
		return "MailslotOpen";
	case PANO_EVENT_FILE_DELETE:
		return "FileDeleted";
	case PANO_EVENT_FILE_RENAME:
		return "FileRenamed";
	case PANO_EVENT_PROCESS_CREATED:
		return "ProcessCreated";
	case PANO_EVENT_PROCESS_TERMINATED:
		return "ProcessTerminated";
	case PANO_EVENT_FILE_MODIFIED:
		return "FileModified";
	case PANO_EVENT_FILE_SECURITY_CHANGED:
		return "FileSecurityChanged";
	case PANO_EVENT_FILE_EA_CHANGED:
		return "FileExtendedAttributesChanged";
	default:
		return nullptr;
	}
}

static FILETIME ToFileTime(INT64 timestamp)
{
	FILETIME fileTime;
	fileTime.dwLowDateTime = (DWORD)(timestamp & 0xFFFFFFFF);
	fileTime.dwHighDateTime = (DWORD)(timestamp >> 32);
	return fileTime;
}

// Events are ordered_json so keys are written in insertion order; every event sets "Event"
// first so each log line starts with its type
static void LogEvent(const nlohmann::ordered_json &event)
{
	std::string line = event.dump();
	line += '\n';
	WriteToLogFile(line);
#ifdef _DEBUG
	{
		std::lock_guard<std::mutex> lock(g_EchoLock);
		if (g_EchoBuffer.size() + line.size() <= PANO_MAX_ECHO_BUFFER)
		{
			g_EchoBuffer += line;
		}
		else
		{
			g_EchoSkipped++;
		}
	}
	g_EchoReady.notify_one();
#endif
}

#ifdef _DEBUG
static void ConsoleEchoThread()
{
	std::string batch;
	for (;;)
	{
		UINT64 skipped = 0;
		bool stopping = false;
		{
			std::unique_lock<std::mutex> lock(g_EchoLock);
			g_EchoReady.wait(lock, [] { return !g_EchoBuffer.empty() || g_EchoStopping; });
			batch.swap(g_EchoBuffer);
			skipped = g_EchoSkipped;
			g_EchoSkipped = 0;
			stopping = g_EchoStopping;
		}

		if (!batch.empty())
		{
			std::cout.write(batch.data(), batch.size());
			batch.clear();
		}
		if (skipped > 0)
		{
			std::cout << "[console echo fell behind: " << skipped << " events not shown here; they are in the log file]\n";
		}
		std::cout.flush();

		// Everything logged before stopping has been printed
		if (stopping)
		{
			return;
		}
	}
}
#endif

// True if the file starts with a DOS header that points at a PE signature
static bool IsPortableExecutable(const std::string &path)
{
	HANDLE file = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
							  NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE)
	{
		return false;
	}

	bool isPe = false;
	IMAGE_DOS_HEADER dosHeader;
	DWORD bytesRead = 0;
	if (ReadFile(file, &dosHeader, sizeof(dosHeader), &bytesRead, NULL) &&
		bytesRead == sizeof(dosHeader) &&
		dosHeader.e_magic == IMAGE_DOS_SIGNATURE &&
		dosHeader.e_lfanew > 0)
	{
		DWORD signature = 0;
		LARGE_INTEGER offset;
		offset.QuadPart = dosHeader.e_lfanew;
		if (SetFilePointerEx(file, offset, NULL, FILE_BEGIN) &&
			ReadFile(file, &signature, sizeof(signature), &bytesRead, NULL) &&
			bytesRead == sizeof(signature))
		{
			isPe = (signature == IMAGE_NT_SIGNATURE);
		}
	}

	CloseHandle(file);
	return isPe;
}

// Only PE files are scanned. The containers scan portable executables, and most file
// activity (databases, journals, caches) is in files that can never be one
static bool IsScanCandidate(const std::string &path)
{
	DWORD attributes = GetFileAttributesA(path.c_str());
	if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_DIRECTORY))
	{
		return false;
	}
	return IsPortableExecutable(path);
}

// Scans the file if it is a PE. Opens and reads the file, so only WrittenFileScanThread calls it
static void QueueFileScan(const std::string &path)
{
	if (IsScanCandidate(path))
	{
		SelfQueuePeScan(path, "");
	}
}

// Hands a file to WrittenFileScanThread to scan. Used by the reader thread
static void RequestFileScan(const std::string &path)
{
	std::lock_guard<std::mutex> lock(g_PendingScansLock);
	g_PendingScans.push_back(path);
}

// Names the parts of a security descriptor in a SECURITY_INFORMATION value. Bits without a
// name are listed in hex
static nlohmann::json SecurityInformationNames(UINT32 securityInformation)
{
	static const std::pair<UINT32, const char *> names[] = {
		{OWNER_SECURITY_INFORMATION, "Owner"},
		{GROUP_SECURITY_INFORMATION, "Group"},
		{DACL_SECURITY_INFORMATION, "Dacl"},
		{SACL_SECURITY_INFORMATION, "Sacl"},
		{LABEL_SECURITY_INFORMATION, "Label"},
		{ATTRIBUTE_SECURITY_INFORMATION, "Attribute"},
		{SCOPE_SECURITY_INFORMATION, "Scope"},
		{PROCESS_TRUST_LABEL_SECURITY_INFORMATION, "ProcessTrustLabel"},
		{BACKUP_SECURITY_INFORMATION, "Backup"},
		{PROTECTED_DACL_SECURITY_INFORMATION, "ProtectedDacl"},
		{PROTECTED_SACL_SECURITY_INFORMATION, "ProtectedSacl"},
		{UNPROTECTED_DACL_SECURITY_INFORMATION, "UnprotectedDacl"},
		{UNPROTECTED_SACL_SECURITY_INFORMATION, "UnprotectedSacl"},
	};

	nlohmann::json result = nlohmann::json::array();
	UINT32 remaining = securityInformation;
	for (const auto &[bit, name] : names)
	{
		if (securityInformation & bit)
		{
			result.push_back(name);
			remaining &= ~bit;
		}
	}
	if (remaining != 0)
	{
		char hex[16];
		sprintf_s(hex, "0x%X", remaining);
		result.push_back(hex);
	}
	return result;
}

// One event per handle that wrote to a file, sent by the driver when the handle is closed or,
// with PANO_FLAG_HANDLE_STILL_OPEN, while it keeps writing. Logged as FileModified like the
// events WrittenFileScanThread builds from an older driver's individual writes
static void HandleFileModifiedEvent(const PANO_EVENT_HEADER *header, const PANO_FILE_MODIFIED_EVENT_DATA *data)
{
	if (data->ProcessId == GetCurrentProcessId())
	{
		return;
	}

	std::wstring ntPath(data->FileName, data->NameLength);
	std::wstring dosPath = ToDosPath(ntPath);
	std::string path = ToString(dosPath.empty() ? ToPipeOrMailslotPath(ntPath) : dosPath);
	bool stillOpen = (data->Flags & PANO_FLAG_HANDLE_STILL_OPEN) != 0;

	nlohmann::ordered_json event;
	event["Event"] = EventTypeName(header->Type);
	event["PID"] = data->ProcessId;
	event["Path"] = path;
	event["Writes"] = data->Writes;
	event["Bytes"] = data->Bytes;
	event["Time"] = FormatSystemTime(ToFileTime(data->FirstWriteTime));
	if (stillOpen)
	{
		event["StillOpen"] = true;
	}
	if (data->Flags & PANO_FLAG_NAME_TRUNCATED)
	{
		event["NameTruncated"] = true;
	}
	if (!IsLogExcluded(path))
	{
		LogEvent(event);
	}

	// A file still being written is not complete yet; it is scanned when its handle closes
	if (!stillOpen && !dosPath.empty())
	{
		RequestFileScan(path);
	}
}

static void HandleFileEvent(const PANO_EVENT_HEADER *header, const PANO_FILE_EVENT_DATA *data)
{
	// The service's own I/O (database, logs, hashing) would otherwise feed back into itself
	if (data->ProcessId == GetCurrentProcessId())
	{
		return;
	}

	// The driver no longer reports opens; this only matters with an older driver
	if (header->Type == PANO_EVENT_FILE_OPENED)
	{
		return;
	}

	std::wstring ntPath(data->FileName, data->NameLength);
	std::wstring dosPath = ToDosPath(ntPath);
	std::string path = ToString(dosPath.empty() ? ToPipeOrMailslotPath(ntPath) : dosPath);

	FILETIME timestamp = ToFileTime(header->Timestamp);

	// Writes arrive in bursts; they are coalesced and logged by WrittenFileScanThread
	if (header->Type == PANO_EVENT_FILE_WRITE)
	{
		if (path.empty())
		{
			return;
		}

		ULONGLONG now = GetTickCount64();
		std::lock_guard<std::mutex> lock(g_WrittenFilesLock);
		auto [it, inserted] = g_WrittenFiles.try_emplace(path);
		PANO_WRITTEN_FILE &file = it->second;
		if (inserted)
		{
			file.FirstWriteTick = now;
			file.FirstWriteTime = timestamp;
			file.Writes = 0;
			file.Bytes = 0;
			file.IsDosPath = !dosPath.empty();
		}
		file.LastWriteTick = now;
		file.ProcessId = data->ProcessId;
		file.Writes++;
		file.Bytes += data->Length;
		return;
	}

	nlohmann::ordered_json event;
	event["Event"] = EventTypeName(header->Type);
	event["PID"] = data->ProcessId;
	event["TID"] = data->ThreadId;
	event["Path"] = path;
	event["Time"] = FormatSystemTime(timestamp);
	if (data->Flags & PANO_FLAG_OPLOCKED)
	{
		event["Oplocked"] = true;
	}
	if (data->Flags & PANO_FLAG_NAME_TRUNCATED)
	{
		event["NameTruncated"] = true;
	}
	if (data->Flags & PANO_FLAG_DELETE_ON_CLOSE)
	{
		event["DeleteOnClose"] = true;
	}
	if (header->Type == PANO_EVENT_FILE_SECURITY_CHANGED)
	{
		// Length holds the SECURITY_INFORMATION flags of the parts that were set
		event["Changed"] = SecurityInformationNames(data->Length);
	}
	else if (header->Type == PANO_EVENT_FILE_EA_CHANGED)
	{
		event["Bytes"] = data->Length;
	}
	if (!IsLogExcluded(path))
	{
		LogEvent(event);
	}

	// Deleted files need no handling: pending writes to them are still logged, and the scan
	// check skips files that no longer exist (or are pending deletion)
	switch (header->Type)
	{
	case PANO_EVENT_FILE_CREATED:
	case PANO_EVENT_FILE_OVERWRITTEN:
	case PANO_EVENT_FILE_SUPERSEDED:
		if (!dosPath.empty())
		{
			RequestFileScan(path);
		}
		break;
	}
}

static void HandleRenameEvent(const PANO_EVENT_HEADER *header, const PANO_RENAME_EVENT_DATA *data)
{
	if (data->ProcessId == GetCurrentProcessId())
	{
		return;
	}

	std::wstring ntSource(data->Names, data->SourceNameLength);
	std::wstring ntDestination(data->Names + data->SourceNameLength, data->DestinationNameLength);
	std::wstring dosSource = ToDosPath(ntSource);
	std::wstring dosDestination = ToDosPath(ntDestination);
	std::string source = ToString(dosSource.empty() ? ntSource : dosSource);
	std::string destination = ToString(dosDestination.empty() ? ntDestination : dosDestination);

	nlohmann::ordered_json event;
	event["Event"] = EventTypeName(header->Type);
	event["PID"] = data->ProcessId;
	event["TID"] = data->ThreadId;
	event["Path"] = source;
	event["NewPath"] = destination;
	event["Time"] = FormatSystemTime(ToFileTime(header->Timestamp));
	if (data->Flags & PANO_FLAG_REPLACE_EXISTING)
	{
		event["ReplaceExisting"] = true;
	}
	if (data->Flags & PANO_FLAG_NAME_TRUNCATED)
	{
		event["NameTruncated"] = true;
	}

	// A file moving into or out of an excluded folder is still worth seeing, so the rename is
	// only hidden when both names are excluded
	if (!(IsLogExcluded(source) && IsLogExcluded(destination)))
	{
		LogEvent(event);
	}

	if (dosDestination.empty())
	{
		return;
	}

	// Writes still pending under the old name follow the file, so it is logged and scanned
	// under its new name once it settles
	bool hasPendingWrites = false;
	{
		std::lock_guard<std::mutex> lock(g_WrittenFilesLock);
		auto pending = g_WrittenFiles.find(source);
		if (pending != g_WrittenFiles.end())
		{
			PANO_WRITTEN_FILE file = pending->second;
			g_WrittenFiles.erase(pending);
			file.IsDosPath = true;

			auto [it, inserted] = g_WrittenFiles.try_emplace(destination, file);
			if (!inserted)
			{
				PANO_WRITTEN_FILE &existing = it->second;
				if (file.FirstWriteTick < existing.FirstWriteTick)
				{
					existing.FirstWriteTick = file.FirstWriteTick;
					existing.FirstWriteTime = file.FirstWriteTime;
				}
				existing.LastWriteTick = std::max(existing.LastWriteTick, file.LastWriteTick);
				existing.Writes += file.Writes;
				existing.Bytes += file.Bytes;
			}
			hasPendingWrites = true;
		}
	}

	// A finished file given a new name (e.g. a download renamed from .tmp to .exe) is scanned now
	if (!hasPendingWrites)
	{
		RequestFileScan(destination);
	}
}

static void HandleProcessEvent(const PANO_EVENT_HEADER *header, const PANO_PROCESS_EVENT_DATA *data)
{
	nlohmann::ordered_json event;
	event["Event"] = EventTypeName(header->Type);
	event["PID"] = data->ProcessId;
	event["Time"] = FormatSystemTime(ToFileTime(header->Timestamp));

	if (header->Type == PANO_EVENT_PROCESS_CREATED)
	{
		std::wstring ntPath(data->Strings, data->ImageNameLength);
		std::wstring dosPath = ToDosPath(ntPath);
		std::wstring commandLine(data->Strings + data->ImageNameLength, data->CommandLineLength);

		event["ParentPID"] = data->ParentProcessId;
		event["CreatorPID"] = data->CreatingProcessId;
		event["CreatorTID"] = data->CreatingThreadId;
		event["Image"] = ToString(dosPath.empty() ? ntPath : dosPath);
		event["CommandLine"] = ToString(commandLine);
		if (data->Flags & PANO_FLAG_NAME_TRUNCATED)
		{
			event["NameTruncated"] = true;
		}
		if (data->Flags & PANO_FLAG_COMMAND_LINE_TRUNCATED)
		{
			event["CommandLineTruncated"] = true;
		}
	}

	LogEvent(event);
}

static void HandleEvent(const BYTE *buffer, DWORD bytes)
{
	if (bytes < sizeof(PANO_EVENT_HEADER))
	{
		return;
	}

	const PANO_EVENT_HEADER *header = (const PANO_EVENT_HEADER *)buffer;
	if (header->Size < sizeof(PANO_EVENT_HEADER) || header->Size > bytes)
	{
		return;
	}

	// The counts cover the gap before this event. NoService: no service was reading events
	// (this one was stopped, restarting, or not yet started); the driver does not buffer for
	// it. QueueFull: the service was connected but not keeping up, or the driver could not
	// allocate the event
	if (header->DroppedNoConsumer > 0)
	{
		nlohmann::ordered_json event;
		event["Event"] = "EventsDropped";
		event["Reason"] = "NoService";
		event["Count"] = header->DroppedNoConsumer;
		LogEvent(event);
	}
	if (header->Dropped > 0)
	{
		nlohmann::ordered_json event;
		event["Event"] = "EventsDropped";
		event["Reason"] = "QueueFull";
		event["Count"] = header->Dropped;
		LogEvent(event);
	}

	if (EventTypeName(header->Type) == nullptr)
	{
		return;
	}

	UINT32 payloadSize = header->Size - (UINT32)sizeof(PANO_EVENT_HEADER);
	const BYTE *payload = buffer + sizeof(PANO_EVENT_HEADER);

	if (header->Type == PANO_EVENT_FILE_RENAME)
	{
		if (payloadSize < FIELD_OFFSET(PANO_RENAME_EVENT_DATA, Names))
		{
			return;
		}

		const PANO_RENAME_EVENT_DATA *rename = (const PANO_RENAME_EVENT_DATA *)payload;
		UINT64 nameLength = (UINT64)rename->SourceNameLength + rename->DestinationNameLength;
		if (nameLength > (payloadSize - FIELD_OFFSET(PANO_RENAME_EVENT_DATA, Names)) / sizeof(WCHAR))
		{
			return;
		}

		HandleRenameEvent(header, rename);
		return;
	}

	if (header->Type == PANO_EVENT_PROCESS_CREATED || header->Type == PANO_EVENT_PROCESS_TERMINATED)
	{
		if (payloadSize < FIELD_OFFSET(PANO_PROCESS_EVENT_DATA, Strings))
		{
			return;
		}

		const PANO_PROCESS_EVENT_DATA *process = (const PANO_PROCESS_EVENT_DATA *)payload;
		UINT64 stringsLength = (UINT64)process->ImageNameLength + process->CommandLineLength;
		if (stringsLength > (payloadSize - FIELD_OFFSET(PANO_PROCESS_EVENT_DATA, Strings)) / sizeof(WCHAR))
		{
			return;
		}

		HandleProcessEvent(header, process);
		return;
	}

	if (header->Type == PANO_EVENT_FILE_MODIFIED)
	{
		if (payloadSize < FIELD_OFFSET(PANO_FILE_MODIFIED_EVENT_DATA, FileName))
		{
			return;
		}

		const PANO_FILE_MODIFIED_EVENT_DATA *modified = (const PANO_FILE_MODIFIED_EVENT_DATA *)payload;
		if (modified->NameLength > (payloadSize - FIELD_OFFSET(PANO_FILE_MODIFIED_EVENT_DATA, FileName)) / sizeof(WCHAR))
		{
			return;
		}

		HandleFileModifiedEvent(header, modified);
		return;
	}

	// Every other event type carries a PANO_FILE_EVENT_DATA
	if (payloadSize < FIELD_OFFSET(PANO_FILE_EVENT_DATA, FileName))
	{
		return;
	}

	const PANO_FILE_EVENT_DATA *data = (const PANO_FILE_EVENT_DATA *)payload;
	if (data->NameLength > (payloadSize - FIELD_OFFSET(PANO_FILE_EVENT_DATA, FileName)) / sizeof(WCHAR))
	{
		return;
	}

	HandleFileEvent(header, data);
}

#pragma endregion

#pragma region Threads

static bool IssueEventRequest(PPANO_EVENT_REQUEST request)
{
	ZeroMemory(&request->Overlapped, sizeof(OVERLAPPED));
	BOOL ok = DeviceIoControl(
		g_Device,
		IOCTL_PANOPTES_GET_EVENT,
		NULL,
		0,
		request->Buffer,
		sizeof(request->Buffer),
		NULL,
		&request->Overlapped);

	// The completion is delivered to the completion port in both cases
	return ok || GetLastError() == ERROR_IO_PENDING;
}

static void EventReaderThread()
{
	int outstanding = 0;
	for (auto &request : g_Requests)
	{
		if (IssueEventRequest(&request))
		{
			outstanding++;
		}
	}

	while (outstanding > 0)
	{
		DWORD bytes = 0;
		ULONG_PTR key = 0;
		LPOVERLAPPED overlapped = NULL;
		BOOL ok = GetQueuedCompletionStatus(g_CompletionPort, &bytes, &key, &overlapped, INFINITE);
		if (overlapped == NULL)
		{
			// The completion port itself failed
			break;
		}

		PPANO_EVENT_REQUEST request = CONTAINING_RECORD(overlapped, PANO_EVENT_REQUEST, Overlapped);
		outstanding--;

		if (ok)
		{
			HandleEvent(request->Buffer, bytes);
		}
		else
		{
			DWORD error = GetLastError();
			if (error != ERROR_OPERATION_ABORTED)
			{
				std::cerr << "Driver event request failed. Error code: " << error << std::endl;
			}
		}

		if (!g_Stopping && IssueEventRequest(request))
		{
			outstanding++;
		}
	}
}

// Scans the files the reader thread asked for. Logs a FileModified event for every file whose
// writes have settled (or that has been written for PANO_WRITE_MAX_WINDOW_MS), and scans the
// ones that settled and are PE files
static void WrittenFileScanThread()
{
	while (!g_Stopping)
	{
		std::this_thread::sleep_for(std::chrono::milliseconds(PANO_WRITE_POLL_MS));

		std::vector<std::string> requested;
		{
			std::lock_guard<std::mutex> lock(g_PendingScansLock);
			requested.swap(g_PendingScans);
		}
		// A file is often created and renamed within one poll; check each one once
		std::sort(requested.begin(), requested.end());
		requested.erase(std::unique(requested.begin(), requested.end()), requested.end());
		for (const auto &path : requested)
		{
			QueueFileScan(path);
		}

		std::vector<std::pair<std::string, PANO_WRITTEN_FILE>> ready;
		ULONGLONG now = GetTickCount64();
		{
			std::lock_guard<std::mutex> lock(g_WrittenFilesLock);
			for (auto it = g_WrittenFiles.begin(); it != g_WrittenFiles.end();)
			{
				const PANO_WRITTEN_FILE &file = it->second;
				if (now - file.LastWriteTick >= PANO_WRITE_SETTLE_MS ||
					now - file.FirstWriteTick >= PANO_WRITE_MAX_WINDOW_MS)
				{
					ready.emplace_back(it->first, file);
					it = g_WrittenFiles.erase(it);
				}
				else
				{
					++it;
				}
			}
		}

		for (const auto &[path, file] : ready)
		{
			nlohmann::ordered_json event;
			event["Event"] = "FileModified";
			event["PID"] = file.ProcessId;
			event["Path"] = path;
			event["Writes"] = file.Writes;
			event["Bytes"] = file.Bytes;
			event["Time"] = FormatSystemTime(file.FirstWriteTime);
			if (!IsLogExcluded(path))
			{
				LogEvent(event);
			}

			// A file still being written is not complete yet; it is scanned once it settles
			bool settled = now - file.LastWriteTick >= PANO_WRITE_SETTLE_MS;
			if (settled && file.IsDosPath)
			{
				QueueFileScan(path);
			}
		}
	}
}

#pragma endregion

ERRORCODE StartDriverEvents(const Configuration *configuration)
{
	BuildDeviceMap();
	g_LogExclusions = configuration->m_logExclusions;

	// The device only allows SYSTEM and Administrators to open it
	g_Device = CreateFileW(
		PANOPTES_USER_DEVICE_PATH,
		GENERIC_READ,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_FLAG_OVERLAPPED,
		NULL);
	if (g_Device == INVALID_HANDLE_VALUE)
	{
		DWORD error = GetLastError();
		std::cerr << "Failed to open the Panoptes driver device. Error code: " << error << std::endl;
		return (error == ERROR_ACCESS_DENIED) ? NOT_ADMIN : KERNEL_PIPE;
	}

	g_CompletionPort = CreateIoCompletionPort(g_Device, NULL, 0, 1);
	if (g_CompletionPort == NULL)
	{
		CloseHandle(g_Device);
		g_Device = INVALID_HANDLE_VALUE;
		return WINDOWS_ERR;
	}

	g_Stopping = false;
#ifdef _DEBUG
	g_EchoStopping = false;
	g_EchoThread = std::thread(ConsoleEchoThread);
#endif
	g_ReaderThread = std::thread(EventReaderThread);
	g_ScanThread = std::thread(WrittenFileScanThread);
	return PANO_SUCCESS;
}

void StopDriverEvents()
{
	if (g_Device == INVALID_HANDLE_VALUE)
	{
		return;
	}

	// Cancelling completes every pending request with ERROR_OPERATION_ABORTED, and the
	// reader exits once none are outstanding
	g_Stopping = true;
	CancelIoEx(g_Device, NULL);

	if (g_ReaderThread.joinable())
	{
		g_ReaderThread.join();
	}
	if (g_ScanThread.joinable())
	{
		g_ScanThread.join();
	}

	{
		std::lock_guard<std::mutex> lock(g_PendingScansLock);
		g_PendingScans.clear();
	}

#ifdef _DEBUG
	// The threads that log are stopped, so the echo thread prints what is left and exits
	{
		std::lock_guard<std::mutex> lock(g_EchoLock);
		g_EchoStopping = true;
	}
	g_EchoReady.notify_one();
	if (g_EchoThread.joinable())
	{
		g_EchoThread.join();
	}
#endif

	CloseHandle(g_CompletionPort);
	CloseHandle(g_Device);
	g_CompletionPort = NULL;
	g_Device = INVALID_HANDLE_VALUE;
}
