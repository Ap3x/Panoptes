#include "hook_events.h"
#include "error_message.h"
#include "pano_log.h"
#include "utils.h"
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include <nlohmann/json.hpp>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "tdh.lib")

// The real-time session the service owns. ETW sessions outlive the process that started them,
// so a session with this name left by a service that was killed is stopped and replaced
#define HOOK_SESSION_NAME L"Panoptes Hook Trace"

// The hook DLL's TraceLogging provider, "Panoptes.Hook". Must match the GUID in
// src/hook/src/hook_trace.cpp
// {D9AA2FDD-2853-4A97-A42F-E77E42921704}
static const GUID HookProviderGuid =
	{ 0xd9aa2fdd, 0x2853, 0x4a97, { 0xa4, 0x2f, 0xe7, 0x7e, 0x42, 0x92, 0x17, 0x04 } };

// Matches HOOK_KEYWORD_DETECTION in src/hook/include/hook_trace.hpp
#define HOOK_KEYWORD_DETECTION 0x1

// How often the session's loss counters are checked
#define HOOK_LOSS_CHECK_MS 5000

static TRACEHANDLE g_SessionHandle = 0;
static TRACEHANDLE g_ConsumerHandle = INVALID_PROCESSTRACE_HANDLE;
static std::thread g_ConsumerThread;

// Loss monitoring. ETW counts what the session lost rather than telling the consumer, so a
// thread reads the counters every HOOK_LOSS_CHECK_MS and logs any increase
static std::thread g_LossThread;
static std::mutex g_LossLock;
static std::condition_variable g_LossWake;
static bool g_LossStopping = false;
static ULONG g_ReportedEventsLost = 0;
static ULONG g_ReportedBuffersLost = 0;

static void LogHookEvent(const nlohmann::ordered_json &event)
{
	std::string line = event.dump();
	WriteToLogFile(line + "\n");
#ifdef _DEBUG
	std::cout << line << std::endl;
#endif
}

#pragma region Event Decoding

static std::string FormatHex(UINT64 value)
{
	char text[19];
	snprintf(text, sizeof(text), "0x%llx", value);
	return text;
}

// Reads an unsigned integer of 1, 2, 4 or 8 bytes
static UINT64 ReadUnsigned(const BYTE *data, ULONG size)
{
	switch (size)
	{
	case 1: return *(const UINT8 *)data;
	case 2: return *(const UINT16 *)data;
	case 4: return *(const UINT32 *)data;
	case 8: return *(const UINT64 *)data;
	default: return 0;
	}
}

static INT64 ReadSigned(const BYTE *data, ULONG size)
{
	switch (size)
	{
	case 1: return *(const INT8 *)data;
	case 2: return *(const INT16 *)data;
	case 4: return *(const INT32 *)data;
	case 8: return *(const INT64 *)data;
	default: return 0;
	}
}

// Converts one decoded property to JSON. Pointers and hex-formatted integers become "0x..."
// strings. Pointer properties are 4 or 8 bytes depending on whether the hook DLL that wrote
// the event was x86 or x64; TDH reports the size actually written
static nlohmann::ordered_json PropertyToJson(const EVENT_PROPERTY_INFO &property, const BYTE *data, ULONG size)
{
	USHORT inType = property.nonStructType.InType;
	USHORT outType = property.nonStructType.OutType;

	switch (inType)
	{
	case TDH_INTYPE_UNICODESTRING:
	{
		std::wstring text((const wchar_t *)data, size / sizeof(wchar_t));
		text.erase(text.find_last_not_of(L'\0') + 1);
		return ToString(text);
	}
	case TDH_INTYPE_ANSISTRING:
	{
		std::string text((const char *)data, size);
		text.erase(text.find_last_not_of('\0') + 1);
		return text;
	}
	case TDH_INTYPE_BOOLEAN:
		return ReadUnsigned(data, size) != 0;
	case TDH_INTYPE_POINTER:
	case TDH_INTYPE_SIZET:
	case TDH_INTYPE_HEXINT32:
	case TDH_INTYPE_HEXINT64:
		return FormatHex(ReadUnsigned(data, size));
	case TDH_INTYPE_INT8:
	case TDH_INTYPE_INT16:
	case TDH_INTYPE_INT32:
	case TDH_INTYPE_INT64:
		return ReadSigned(data, size);
	case TDH_INTYPE_UINT8:
	case TDH_INTYPE_UINT16:
	case TDH_INTYPE_UINT32:
	case TDH_INTYPE_UINT64:
		if (outType == TDH_OUTTYPE_HEXINT8 || outType == TDH_OUTTYPE_HEXINT16 ||
			outType == TDH_OUTTYPE_HEXINT32 || outType == TDH_OUTTYPE_HEXINT64)
		{
			return FormatHex(ReadUnsigned(data, size));
		}
		return ReadUnsigned(data, size);
	default:
	{
		// A type the hook DLL does not write today: keep the raw bytes
		std::string hex;
		char byte[3];
		for (ULONG i = 0; i < size; i++)
		{
			snprintf(byte, sizeof(byte), "%02x", data[i]);
			hex += byte;
		}
		return hex;
	}
	}
}

// The full image path of a running process, or an empty string if it has exited or cannot be
// opened
static std::string ProcessImage(DWORD processId)
{
	HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
	if (process == NULL)
	{
		return "";
	}

	wchar_t path[MAX_PATH * 2];
	DWORD length = ARRAYSIZE(path);
	std::string image;
	if (QueryFullProcessImageNameW(process, 0, path, &length))
	{
		image = ToString(std::wstring(path, length));
	}
	CloseHandle(process);
	return image;
}

static FILETIME ToFileTime(const LARGE_INTEGER &timestamp)
{
	FILETIME fileTime;
	fileTime.dwLowDateTime = timestamp.LowPart;
	fileTime.dwHighDateTime = (DWORD)timestamp.HighPart;
	return fileTime;
}

// Logs one hook event as a JSON line, in the same log as the driver's events. PID and TID come
// from the event header, which the kernel fills in, so they identify the process the hook ran
// in even though the payload is written by code inside that (untrusted) process
static void WINAPI OnHookEvent(PEVENT_RECORD record)
{
	if (!IsEqualGUID(record->EventHeader.ProviderId, HookProviderGuid))
	{
		return;
	}

	ULONG infoSize = 0;
	if (TdhGetEventInformation(record, 0, NULL, NULL, &infoSize) != ERROR_INSUFFICIENT_BUFFER)
	{
		return;
	}
	std::vector<BYTE> infoBuffer(infoSize);
	PTRACE_EVENT_INFO info = (PTRACE_EVENT_INFO)infoBuffer.data();
	if (TdhGetEventInformation(record, 0, NULL, info, &infoSize) != ERROR_SUCCESS)
	{
		return;
	}

	// For TraceLogging events TaskNameOffset holds the event name
	ULONG nameOffset = info->EventNameOffset != 0 ? info->EventNameOffset : info->TaskNameOffset;
	std::string eventName = nameOffset != 0
		? ToString((PCWSTR)(infoBuffer.data() + nameOffset))
		: "HookEvent";

	DWORD processId = record->EventHeader.ProcessId;

	nlohmann::ordered_json event;
	event["Event"] = eventName;
	event["Source"] = "Hook";
	event["PID"] = processId;
	event["TID"] = record->EventHeader.ThreadId;
	event["Image"] = ProcessImage(processId);
	event["Time"] = FormatSystemTime(ToFileTime(record->EventHeader.TimeStamp));

	for (ULONG i = 0; i < info->TopLevelPropertyCount; i++)
	{
		const EVENT_PROPERTY_INFO &property = info->EventPropertyInfoArray[i];
		PCWSTR propertyName = (PCWSTR)(infoBuffer.data() + property.NameOffset);

		// The hook events only have scalar fields; structs and arrays are not decoded
		if ((property.Flags & (PropertyStruct | PropertyParamCount)) || property.count > 1)
		{
			continue;
		}

		PROPERTY_DATA_DESCRIPTOR descriptor{};
		descriptor.PropertyName = (ULONGLONG)propertyName;
		descriptor.ArrayIndex = ULONG_MAX;

		ULONG size = 0;
		if (TdhGetPropertySize(record, 0, NULL, 1, &descriptor, &size) != ERROR_SUCCESS || size == 0)
		{
			continue;
		}
		std::vector<BYTE> data(size);
		if (TdhGetProperty(record, 0, NULL, 1, &descriptor, size, data.data()) != ERROR_SUCCESS)
		{
			continue;
		}

		event[ToString(propertyName)] = PropertyToJson(property, data.data(), size);
	}

	// Name the process acted on when it is not the one the hook ran in
	if (event.value("Remote", false) && event.contains("TargetProcessId") && event["TargetProcessId"].is_number())
	{
		event["TargetImage"] = ProcessImage(event["TargetProcessId"].get<DWORD>());
	}

	LogHookEvent(event);
}

#pragma endregion

#pragma region Session

// EVENT_TRACE_PROPERTIES followed by room for the session name, which StartTrace and
// ControlTrace copy in after the structure
struct HookSessionProperties
{
	EVENT_TRACE_PROPERTIES Properties;
	wchar_t SessionName[ARRAYSIZE(HOOK_SESSION_NAME)];

	HookSessionProperties()
	{
		ZeroMemory(this, sizeof(*this));
		Properties.Wnode.BufferSize = sizeof(*this);
		Properties.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
		Properties.Wnode.ClientContext = 1; // QPC timestamps, converted to FILETIME for consumers
		Properties.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
		Properties.BufferSize = 64; // KB
		Properties.FlushTimer = 1;  // deliver buffered events at least once a second
		Properties.LoggerNameOffset = offsetof(HookSessionProperties, SessionName);
	}
};

// Logs what the session has lost since the last report, from counters filled in by a query or
// stop. The two counters mean different things:
//  - EventsLost: events a hooked process wrote while every session buffer was full. Reported
//    as Reason "QueueFull" with the number of events
//  - RealTimeBuffersLost: full buffers ETW discarded because the service did not take them in
//    time. How many events each held is not known, so it is reported as Reason "BuffersLost"
//    with the number of buffers
static void ReportLoss(const EVENT_TRACE_PROPERTIES &properties)
{
	if (properties.EventsLost > g_ReportedEventsLost)
	{
		nlohmann::ordered_json event;
		event["Event"] = "EventsDropped";
		event["Source"] = "Hook";
		event["Reason"] = "QueueFull";
		event["Count"] = properties.EventsLost - g_ReportedEventsLost;
		LogHookEvent(event);
		g_ReportedEventsLost = properties.EventsLost;
	}
	if (properties.RealTimeBuffersLost > g_ReportedBuffersLost)
	{
		nlohmann::ordered_json event;
		event["Event"] = "EventsDropped";
		event["Source"] = "Hook";
		event["Reason"] = "BuffersLost";
		event["Buffers"] = properties.RealTimeBuffersLost - g_ReportedBuffersLost;
		LogHookEvent(event);
		g_ReportedBuffersLost = properties.RealTimeBuffersLost;
	}
}

static void LossMonitorThread()
{
	std::unique_lock<std::mutex> lock(g_LossLock);
	while (!g_LossWake.wait_for(lock, std::chrono::milliseconds(HOOK_LOSS_CHECK_MS), [] { return g_LossStopping; }))
	{
		HookSessionProperties properties;
		if (ControlTraceW(g_SessionHandle, NULL, &properties.Properties, EVENT_TRACE_CONTROL_QUERY) == ERROR_SUCCESS)
		{
			ReportLoss(properties.Properties);
		}
	}
}

static void ConsumerThread()
{
	ULONG status = ProcessTrace(&g_ConsumerHandle, 1, NULL, NULL);
	if (status != ERROR_SUCCESS && status != ERROR_CANCELLED)
	{
		std::cerr << "Hook event trace stopped. Error code: " << status << std::endl;
	}
}

ERRORCODE StartHookEvents()
{
	HookSessionProperties properties;
	ULONG status = StartTraceW(&g_SessionHandle, HOOK_SESSION_NAME, &properties.Properties);
	if (status == ERROR_ALREADY_EXISTS)
	{
		// Left behind by a previous run of the service
		HookSessionProperties stale;
		ControlTraceW(0, HOOK_SESSION_NAME, &stale.Properties, EVENT_TRACE_CONTROL_STOP);

		properties = HookSessionProperties();
		status = StartTraceW(&g_SessionHandle, HOOK_SESSION_NAME, &properties.Properties);
	}
	if (status != ERROR_SUCCESS)
	{
		std::cerr << "Failed to start the hook event trace session. Error code: " << status << std::endl;
		g_SessionHandle = 0;
		return (status == ERROR_ACCESS_DENIED) ? NOT_ADMIN : WINDOWS_ERR;
	}

	status = EnableTraceEx2(g_SessionHandle, &HookProviderGuid, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
		TRACE_LEVEL_WARNING, HOOK_KEYWORD_DETECTION, 0, 0, NULL);
	if (status != ERROR_SUCCESS)
	{
		std::cerr << "Failed to enable the hook event provider. Error code: " << status << std::endl;
		StopHookEvents();
		return WINDOWS_ERR;
	}

	EVENT_TRACE_LOGFILEW logFile{};
	logFile.LoggerName = (LPWSTR)HOOK_SESSION_NAME;
	logFile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
	logFile.EventRecordCallback = OnHookEvent;

	g_ConsumerHandle = OpenTraceW(&logFile);
	if (g_ConsumerHandle == INVALID_PROCESSTRACE_HANDLE)
	{
		std::cerr << "Failed to open the hook event trace. Error code: " << GetLastError() << std::endl;
		StopHookEvents();
		return WINDOWS_ERR;
	}

	g_ConsumerThread = std::thread(ConsumerThread);

	g_ReportedEventsLost = 0;
	g_ReportedBuffersLost = 0;
	g_LossStopping = false;
	g_LossThread = std::thread(LossMonitorThread);
	return PANO_SUCCESS;
}

void StopHookEvents()
{
	// The monitor goes first so it never queries a session that has been stopped
	if (g_LossThread.joinable())
	{
		{
			std::lock_guard<std::mutex> lock(g_LossLock);
			g_LossStopping = true;
		}
		g_LossWake.notify_all();
		g_LossThread.join();
	}

	// Stopping the session flushes its buffers to the consumer, after which ProcessTrace
	// returns. The stop also returns the session's final counters, so losses since the last
	// check are still reported
	if (g_SessionHandle != 0)
	{
		HookSessionProperties properties;
		if (ControlTraceW(g_SessionHandle, NULL, &properties.Properties, EVENT_TRACE_CONTROL_STOP) == ERROR_SUCCESS)
		{
			ReportLoss(properties.Properties);
		}
		g_SessionHandle = 0;
	}

	if (g_ConsumerThread.joinable())
	{
		g_ConsumerThread.join();
	}

	if (g_ConsumerHandle != INVALID_PROCESSTRACE_HANDLE)
	{
		CloseTrace(g_ConsumerHandle);
		g_ConsumerHandle = INVALID_PROCESSTRACE_HANDLE;
	}
}

#pragma endregion
