#include <Windows.h>
#include <evntrace.h>
#include <stdio.h>
#include <evntcons.h>
#include <string>
#include <tdh.h>
#include <assert.h>
#include <memory>
#include <in6addr.h>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <nlohmann/json.hpp>
#include "pano_log.h"
#include "utils.h"
#include "service_constants.h"
#include "grpc.hpp"
#include "panoptes_service.h"


TRACEHANDLE hTrace = 0;
ULONG result, bufferSize;
EVENT_TRACE_LOGFILEW trace;
EVENT_TRACE_PROPERTIES* traceProp = nullptr;

std::string FormatSystemTime(const FILETIME& ft) {
	SYSTEMTIME st;
	FileTimeToSystemTime(&ft, &st);
	
	std::ostringstream ss;
	ss << std::setfill('0') 
	   << st.wYear << '/' 
	   << std::setw(2) << st.wMonth << '/' 
	   << std::setw(2) << st.wDay << ' '
	   << std::setw(2) << st.wHour << ':' 
	   << std::setw(2) << st.wMinute << ':' 
	   << std::setw(2) << st.wSecond;
	return ss.str();
}

std::optional<GUID> GetProviderGuid(const std::string& providerNameToFind) {
	ULONG bufferSize = 0;
	PROVIDER_ENUMERATION_INFO* providerInfo = nullptr;
	std::optional<GUID> result;

	// Get the required buffer size
	ULONG status = TdhEnumerateProviders(nullptr, &bufferSize);
	if (status == ERROR_INSUFFICIENT_BUFFER) {
		providerInfo = (PROVIDER_ENUMERATION_INFO*)malloc(bufferSize);
		if (providerInfo == nullptr) {
			throw std::runtime_error("Failed to allocate memory");
		}

		// Enumerate providers
		status = TdhEnumerateProviders(providerInfo, &bufferSize);
		if (status == ERROR_SUCCESS) {
			for (ULONG i = 0; i < providerInfo->NumberOfProviders; i++) {
				TRACE_PROVIDER_INFO& provider = providerInfo->TraceProviderInfoArray[i];
				wchar_t* providerName = (wchar_t*)((BYTE*)providerInfo + provider.ProviderNameOffset);

				std::wstring wProviderName(providerName);
				std::string providerNameStr(wProviderName.begin(), wProviderName.end());

				if (providerNameStr == providerNameToFind) {
					result = provider.ProviderGuid;
					break;
				}
			}
		}
		else {
			throw std::runtime_error("TdhEnumerateProviders failed with error: " + std::to_string(status));
		}

		free(providerInfo);
	}
	else {
		throw std::runtime_error("TdhEnumerateProviders failed with error: " + std::to_string(status));
	}

	return result;
}

std::vector<GUID> GetProvidersGUID(std::vector<std::string> providers) {
	std::vector<GUID> guids;
	for (const auto& providerName : providers) {
		auto guid = GetProviderGuid(providerName);
		if (guid.has_value()) {
			guids.push_back(guid.value());
		}
		else {
			printf("Provider %s not found\n", providerName.c_str());
		}
	}
	return guids;
}

/// <summary>
/// https://github.com/zodiacon/Win10SysProgBookSamples/blob/9f2d1bb61a24fee4e08ec46738680e44f6c132de/Chapter20/ParseETW/ParseETW.cpp#L131
/// </summary>
/// <param name="rec"></param>
/// <param name="info"></param>
void DisplayEventInfo(PEVENT_RECORD rec, PTRACE_EVENT_INFO info) {

	//GUID providerId = { 0x7036af95, 0x9daf, 0x4486, 0x8d, 0x93, 0x70, 0x5, 0xd4, 0x5a, 0x6a, 0x6 };
	//if (rec->EventHeader.ProviderId != providerId)
	//	return;

	nlohmann::json jsonObject;
	if (info->KeywordsNameOffset)
		printf("Keywords: %ws ", (PCWSTR)((BYTE*)info + info->KeywordsNameOffset));
	if (info->OpcodeNameOffset)
		printf("Opcode: %ws ", (PCWSTR)((BYTE*)info + info->OpcodeNameOffset));
	if (info->LevelNameOffset)
		printf("Level: %ws ", (PCWSTR)((BYTE*)info + info->LevelNameOffset));
	if (info->TaskNameOffset) {
		printf("Task: %ws ", (PCWSTR)((BYTE*)info + info->TaskNameOffset));
		std::wstring taskName = (PCWSTR)((BYTE*)info + info->TaskNameOffset);
		jsonObject["Event"] = ToString(taskName);
	}
	if (info->EventMessageOffset)
		printf("\nMessage: %ws", (PCWSTR)((BYTE*)info + info->EventMessageOffset));

	printf("\nProperties: %u\n", info->TopLevelPropertyCount);

	// properties data length and pointer
	auto userlen = rec->UserDataLength;
	auto data = (PBYTE)rec->UserData;

	auto pointerSize = (rec->EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER) ? 4 : 8;
	ULONG len;
	WCHAR value[512];

	for (DWORD i = 0; i < info->TopLevelPropertyCount; i++) {
		auto& pi = info->EventPropertyInfoArray[i];
		auto propName = (PCWSTR)((BYTE*)info + pi.NameOffset);
		printf(" Name: %ws ", propName);
		std::string propNameStr = ToString(propName);

		len = pi.length;
		if ((pi.Flags & (PropertyStruct | PropertyParamCount)) == 0) {
			//
			// deal with simple properties only
			//
			PEVENT_MAP_INFO mapInfo = nullptr;
			std::unique_ptr<BYTE[]> mapBuffer;
			PWSTR mapName = nullptr;
			//
			// retrieve map information (if any)
			//
			if (pi.nonStructType.MapNameOffset) {
				ULONG size = 0;
				mapName = (PWSTR)((BYTE*)info + pi.nonStructType.MapNameOffset);
				if (ERROR_INSUFFICIENT_BUFFER == ::TdhGetEventMapInformation(rec, mapName, mapInfo, &size)) {
					mapBuffer = std::make_unique<BYTE[]>(size);
					mapInfo = reinterpret_cast<PEVENT_MAP_INFO>(mapBuffer.get());
					if (ERROR_SUCCESS != ::TdhGetEventMapInformation(rec, mapName, mapInfo, &size))
						mapInfo = nullptr;
				}
			}

			ULONG size = sizeof(value);
			USHORT consumed;
			// special case for IPv6 address
			if (pi.nonStructType.InType == TDH_INTYPE_BINARY && pi.nonStructType.OutType == TDH_OUTTYPE_IPV6)
				len = sizeof(IN6_ADDR);

			auto error = ::TdhFormatProperty(info, mapInfo, pointerSize,
				pi.nonStructType.InType, pi.nonStructType.OutType,
				(USHORT)len, userlen, data, &size, value, &consumed);
			if (ERROR_SUCCESS == error) {
				printf("Value: %ws", value);
				jsonObject[propNameStr] = ToString(value);
				len = consumed;
				if (mapName)
					printf(" (%ws)", (PCWSTR)mapName);
				printf("\n");
			}
			else if (mapInfo) {
				error = ::TdhFormatProperty(info, nullptr, pointerSize,
					pi.nonStructType.InType, pi.nonStructType.OutType,
					(USHORT)len, userlen, data, &size, value, &consumed);
				if (ERROR_SUCCESS == error) {
					printf("Value: %ws\n", value);
					jsonObject[propNameStr] = ToString(value);
				}
			}
			if (ERROR_SUCCESS != error)
				printf("(failed to get value)\n");
		}
		else {
			printf("(not a simple property)\n");
		}
		userlen -= (USHORT)len;
		data += len;
	}
	auto& header = rec->EventHeader;
	jsonObject["TID"] = header.ThreadId;
	jsonObject["PID"] = header.ProcessId;
	if (header.ProcessId == GetCurrentProcessId()) {
		return;
	}
	std::string timeLog = FormatSystemTime(*(FILETIME*)&header.TimeStamp);
	jsonObject["Time"] = timeLog;

	try {
		std::string eventName = jsonObject["Event"].get<std::string>();
		if (!eventName.empty()) {
			if (eventName == "FileCreated" || eventName == "FileModified") {
				std::string fileName = jsonObject["FileName"].get<std::string>();
				SelfQueuePeScan(fileName, "");
			}
			else if (eventName == "KERNEL_NETWORK_TASK_TCPIP" || eventName == "KERNEL_NETWORK_TASK_UDPIP"){
				auto destAddr = jsonObject["daddr"].get<std::string>();
				auto srcAddr = jsonObject["saddr"].get<std::string>();
				if (srcAddr == "127.0.0.1" || destAddr == "127.0.0.1") {
					return;
				}
				if (srcAddr == "::1" || destAddr == "::1") {
					return;
				}
			}
		}

	}
	catch (...){
		WriteToLogFile(jsonObject.dump() + "\n");
		return;
	}

	WriteToLogFile(jsonObject.dump() + "\n");
}

//void DisplayGeneralEventInfo(PEVENT_RECORD rec) {
//	WCHAR sguid[64];
//	auto& header = rec->EventHeader;
//	::StringFromGUID2(header.ProviderId, sguid, _countof(sguid));
//
//	printf("Provider: %ws Time: %ws PID: %u TID: %u\n",
//		sguid, (PCWSTR)CTime(*(FILETIME*)&header.TimeStamp).Format(L"%c"),
//		header.ProcessId, header.ThreadId);
//}

VOID WINAPI EventRecordCallback(EVENT_RECORD* pEventRecord) {
	//DisplayGeneralEventInfo(pEventRecord);

	ULONG size = 0;
	auto status = ::TdhGetEventInformation(pEventRecord, 0, nullptr, nullptr, &size);
	assert(status == ERROR_INSUFFICIENT_BUFFER);

	auto buffer = std::make_unique<BYTE[]>(size);
	if (!buffer) {
		printf("Out of memory!\n");
		::ExitProcess(1);
	}

	auto info = reinterpret_cast<PTRACE_EVENT_INFO>(buffer.get());
	status = ::TdhGetEventInformation(pEventRecord, 0, nullptr, info, &size);
	if (status != ERROR_SUCCESS) {
		printf("Error processing event!\n");
		return;
	}

	DisplayEventInfo(pEventRecord, info);
}

ULONG WINAPI BufferCallback(EVENT_TRACE_LOGFILE* pLogFile) {
	return TRUE;
}

ULONG StopAndDeleteTrace()
{
	std::wstring sessionName = TRACE_NAMEW;
	EVENT_TRACE_PROPERTIES* pProperties = NULL;
	ULONG bufferSize = 0;
	ULONG status = ERROR_SUCCESS;

	// Calculate the buffer size
	bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + (wcslen(sessionName.c_str()) + 1) * sizeof(WCHAR);
	pProperties = (EVENT_TRACE_PROPERTIES*)malloc(bufferSize);
	if (pProperties == NULL)
	{
		return ERROR_OUTOFMEMORY;
	}

	ZeroMemory(pProperties, bufferSize);
	pProperties->Wnode.BufferSize = bufferSize;
	pProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
	pProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

	// Stop and delete the trace session
	status = ControlTraceW(NULL, sessionName.c_str(), pProperties, EVENT_TRACE_CONTROL_STOP);

	free(pProperties);
	return status;
}

VOID StopPanoptesTrace() {
	std::wstring Name = TRACE_NAMEW;
	ControlTraceW(NULL, Name.c_str(), traceProp, EVENT_TRACE_CONTROL_STOP);
	if (hTrace != NULL) {
		CloseTrace(hTrace);  // Ensure hTrace is closed
	}
}

ULONG StartPanoptesTrace(LPVOID lpParam) {
	StopAndDeleteTrace();
	PanoptesContext& serviceContext = *(PanoptesContext*)lpParam;
	auto providers = serviceContext.config->m_eventProviders;

	// Initialize properties for the single trace session
	ULONG bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + (MAX_PATH * sizeof(WCHAR));
	EVENT_TRACE_PROPERTIES* pProperties = (EVENT_TRACE_PROPERTIES*)malloc(bufferSize);
	ZeroMemory(pProperties, bufferSize);

	pProperties->Wnode.BufferSize = bufferSize;
	pProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
	pProperties->Wnode.ClientContext = 1; // QPC clock resolution
	pProperties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
	pProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
	pProperties->LogFileNameOffset = 0;

	// Start the trace session
	TRACEHANDLE hTrace;
	WCHAR sessionName[] = L"Panoptes";
	ULONG result = StartTraceW(&hTrace, sessionName, pProperties);
	if (result != ERROR_SUCCESS)
	{
		// Handle error
		free(pProperties);
		return 1;
	}

	// Enable multiple providers
	for (const auto& provider : providers)
	{
		auto [provName, provMatchAny, provMatchAll] = provider;

		GUID provGUID = GetProviderGuid(provName).value_or(GUID{});
		if (provGUID == GUID{}) {
			printf("[!] Could not retrieve GUID for %s\n", provName);
			continue;
		}

		result = EnableTraceEx2(
			hTrace,
			&provGUID,
			EVENT_CONTROL_CODE_ENABLE_PROVIDER,
			TRACE_LEVEL_INFORMATION,
			provMatchAny,
			provMatchAll,
			0,
			NULL
		);
		if (result != ERROR_SUCCESS)
		{
			// Handle error
			printf("[!] Could not enable trace for %s\n", provName);
			continue;
		}
	}

	// Set up the trace session
	EVENT_TRACE_LOGFILEW trace;
	ZeroMemory(&trace, sizeof(EVENT_TRACE_LOGFILE));
	trace.LoggerName = (LPWSTR)sessionName;
	trace.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
	trace.EventRecordCallback = EventRecordCallback;

	// Start processing events
	TRACEHANDLE hProcessTrace = OpenTraceW(&trace);
	if (hProcessTrace == INVALID_PROCESSTRACE_HANDLE)
	{
		// Handle error
		ControlTraceW(hTrace, NULL, pProperties, EVENT_TRACE_CONTROL_STOP);
		free(pProperties);
		return 1;
	}

	ProcessTrace(&hProcessTrace, 1, NULL, NULL);

	// Clean up
	CloseTrace(hProcessTrace);
	ControlTraceW(hTrace, NULL, pProperties, EVENT_TRACE_CONTROL_STOP);
	free(pProperties);

	return 1;

}




