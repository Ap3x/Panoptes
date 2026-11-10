#include "driver.h"
#include "error_message.h"
#include "pano_events.h"
#include <iostream>

ERRORCODE GetKernelServiceStatus()
{
	SC_HANDLE serviceControlManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
	if (serviceControlManager == NULL) {
		return NOT_SET;
	}

	// Open the service
	SC_HANDLE service = OpenServiceA(serviceControlManager, KERNEL_DRIVER_SERVICE_NAME, SERVICE_QUERY_STATUS);
	if (service == NULL) {
		CloseServiceHandle(serviceControlManager);
		return NOT_INSTALLED;
	}

	SERVICE_STATUS serviceStatus;
	ERRORCODE serviceStatusReturn = PANO_SERVICE_STOPPED;
	if (!QueryServiceStatus(service, &serviceStatus)) {
		serviceStatusReturn = CONTROL_SERVICE;
	}
	else if (serviceStatus.dwCurrentState == SERVICE_RUNNING)
	{
		serviceStatusReturn = PANO_SERVICE_RUNNING;
	}

	CloseServiceHandle(service);
	CloseServiceHandle(serviceControlManager);

	return serviceStatusReturn;
}

ERRORCODE TerminateProcessByDriver(UINT64 processId)
{
	// A separate synchronous handle, since the event reader's handle is overlapped
	HANDLE device = CreateFileW(PANOPTES_USER_DEVICE_PATH, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if (device == INVALID_HANDLE_VALUE) {
		return (GetLastError() == ERROR_ACCESS_DENIED) ? NOT_ADMIN : KERNEL_PIPE;
	}

	PANO_TERMINATE_PROCESS request;
	request.ProcessId = processId;
	DWORD bytesReturned = 0;
	BOOL ok = DeviceIoControl(device, IOCTL_PANOPTES_TERMINATE_PROCESS, &request, sizeof(request), NULL, 0, &bytesReturned, NULL);
	CloseHandle(device);

	return ok ? PANO_SUCCESS : IOCTL_FAILED;
}


ERRORCODE SetInjectionExclusionsInDriver(const std::vector<std::string>& imageNames)
{
	if (imageNames.size() > PANO_MAX_INJECTION_EXCLUSIONS) {
		std::cerr << "DontInject has " << imageNames.size() << " entries; the driver accepts at most "
			<< PANO_MAX_INJECTION_EXCLUSIONS << std::endl;
		return INVALID_INPUT;
	}

	// A PANO_INJECTION_EXCLUSIONS: the count, then each name null-terminated, back to back
	std::vector<WCHAR> names;
	for (const auto& name : imageNames) {
		int length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, name.c_str(), (int)name.size(), NULL, 0);
		if (length <= 0) {
			std::cerr << "Invalid DontInject entry: \"" << name << "\"" << std::endl;
			return INVALID_INPUT;
		}
		std::wstring wideName(length, L'\0');
		MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, name.c_str(), (int)name.size(), wideName.data(), length);

		std::wstring entry;
		if (wideName.find(L'\\') == std::wstring::npos) {
			entry = wideName; // A file name, matched in any folder
		}
		else {
			// A full path such as C:\Tools\app.exe (Configuration checked the form). The driver
			// sees NT paths, so swap the drive letter for its device: \Device\HarddiskVolume3\Tools\app.exe
			WCHAR drive[3] = { wideName[0], L':', L'\0' };
			WCHAR device[MAX_PATH];
			if (QueryDosDeviceW(drive, device, MAX_PATH) == 0) {
				std::cerr << "DontInject entry \"" << name << "\" is on drive " << (char)wideName[0]
					<< ": which does not exist. Error code: " << GetLastError() << std::endl;
				return INVALID_INPUT;
			}
			entry = std::wstring(device) + wideName.substr(2);
		}

		if (entry.size() > PANO_MAX_INJECTION_EXCLUSION_LENGTH) {
			std::cerr << "DontInject entry is too long: \"" << name << "\"" << std::endl;
			return INVALID_INPUT;
		}
		names.insert(names.end(), entry.begin(), entry.end());
		names.push_back(L'\0');
	}

	const size_t headerSize = FIELD_OFFSET(PANO_INJECTION_EXCLUSIONS, Names);
	std::vector<BYTE> request(headerSize + names.size() * sizeof(WCHAR));
	UINT32 count = (UINT32)imageNames.size();
	memcpy(request.data(), &count, sizeof(count));
	if (!names.empty()) {
		memcpy(request.data() + headerSize, names.data(), names.size() * sizeof(WCHAR));
	}

	// The IOCTL requires write access to the device
	HANDLE device = CreateFileW(PANOPTES_USER_DEVICE_PATH, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if (device == INVALID_HANDLE_VALUE) {
		return (GetLastError() == ERROR_ACCESS_DENIED) ? NOT_ADMIN : KERNEL_PIPE;
	}

	DWORD bytesReturned = 0;
	BOOL ok = DeviceIoControl(device, IOCTL_PANOPTES_SET_INJECTION_EXCLUSIONS, request.data(), (DWORD)request.size(), NULL, 0, &bytesReturned, NULL);
	DWORD error = GetLastError();
	CloseHandle(device);

	if (!ok) {
		std::cerr << "The driver rejected the DontInject list. Error code: " << error << std::endl;
		return IOCTL_FAILED;
	}
	return PANO_SUCCESS;
}

ERRORCODE SetFileEventsInDriver(const std::vector<std::string>& groups)
{
	// Must cover every name in Configuration::FileEventNames()
	static const std::pair<const char*, UINT32> groupBits[] = {
		{ "Create", PANO_FILE_EVENTS_CREATE },
		{ "Write", PANO_FILE_EVENTS_WRITE },
		{ "DeleteRename", PANO_FILE_EVENTS_DELETE_RENAME },
		{ "PipeMailslot", PANO_FILE_EVENTS_PIPE_MAILSLOT },
		{ "Security", PANO_FILE_EVENTS_SECURITY },
		{ "ExtendedAttributes", PANO_FILE_EVENTS_EA },
	};

	PANO_FILE_EVENTS request{};
	for (const auto& group : groups) {
		bool found = false;
		for (const auto& [name, bit] : groupBits) {
			if (group == name) {
				request.Enabled |= bit;
				found = true;
				break;
			}
		}
		if (!found) {
			std::cerr << "Unknown FileEvents entry: \"" << group << "\"" << std::endl;
			return INVALID_INPUT;
		}
	}

	// The IOCTL requires write access to the device
	HANDLE device = CreateFileW(PANOPTES_USER_DEVICE_PATH, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if (device == INVALID_HANDLE_VALUE) {
		return (GetLastError() == ERROR_ACCESS_DENIED) ? NOT_ADMIN : KERNEL_PIPE;
	}

	DWORD bytesReturned = 0;
	BOOL ok = DeviceIoControl(device, IOCTL_PANOPTES_SET_FILE_EVENTS, &request, sizeof(request), NULL, 0, &bytesReturned, NULL);
	DWORD error = GetLastError();
	CloseHandle(device);

	if (!ok) {
		std::cerr << "The driver rejected the FileEvents setting. Error code: " << error << std::endl;
		return IOCTL_FAILED;
	}
	return PANO_SUCCESS;
}
