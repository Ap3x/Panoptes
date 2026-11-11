#include "containers.h"
#include "error_message.h"
#include "utils.h"
#include "Configuration.hpp"
#include <iostream>

std::string BuildContainerCommandLine(Configuration::ContainerType ext)
{
	std::string localPath = GetExecutableDirectory();
	std::string extPath = localPath + "\\ext\\";
	std::string result = "\"" + localPath + "\\PanoptesContainer.exe" + "\" \"";

	switch (ext) {
	case CONTAINER_TYPE_YARA:
		result.append(extPath + EXT_YARA);
		break;
	default:
		break;
	}
	result.append("\"");

	return result;
}

// Every container runs in this job. The job kills its processes when its last handle closes,
// so containers end with the service even if the service is killed rather than shut down
static HANDLE g_ContainerJob = NULL;

static bool CreateContainerJob() {
	if (g_ContainerJob != NULL) {
		return true; // StartContainers and StartDetector share it
	}
	g_ContainerJob = CreateJobObjectW(NULL, NULL);
	if (g_ContainerJob == NULL) {
		return false;
	}

	JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
	limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
	if (!SetInformationJobObject(g_ContainerJob, JobObjectExtendedLimitInformation, &limits, sizeof(limits))) {
		CloseHandle(g_ContainerJob);
		g_ContainerJob = NULL;
		return false;
	}
	return true;
}

ERRORCODE StartContainers() {
	// Every extensibility is always loaded
	const Configuration::ContainerType extensibility[] = {
		Configuration::CONTAINER_TYPE_YARA,
	};

	if (!CreateContainerJob()) {
		return CONTAINER_START;
	}

	STARTUPINFOA startupInfo;
	PROCESS_INFORMATION processInformation;

	ZeroMemory(&startupInfo, sizeof(startupInfo));
	startupInfo.cb = sizeof(startupInfo);
	ZeroMemory(&processInformation, sizeof(processInformation));

	for (auto containerType : extensibility) {
		std::string cmdStr = BuildContainerCommandLine(containerType);
		// Started suspended so the container is in the job before it runs any code
#ifdef _DEBUG
		DWORD creationFlags = CREATE_SUSPENDED;
#else
		DWORD creationFlags = CREATE_SUSPENDED | CREATE_NO_WINDOW;
#endif

		if (!CreateProcessA(
			NULL,   // No module name (use command line)
			(LPSTR)cmdStr.c_str(),  // Command line
			NULL,   // Process handle not inheritable
			NULL,   // Thread handle not inheritable
			FALSE,  // Set handle inheritance to FALSE
			creationFlags,      // No creation flags
			NULL,   // Use parent's environment block
			NULL,   // Use parent's starting directory
			&startupInfo,    // Pointer to STARTUPINFO structure
			&processInformation)    // Pointer to PROCESS_INFORMATION structure
			)
		{
			//string message = format("Failed to create process for {} extensibility: {}", m_extensibilityListName[i], GetLastError());
			//LogErrorMessage(message);
			//DWORD errMsg = GetLastError();
			return CONTAINER_START;
		}

		BOOL assigned = AssignProcessToJobObject(g_ContainerJob, processInformation.hProcess);
		if (assigned) {
			ResumeThread(processInformation.hThread);
		}
		else {
			TerminateProcess(processInformation.hProcess, 1);
		}
		CloseHandle(processInformation.hThread);
		CloseHandle(processInformation.hProcess);
		if (!assigned) {
			return CONTAINER_START;
		}
	}

	return PANO_SUCCESS;
}

std::wstring DetectorExecutablePath() {
	WCHAR path[MAX_PATH];
	DWORD length = GetModuleFileNameW(NULL, path, MAX_PATH);
	if (length == 0 || length == MAX_PATH) {
		return L"";
	}
	std::wstring directory(path, length);
	directory.resize(directory.find_last_of(L'\\') + 1);
	return directory + L"PanoptesDetector.exe";
}

ERRORCODE StartDetector() {
	std::wstring exe = DetectorExecutablePath();
	if (exe.empty() || GetFileAttributesW(exe.c_str()) == INVALID_FILE_ATTRIBUTES) {
		// The detector is optional: without it, the service still logs and scans
		std::cerr << "PanoptesDetector.exe is not next to the service; behavioral rules are off" << std::endl;
		return PANO_SUCCESS;
	}
	if (!CreateContainerJob()) {
		return CONTAINER_START;
	}

	std::wstring folder = exe.substr(0, exe.find_last_of(L'\\'));
	std::wstring commandLine = L"\"" + exe + L"\" -rules \"" + folder + L"\\rules\"";
#ifdef _DEBUG
	// Debug builds of the service publish their port under HKCU, and the detector's output
	// shares the service's console
	commandLine += L" -debug-service";
	DWORD creationFlags = CREATE_SUSPENDED;
#else
	DWORD creationFlags = CREATE_SUSPENDED | CREATE_NO_WINDOW;
#endif

	STARTUPINFOW startupInfo{};
	startupInfo.cb = sizeof(startupInfo);
	PROCESS_INFORMATION processInformation{};
	if (!CreateProcessW(exe.c_str(), commandLine.data(), NULL, NULL, FALSE, creationFlags, NULL,
		folder.c_str(), &startupInfo, &processInformation)) {
		std::cerr << "Failed to start PanoptesDetector.exe (error " << GetLastError() << ")" << std::endl;
		return CONTAINER_START;
	}

	// In the job before it runs, so it ends with the service like the containers do
	BOOL assigned = AssignProcessToJobObject(g_ContainerJob, processInformation.hProcess);
	if (assigned) {
		ResumeThread(processInformation.hThread);
	}
	else {
		TerminateProcess(processInformation.hProcess, 1);
	}
	CloseHandle(processInformation.hThread);
	CloseHandle(processInformation.hProcess);
	return assigned ? PANO_SUCCESS : CONTAINER_START;
}

bool IsServiceChildProcess(HANDLE process) {
	BOOL inJob = FALSE;
	return g_ContainerJob != NULL && IsProcessInJob(process, g_ContainerJob, &inJob) && inJob;
}

void StopContainers() {
	if (g_ContainerJob == NULL) {
		return;
	}

	// Containers hold no state that needs saving, so they are ended rather than asked to exit
	TerminateJobObject(g_ContainerJob, 0);
	CloseHandle(g_ContainerJob);
	g_ContainerJob = NULL;
}
