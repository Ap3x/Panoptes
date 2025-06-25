#include "containers.h"
#include "error_message.h"
#include "utils.h"
#include "Configuration.hpp"

std::string BuildContainerCommandLine(Configuration::ContainerType ext)
{
	std::string localPath = GetCurrentPath();
	std::string extPath = localPath + "\\ext\\";
	std::string result = "\"" + localPath + "\\PanoptesContainer.exe" + "\" \"";

	switch (ext) {
	case CONTAINER_TYPE_YARA:
		result.append(extPath + EXT_YARA);
		break;
	case CONTAINER_TYPE_AMSI:
		result.append(extPath + EXT_AMSI);
		break;
	case CONTAINER_TYPE_PE:
		result.append(extPath + EXT_PE);
		break;
	default:
		break;
	}
	result.append("\"");

	return result;
}

ERRORCODE StartContainers(std::vector<Configuration::ContainerType> selectedExtensibility) {

	if (selectedExtensibility.size() < 1)
	{
		return EXT_SELECTED;
	}

	BOOL containerStartupSuccess = true;
	STARTUPINFOA startupInfo;
	PROCESS_INFORMATION processInformation;

	ZeroMemory(&startupInfo, sizeof(startupInfo));
	startupInfo.cb = sizeof(startupInfo);
	ZeroMemory(&processInformation, sizeof(processInformation));

	for (auto containerType : selectedExtensibility) {
		std::string cmdStr = BuildContainerCommandLine(containerType);
#ifdef _DEBUG
		DWORD creationFlags = 0;
#else
		DWORD creationFlags = CREATE_NO_WINDOW;
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
	}

	return PANO_SUCCESS;
}
