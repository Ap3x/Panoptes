#include "PanoptesYara.h"
#include <string>

/// @brief The main entry point for the DLL
/// @param module The module handle
/// @param dllAction The action to take
/// @param lpReserved Reserved
/// @return 
BOOL APIENTRY DllMain(HMODULE module, DWORD  dllAction, LPVOID lpReserved)
{
	switch (dllAction)
	{
	case DLL_PROCESS_ATTACH:
		//DisableThreadLibraryCalls(module);
		break;
	case DLL_THREAD_ATTACH:
		// Code to run when a thread is created
		break;
	case DLL_THREAD_DETACH:
		// Code to run when a thread ends
		break;
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

/// @brief Bind to the Panoptes Service by sending a hello message containing the extensibility type
/// and the port of the container that the extensibility is running in
/// @param ContainerPort The port of the container that the extensibility is running in
/// @return The container port
extern "C" PANO_API int PanoBind(int ContainerPort)
{
	PanoptesServiceClient client = PanoptesServiceClient();
	if (!client.Hello(ExtensibilityType::EXTENSIBILITY_TYPE_YARA, ContainerPort)) {
		return 0;
	}

	return ContainerPort;
}

/// @brief The entry point for the YARA extensibility
/// @param data The information about the file to be scanned
/// @param mem_data The information about the memory to be scanned
/// @return True if the scan was successful, false otherwise
extern "C" PANO_API bool PanoEntry(PeScan* data, MemScan* mem_data)
{
	std::string rules = "rules.pkg";

	YaraScanner yaraScan = YaraScanner::YaraScanner(rules.c_str());
	std::vector<std::string> scanDataResults = yaraScan.YaraScanFile(data->PePath);

	PanoptesServiceClient client = PanoptesServiceClient();
	if (!client.SendResults_Yara(data->PePath, data->FileHash, scanDataResults)) {
		return false;
	}

	return true;
}

/// @brief Unbind from the Panoptes Service by freeing the DLL
/// @return True if the unbind was successful, false otherwise
extern "C" PANO_API bool PanoUnbind()
{
	HMODULE hModule = GetModuleHandleA("PanoptesYara.dll");
	if (hModule != NULL) {
		FreeLibraryAndExitThread(hModule, 0);
	}
	return true;
}
