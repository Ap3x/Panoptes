#include "PanoptesYara.h"
#include <string>
#include <iostream>
#include <stdexcept>

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
/// @return True if the scan was successful, false otherwise
extern "C" PANO_API bool PanoEntry(PeScan* data)
{
	std::string rules = "rules.pkg";

	std::vector<std::string> scanDataResults;
	try {
		YaraScanner yaraScan(rules.c_str());
		scanDataResults = yaraScan.YaraScanFile(data->PePath);
	}
	catch (const std::exception& e) {
		// An exception must not leave this extern "C" export: it would end the container,
		// and every later scan with it. A file deleted or locked before its scan is common
		std::cerr << "YARA scan of " << data->PePath << " failed: " << e.what() << std::endl;
		return false;
	}
	SignatureInfo signature = VerifyFileSignature(data->PePath);

	PanoptesServiceClient client = PanoptesServiceClient();
	if (!client.SendResults_Yara(data->PePath, data->FileHash, scanDataResults, signature)) {
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
