#include <string>
#include <codecvt>
#include <locale>
#include <amsi.h>
#include "PanoptesAMSI.h"
#define VERSION "1.0.0"

/// @brief Main entry point for the DLL
/// @param module The module handle
/// @param dllAction The action to take
/// @param lpReserved Reserved
/// @return 
BOOL APIENTRY DllMain(HMODULE module, DWORD dllAction, LPVOID lpReserved)
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
/// @param ContainerPort The port of the container that the extensibility is running in
/// @return The container port
extern "C" PANO_API int PanoBind(int ContainerPort)
{
	PanoptesServiceClient client = PanoptesServiceClient();
	if (!client.Hello(ExtensibilityType::EXTENSIBILITY_TYPE_AMSI, ContainerPort)) {
		return 0;
	}

	return ContainerPort;
}

/// @brief The entry point for the AMSI extensibility
/// @param data The information about the file to be scanned
/// @param mem_data The information about the memory to be scanned
/// @return True if the scan was successful, false otherwise
extern "C" PANO_API bool PanoEntry(PeScan* data, MemScan* mem_data)
{
	if (data->PePath.empty()) {
		return false;
	}

	INT amsi_result = 0;
	HRESULT status = AmsiScanner::AmsiScanFile(data->PePath, "", &amsi_result);
	if (FAILED(status)) {
		return false;
	}
	else {
		PanoptesServiceClient client = PanoptesServiceClient();
		if (!client.SendResults_AMSI(data->PePath, data->FileHash, amsi_result)) {
			return false;
		}

		return true;
	}
}

/// @brief Unbind from the Panoptes Service by freeing the DLL
/// @return True if the unbind was successful, false otherwise
extern "C" PANO_API bool PanoUnbind()
{
	HMODULE hModule = GetModuleHandleA("PanoptesAMSI.dll");
	if (hModule != NULL) {
		FreeLibraryAndExitThread(hModule, 0);
	}
	return true;
}