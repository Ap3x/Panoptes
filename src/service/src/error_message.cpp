#include "error_message.h"
#include "utils.h"
#include <iostream>

std::string GetErrorMessage( UINT resourceID)
{
    char buffer[MAX_PATH];
    GetModuleFileNameA(NULL, buffer, MAX_PATH);
    std::string::size_type pos = std::string(buffer).find_last_of("\\/");
    std::string currentPath = std::string(buffer).substr(0, pos);

    std::string fullPath = currentPath + "\\Resources.dll";

	HMODULE hModule = LoadLibraryA(fullPath.c_str());
    if(hModule == NULL)
		return "";

    char err_buffer[1024];
	LoadStringA(hModule, resourceID, (LPSTR)err_buffer, MAX_PATH);
	
    return std::string(err_buffer);;
}

void DisplayErrorMessage(std::string errorMessage)
{
	MessageBoxA(NULL, errorMessage.c_str(), "Panoptes EDR", MB_OK | MB_ICONERROR);
    return;
}
