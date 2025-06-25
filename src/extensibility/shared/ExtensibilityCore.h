#pragma once
#include <Windows.h>
#include <string>

#define SERVICE_PORT 50055

#define PANO_API __declspec(dllexport)

/// @brief The type of extensibility
enum ExtensibilityType {
	EXTENSIBILITY_TYPE_NOT_SET = 0,
	EXTENSIBILITY_TYPE_AMSI = 10,
	EXTENSIBILITY_TYPE_PE = 20,
	EXTENSIBILITY_TYPE_YARA = 30,
};

/// @brief The information about the file to be scanned that passed between the container, 
/// extensibility and the Panoptes Service
struct PeScan {
	std::string PePath;
	std::string FileHash;
};

/// @brief The information about the memory to be scanned that passed between the container, 
/// extensibility and the Panoptes Service
struct MemScan {
	DWORD ProcessId;
};

/// @brief The core class for all extensibility to inherit from
class ExtensibilityCore {
public: 
	typedef int(*PanoBindPtr)(int);
	typedef bool(*PanoEntryPtr)(PeScan*, MemScan*);
	typedef bool(*PanoUnbindPtr)();
};