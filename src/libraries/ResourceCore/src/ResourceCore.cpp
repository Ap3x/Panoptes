#define RESOURCES_EXPORTS
#include "ResourceCore.h"
#include <string>
#include <unordered_map>

// Define the error code mappings
static const std::unordered_map<std::string, int> errorCodeMap = {
    {"NOT_SET", NOT_SET},
    {"PANO_SUCCESS", PANO_SUCCESS},
    {"FILE_NOT_FOUND", FILE_NOT_FOUND},
    {"PERMISSION_DENIED", PERMISSION_DENIED},
    {"INVALID_INPUT", INVALID_INPUT},
    {"MUTEX_NOT_SET", MUTEX_NOT_SET},
    {"MUTEX_SET", MUTEX_SET},
    {"DB_INITIALIZATION", DB_INITIALIZATION},
    {"DB_DELETE", DB_DELETE},
    {"CONTAINER_START", CONTAINER_START},
    {"WINDOWS_ERR", WINDOWS_ERR},
    {"INVALID_HANDLE", INVALID_HANDLE},
    {"IOCTL_FAILED", IOCTL_FAILED},
    {"EVENT_CREATE", EVENT_CREATE},
    {"NAMED_PIPE_CREATE", NAMED_PIPE_CREATE},
    {"KERNEL_PIPE", KERNEL_PIPE},
    {"NOT_INSTALLED", NOT_INSTALLED},
    {"CONTROL_SERVICE", CONTROL_SERVICE},
    {"PANO_SERVICE_RUNNING", PANO_SERVICE_RUNNING},
    {"PANO_SERVICE_STOPPED", PANO_SERVICE_STOPPED},
    {"ERROR_STARTING_SERVICE", ERROR_STARTING_SERVICE},
    {"ERROR_STOPPING_SERVICE", ERROR_STOPPING_SERVICE},
    {"CLEAN_HANDLE", CLEAN_HANDLE},
    {"EXT_SELECTED", EXT_SELECTED},
    {"NOT_ADMIN", NOT_ADMIN},
    {"NO_CONFIG", NO_CONFIG},
    {"START_TRACE", START_TRACE},
    {"GRPC_SERVER_ERROR", GRPC_SERVER_ERROR},
    {"EXT_INVALID", EXT_INVALID},
    {"DEBUGGER", DEBUGGER}
};

static const std::unordered_map<int, const char*> errorStringMap = {
    {NOT_SET, "Not Set"},
    {PANO_SUCCESS, "Operation successful"},
    {FILE_NOT_FOUND, "File not found"},
    {PERMISSION_DENIED, "Permission denied"},
    {INVALID_INPUT, "Invalid input"},
    {MUTEX_NOT_SET, "Mutex was not set"},
    {MUTEX_SET, "Could not set service mutex"},
    {DB_INITIALIZATION, "Cant initialize database"},
    {DB_DELETE, "Unable to delete database"},
    {CONTAINER_START, "Unable to start container instances"},
    {WINDOWS_ERR, "Windows Internal Error"},
    {INVALID_HANDLE, "Invalid Handle"},
    {IOCTL_FAILED, "An invalid IOCTL"},
    {EVENT_CREATE, "An error occured when attempting to create an event"},
    {NAMED_PIPE_CREATE, "An error occured when attempting to create a named pipe"},
    {KERNEL_PIPE, "An error occured when attempting to connect to kernel pipe."},
    {NOT_INSTALLED, "The feature was not installed"},
    {CONTROL_SERVICE, "Can't control the supplied service"},
    {PANO_SERVICE_RUNNING, "The service is running"},
    {PANO_SERVICE_STOPPED, "The service is stopped"},
    {ERROR_STARTING_SERVICE, "Failed to start service"},
    {ERROR_STOPPING_SERVICE, "Failed to stop service"},
    {CLEAN_HANDLE, "An error occured when attempting to clean up handles"},
    {EXT_SELECTED, "No extensibility has been selected"},
    {NOT_ADMIN, "The program is not running as administrator"},
    {NO_CONFIG, "Not config file was provided"},
    {START_TRACE, "Unable to start ETW trace session. Try Restarting Panoptes"},
    {GRPC_SERVER_ERROR, "An error occured attempting to start local server"},
    {EXT_INVALID, "An invalid extensibility was selected"},
    {DEBUGGER, "Debugger Detected"}
};

extern "C" {

RESOURCES_API int GetResourceErrorCode(const char* errorName) {
    auto it = errorCodeMap.find(errorName);
    return (it != errorCodeMap.end()) ? it->second : NOT_SET;
}

RESOURCES_API const char* GetResourceErrorString(int errorCode) {
    auto it = errorStringMap.find(errorCode);
    return (it != errorStringMap.end()) ? it->second : "Unknown error code";
}

} 