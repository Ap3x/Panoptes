#pragma once

#ifdef RESOURCES_EXPORTS
    #define RESOURCES_API __declspec(dllexport)
#else
    #define RESOURCES_API __declspec(dllimport)
#endif

// Error codes (imported from resource.h)
#define NOT_SET                         101
#define PANO_SUCCESS                    102
#define FILE_NOT_FOUND                  103
#define PERMISSION_DENIED               104
#define INVALID_INPUT                   105
#define MUTEX_NOT_SET                   106
#define MUTEX_SET                       107
#define DB_INITIALIZATION               108
#define DB_DELETE                       109
#define CONTAINER_START                 110
#define WINDOWS_ERR                     111
#define INVALID_HANDLE                  112
#define IOCTL_FAILED                    113
#define EVENT_CREATE                    114
#define NAMED_PIPE_CREATE               115
#define KERNEL_PIPE                     116
#define NOT_INSTALLED                   117
#define CONTROL_SERVICE                 118
#define PANO_SERVICE_RUNNING            119
#define PANO_SERVICE_STOPPED            120
#define ERROR_STARTING_SERVICE          121
#define ERROR_STOPPING_SERVICE          122
#define CLEAN_HANDLE                    123
#define EXT_SELECTED                    124
#define NOT_ADMIN                       125
#define NO_CONFIG                       126
#define START_TRACE                     127
#define GRPC_SERVER_ERROR               128
#define EXT_INVALID                     129
#define DEBUGGER                        130


// Add your DLL function declarations here
extern "C" {

RESOURCES_API int GetResourceErrorCode(const char* errorName);
RESOURCES_API const char* GetResourceErrorString(int errorCode);

}