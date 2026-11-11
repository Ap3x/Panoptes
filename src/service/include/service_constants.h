//Container Constants

#define EXT_YARA "PanoptesYara.dll"
#define EXT_ML "PanoptesML.dll"

//Service Constants

#define SERVICE_MUTEX "Panoptes"

//Database Constants

#define PANOPTES_DATABASE_PATH "C:\\ProgramData\\Panoptes\\database"

//Registry Constants

// Debug builds run unelevated, so the port is published under HKCU instead of HKLM
#ifdef _DEBUG
#define PANOPTES_REG_ROOT HKEY_CURRENT_USER
#else
#define PANOPTES_REG_ROOT HKEY_LOCAL_MACHINE
#endif // _DEBUG

//Logging Constants

#define LOG_FOLDER L"C:\\ProgramData\\Panoptes\\Logs\\"
#define BASE_FILENAME  L"pano"
#define FILE_EXTENSION L".log"
#define MAX_FILE_SIZE (1024 * 1024 * 5) // 5 MB

//Error Constants

#define ERRORCODE int

// Driver Constants

#define KERNEL_DRIVER_SERVICE_NAME "Panoptes"
