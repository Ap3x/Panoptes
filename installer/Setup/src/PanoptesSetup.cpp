#include <Windows.h>
#include <setupapi.h>
#include <iostream>
#include <string>
#include "absl/flags/flag.h"
#include "absl/flags/parse.h"

ABSL_FLAG(bool, install, false, "Install Panoptes Kernel Driver, Service, and Context Menu");
ABSL_FLAG(bool, uninstall, false,"Uninstall Panoptes");

/// <summary>
/// Checks if a file exists
/// </summary>
/// <param name="filePath">The path to the file</param>
/// <returns>True if the file exists, false otherwise</returns>
bool FileExists(const std::string& filePath) {
    DWORD fileAttributes = GetFileAttributesA(filePath.c_str());
    return (fileAttributes != INVALID_FILE_ATTRIBUTES &&
        !(fileAttributes & FILE_ATTRIBUTE_DIRECTORY));
}

/// <summary>
/// Checks if a service exists
/// </summary>
/// <param name="serviceName">The name of the service</param>
/// <returns>True if the service exists, false otherwise</returns>
bool ServiceExists(const std::string& serviceName) {
    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (scm == NULL) {
        return false;
    }

    SC_HANDLE service = OpenServiceA(scm, serviceName.c_str(), SERVICE_QUERY_STATUS);

    if (service == NULL) {
        DWORD error = GetLastError();
        CloseServiceHandle(scm);
        return (error != ERROR_SERVICE_DOES_NOT_EXIST);
    }

    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    return true;
}

/// <summary>
/// Installs the driver file
/// </summary>
/// <param name="infPath">The path to the INF file</param>
VOID InstallDriverFile(std::string infPath) {
	InstallHinfSection(NULL, NULL, L"DefaultInstall 132 C:\\Program Files\\Panoptes\\driver\\Panoptes.inf", 0);
}

/// <summary>
/// Creates a new context menu item called "Scan with Panoptes" that uses the PanoptesScan.exe executable
/// </summary>
/// <returns>The result of the operation</returns>
LONG NewContextMenuItem() {
    HKEY hKey, hCommandKey;
    std::string subKey = "*\\shell\\Panoptes";

    LONG result = RegCreateKeyExA(
        HKEY_CLASSES_ROOT,
        subKey.c_str(),
        0,
        NULL,
        REG_OPTION_NON_VOLATILE,
        KEY_ALL_ACCESS,
        NULL,
        &hKey,
        NULL
    );

    if (result == ERROR_SUCCESS) {
        std::string rootDefaultValue = "Scan with Panoptes";
        result = RegSetValueExA(
            hKey,
            NULL,  // NULL for the default value
            0,
            REG_SZ,
            reinterpret_cast<const BYTE*>(rootDefaultValue.c_str()),
            static_cast<DWORD>((rootDefaultValue.length() + 1) * sizeof(wchar_t))
        );
        if (result != ERROR_SUCCESS) {
            return result;
        }


        // Add the "Icon" string value
        std::string iconValue = "C:\\Program Files\\Panoptes\\tools\\PanoptesScan.exe";
        result = RegSetValueExA(
            hKey,
            "Icon",
            0,
            REG_SZ,
            reinterpret_cast<const BYTE*>(iconValue.c_str()),
            static_cast<DWORD>((iconValue.length() + 1) * sizeof(wchar_t))
        );

        if (result == ERROR_SUCCESS) {
            // Create the "Command" subkey
            result = RegCreateKeyExA(
                hKey,
                "Command",
                0,
                NULL,
                REG_OPTION_NON_VOLATILE,
                KEY_ALL_ACCESS,
                NULL,
                &hCommandKey,
                NULL
            );

            if (result == ERROR_SUCCESS) {
                // Set the default value of the "Command" subkey
                std::string commandValue = "\"C:\\Program Files\\Panoptes\\tools\\PanoptesScan.exe\" \"%1\"";
                result = RegSetValueExA(
                    hCommandKey,
                    NULL,  // NULL for the default value
                    0,
                    REG_SZ,
                    reinterpret_cast<const BYTE*>(commandValue.c_str()),
                    static_cast<DWORD>((commandValue.length() + 1) * sizeof(wchar_t))
                );

                RegCloseKey(hCommandKey);
            }
        }

        RegCloseKey(hKey);
    }

    return result;
}

/// <summary>
/// Deletes the rocksdb database file
/// </summary>
/// <param name="databasePath">The path to the database file</param>
/// <returns>True if the database file was deleted, false otherwise</returns>
bool DeleteDatabase(std::string databasePath)
{
    WIN32_FIND_DATAA findFileData;
    char searchPath[MAX_PATH];
    strcpy_s(searchPath, databasePath.c_str());
    strcat_s(searchPath, "\\*");

    HANDLE hFind = FindFirstFileA(searchPath, &findFileData);
    if (hFind == INVALID_HANDLE_VALUE) {
        return true;
    }

    do {
        if (strcmp(findFileData.cFileName, ".") != 0 &&
            strcmp(findFileData.cFileName, "..") != 0) {
            std::string filePath = databasePath + "\\" + findFileData.cFileName;

            if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                DeleteDatabase(filePath);
            }
            else {
                DeleteFileA(filePath.c_str());
            }
        }
    } while (FindNextFileA(hFind, &findFileData) != 0);

    if (RemoveDirectoryA(databasePath.c_str())) {
        return true;
    }
    else {
        printf("Error attempting to delete database file: %d\n", GetLastError());
        return false;
    }
}

/// <summary>
/// Deletes the context menu item called "Scan with Panoptes"
/// </summary>
/// <returns>The result of the operation</returns>
LONG DeleteContextMenuItem() {
    std::string subKey = "*\\shell\\Panoptes";

    LONG result = RegDeleteTreeA(
        HKEY_CLASSES_ROOT,
        subKey.c_str()
    );

    return result;
}

/// <summary>
/// Deletes the Panoptes service
/// </summary>
/// <param name="serviceName">The name of the service</param>
/// <returns>True if the service was deleted, false otherwise</returns>
bool DeletePanoptesService(const std::string& serviceName) {
    SC_HANDLE scm = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (scm == NULL) {
        return false;
    }

    SC_HANDLE service = OpenServiceA(scm, serviceName.c_str(), DELETE);
    if (service == NULL) {
        CloseServiceHandle(scm);
        return false;
    }

    BOOL result = DeleteService(service);
    if (!result) {
        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        return false;
    }

    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    return true;
}

/// <summary>
/// Deletes the Panoptes driver file
/// </summary>
/// <param name="filePath">The path to the driver file</param>
/// <returns>True if the driver file was deleted, false otherwise</returns>
bool DeletePanoptesDriver(const std::string& filePath) {
    if (DeleteFileA(filePath.c_str())) {
        return true;
    }
    else {
        DWORD error = GetLastError();
        if (error == ERROR_FILE_NOT_FOUND) {
            return true;
        }
        else {
            return false;
        }
    }
}


/// <summary>
/// Installs the Panoptes driver, service, and adds the context menu item
/// </summary>
/// <param name="infPath">The path to the INF file</param>
/// <returns>True if the driver and service were installed, false otherwise</returns>
BOOL InstallPanoptes(std::string infPath) {
    // Setup Registry Key to add Panoptes Scan to the context menu
	printf("Adding new context menu item\n");
	if (NewContextMenuItem() == ERROR_SUCCESS) {
        printf("successfully added new context menu item\n");
        // Install the Panoptes Driver INF which will setup the service
        printf("Attempting to install driver");
        InstallDriverFile(infPath);
        printf("Successfully installed driver");

        if (!FileExists("C:\\Windows\\System32\\drivers\\Panoptes\\Panoptes.sys"))
        {
			return FALSE;
        }

        if (!ServiceExists("Panoptes"))
        {
            return FALSE;
        }
        
        return TRUE;
	}

    return FALSE;
}

/// <summary>
/// Uninstalls the Panoptes driver, service, and removes the context menu item
/// </summary>
/// <returns>True if the driver, service, and context menu item were uninstalled, false otherwise</returns>
BOOL UninstallPanoptes() {
    if (DeleteContextMenuItem() == ERROR_SUCCESS) {
		if (ServiceExists("Panoptes")) {
            if (!DeletePanoptesService("Panoptes")) {
                return FALSE;
            }
		}

		std::string driverPath = "C:\\Windows\\System32\\drivers\\Panoptes\\Panoptes.sys";
        if (FileExists(driverPath)) {
            if (!DeletePanoptesDriver("C:\\Windows\\System32\\drivers\\Panoptes\\Panoptes.sys")) {
                return FALSE;
            }
        }

        if (!DeleteDatabase("C:\\ProgramData\\Panoptes\\Database")) {
            return FALSE;
        }

        return TRUE;
    }
    else {
        return FALSE;
    }

}

/// <summary>
/// The main function for the Panoptes Setup program
/// </summary>
/// <param name="hInstance">The instance of the application</param>
/// <param name="hPrevInstance">The previous instance of the application</param>
/// <param name="lpCmdLine">The command line arguments</param>
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    std::string infPath = "C:\\Program Files\\Panoptes\\driver\\Panoptes.inf";
    absl::ParseCommandLine(__argc, __argv);

    if (absl::GetFlag(FLAGS_install) == true && absl::GetFlag(FLAGS_uninstall) == true) {
        MessageBoxA(NULL, "Can not specify `install` and `uninstall` flags", "Panoptes EDR", 1);
    }
    else if (absl::GetFlag(FLAGS_uninstall) == true) {
        if (UninstallPanoptes()) {
            MessageBoxA(NULL, "Driver uninstalled successfully.", "Panoptes EDR Uninstall", 0);
        }
        else {
            MessageBoxA(NULL, "Failed to uninstall driver.", "Panoptes EDR Uninstall", 1);
        }
    }
    else if (absl::GetFlag(FLAGS_install)) {
        if (InstallPanoptes(infPath)) {
            MessageBoxA(NULL, "Driver installed successfully.", "Panoptes EDR Installer", 0);
        }
        else {
            MessageBoxA(NULL, "Failed to install driver.", "Panoptes EDR Installer", 1);
        }
    }
    else {
        MessageBoxA(NULL, "No arguments provided.", "Panoptes EDR", 1);
    }

    return 0;
}
