# Panoptes Endpoint Detection and Response

<p align="center">
<img width="50%" src="assets/icons/original.jpg" alt="Panoptes Logo"/><br />
</p>

## Overview

Panoptes is an Endpoint Detection and Response (EDR) system designed for educational purposes to understand Windows Kernel Drivers, ETW, and Windows system interactions. **This is not intended for production use.**

## Demo

[Link to video](https://youtu.be/U_L-zY7IxYM)

## Features

- MSI installer for easy installation and removal
- Persistent storage using RocksDB for improved response time
- JSON-formatted logs compatible with ELK, [HELK](https://github.com/Cyb3rWard0g/HELK), and other SIEM solutions
- Kernel-level DLL injection using Kernel Asynchronous Procedure Call (kAPC)
- Kernel Callbacks monitoring:
  - Process Creation
  - DLL loading
  - Kernel Driver loading
  - Thread/Process/Desktop handle operations
- Userland NTAPI function hooks
- Static Analysis using Yara-X with ability to use custom rules
- Authenticode signature verification (embedded and catalog) using WinVerifyTrust
- JSON configuration file with built-in linter
- Right-click context menu integration
- Command-line interface for scanning
- Comprehensive unit testing using Google Tests (IN PROGRESS)

## About the Name

Panoptes, meaning "all-seeing," comes from Greek mythology. Argus Panoptes was a giant with a hundred eyes who served as a guardian to the Greek Gods. [Learn more about Argus Panoptes](https://en.wikipedia.org/wiki/Argus_Panoptes)

## Architecture

Panoptes is designed with flexibility in mind, allowing users to customize deployment through a JSON configuration file. Panoptes is also packaged using [Wix Toolset](https://www.firegiant.com/wixtoolset/) MSI file for easy installation and uninstallation.

<p align="center">
<img width="90%" src="assets/diagrams/EDR_Overview.gif" alt="EDR Architecture Overview"/><br />
</p>

The system uses gRPC for communication between the main service, containers, and tools. The kernel driver reports events directly to the main service through a device object: the service keeps a single general `GET_EVENT` IOCTL pending, and the driver completes it with the next event (a header containing the event's size and type, followed by the event data). The service does all of the logging; the driver only produces events. *(In progress: the shared event format is defined in `src/driver/include/pano_events.h`; the driver still reports through its legacy ETW provider until the device object is implemented.)*

## Core Components

### Kernel Driver Callbacks

The kernel driver implements several callbacks for system event monitoring:
- Process creation/termination
- Module/driver loading 
- Process handle operations (**IN PROGRESS**)
- Registry modifications (**IN PROGRESS**)

Currently implemented:
- PsSetCreateProcessNotifyRoutineEx
- PsSetLoadImageNotifyRoutine

Planned implementations:
- ObRegisterCallbacks
- CmRegisterCallbackEx
- PsSetCreateThreadNotifyRoutine

**Note: Currently the kernel driver is hardcoded to only inject the hooking DLL into Detect it Easy (die.exe)**

### Userland Hooks

Panoptes injects a DLL module into processes during early creation stages using kernel-level injection. This ensures comprehensive event capture from process start to finish. Current API hooks include:
- NtWriteVirtualMemory
- NtModifyBootEntry
- NtMapViewOfSectionEx
- NtMapViewOfSection
- **MORE TO BE ADDED**

### Extensibility Modules

Panoptes uses a container-based architecture for its modules, providing:
- Fault isolation
- Improved stability
- Easy module addition
- Better resource management
- Parallel processing capabilities

#### Core Modules

1. **PanoptesYara**
   - Core detection module
   - Uses [VirusTotal/Yara-X](https://github.com/VirusTotal/yara-x)
   - Supports custom compiled rules
   - Compatible with [awesome-yara](https://github.com/InQuest/awesome-yara) rules or many others
   - Verifies each scanned file's Authenticode signature with WinVerifyTrust and reports the result (signed, trusted, signer)

## Installation

1. Download the MSI installer from the Releases page
2. To use the Panoptes Kernel Driver ensure that testsigning is enabled using the following command:
   ```powershell
   bcdedit /set TESTSIGNING ON
   ```
   Then restart your system
3. Run the MSI installer
4. Place compiled Yara-X rules in `C:\Program Files\Panoptes\`
5. Start `PanoptesService.exe` as Administrator


### Compiling Custom Rules

```powershell
yr.exe compile <PATH_TO_YARA_RULES_FOLDER> -o rules.pkg
```

## Usage

- Right-click files to scan
- Use command-line interface for batch scanning
- Monitor notifications for detections
- Check quarantine folder: `C:\ProgramData\Panoptes\Quarantine`
- View logs: `C:\ProgramData\Panoptes\Logs`

## Development Setup

### Prerequisites

- [Visual Studio 2026](https://visualstudio.microsoft.com/) with C++ desktop development workload
- [vcpkg](https://vcpkg.io/en/) (included with Visual Studio or standalone)
- [Windows Driver Kit (WDK)](https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk) (for kernel driver builds)
- Test signing enabled (for driver development)
- Virtual Machine configured for Windows Kernel Debugging using WinDbg

Set the `VCPKG_ROOT` environment variable to your vcpkg installation:
```powershell
# If installed with Visual Studio
$env:VCPKG_ROOT = "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\vcpkg"

# Or set it permanently
[System.Environment]::SetEnvironmentVariable("VCPKG_ROOT", "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\vcpkg", "User")
```

For kernel development environment setup, see:
- [Ap3x/Windows-Kernel-Development-Infrastructure](https://github.com/Ap3x/Windows-Kernel-Development-Infrastructure)
- [Microsoft WDK Installation Guide](https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk)

### Building with CMake

The project uses a single CMake preset with the Visual Studio multi-config generator. You configure once and choose Debug/Release at build time.

#### Configure
```powershell
cmake --preset default
```

#### Build
```powershell
# Debug build (with debug symbols for your code)
cmake --build build/default --config Debug

# Release build (optimized)
cmake --build build/default --config Release
```

#### Build the Kernel Driver
```powershell
cmake --preset default -DBUILD_DRIVER=ON
cmake --build build/default --config Debug --target PanoptesDriver
```

#### Build and Run Tests
```powershell
cmake --preset tests
cmake --build --preset tests --config Debug
```

```powershell
cd bin/Debug/tests
./Test_PanoptesYara.exe
./Test_Linter.exe
```

### CMake Build Options

The following options can be passed during configuration with `-D`:

| Option | Default | Description |
|--------|---------|-------------|
| `BUILD_DRIVER` | OFF | Build the kernel driver package (requires WDK) |
| `BUILD_GRPC` | ON | Generate gRPC code from protobuf definitions |
| `BUILD_TESTS` | OFF | Build the unit tests into `bin/<config>/tests` (enabled by the `tests` preset) |
| `BUILD_DOC` | OFF | Build Doxygen documentation |
| `BUILD_WIX_INSTALLER` | OFF | Build the Wix MSI installer package |

Example with multiple options:
```powershell
cmake --preset default -DBUILD_DRIVER=ON -DBUILD_DOC=ON
cmake --build build/default --config Release
```

#### Building the MSI Installer

The MSI installer requires the WDK (for the driver) and the [WiX Toolset v5](https://wixtoolset.org/) CLI:

```powershell
dotnet tool install --global wix --version 5.0.2
```

The required WiX extensions (`WixToolset.UI.wixext`, `WixToolset.Util.wixext`) are installed automatically during CMake configuration. Then configure and build with the `installer` preset, which enables `BUILD_DRIVER` and `BUILD_WIX_INSTALLER` and builds every packaged binary in Release:

```powershell
cmake --preset installer
cmake --build --preset installer
```

In VS Code, select the **MSI Installer** configure preset and the **MSI Installer (Release)** build preset in the CMake Tools status bar, then run **CMake: Build**.

The MSI will be output to `bin/Release/installer/PanoptesInstaller.msi`.

## Screenshots of Panoptes Features
### Scanning and Detecting Malicious Activity Notification

<p align="center" >
<img width="40%" src="assets/screenshots/traynotification.png"/><br />
</p>

<p align="center" >
<img width="40%" src="assets/screenshots/contextmenu.png"/><br />
</p>

### MSI Installer 

<p align="center" >
<img width="40%" src="assets/screenshots/welcomeinstaller.png"/><br />
</p>


<p align="center" >
<img width="40%" src="assets/screenshots/eula.png"/><br />
</p>

<p align="center" >
<img width="40%" src="assets/screenshots/customactioninstaller.png"/><br />
</p>

### Installed Locations

<p align="center" >
<img width="60%" src="assets/screenshots/installfolder.png"/><br />
</p>


<p align="center" >
<img width="60%" src="assets/screenshots/driverinstallfolder.png"/><br />
</p>

### Easily Uninstall in App and Programs Menu in Settings

<p align="center" >
<img width="50%" src="assets/screenshots/appfeatures.png"/><br />
</p>

## Roadmap

- [ ] Component-specific documentation
- [ ] Add more NTDLL hooks for monitoring

## Future Plans

### PanoptesLite

A lighter, driver-less edition of Panoptes. Instead of the kernel driver, PanoptesLite would collect its telemetry only from ETW providers (for example `Microsoft-Windows-Kernel-Process` and `Microsoft-Windows-Kernel-File`), while still using the same extensibility (Yara) containers for scanning. This makes it installable where loading a kernel driver isn't possible or wanted, at the cost of the visibility and enforcement the driver provides.

## References

- [Kernel Callback Functions](https://codemachine.com/articles/kernel_callback_functions.html)
- [EDR Kernel Callbacks](https://pre.empt.blog/2023/maelstrom-5-edr-kernel-callbacks-hooks-and-call-stacks)
- [Windows EDR Telemetry](https://www.edr-telemetry.com/windows)
- [ETW Events Overview](https://artefacts.help/windows_etw_overview.html)
- [Windows Security Event IDs](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/default.aspx)
- [LOL Drivers Yara Rules](https://github.com/magicsword-io/LOLDrivers/tree/main/detections/yara)
- [Installing Test Certifications](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/installing-test-certificates)


