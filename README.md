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
- Kernel callbacks monitoring (see [Kernel Driver Callbacks](#kernel-driver-callbacks)):
  - Process creation and termination
  - Image (DLL) loading, which drives the hook DLL injection
  - File system activity through a minifilter: file creation, modification, deletion, renames, security and extended attribute changes, named pipes and mailslots
- Userland NTAPI function hooks for injection and process tampering techniques (see [Userland Hooks](#userland-hooks))
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

Panoptes has four parts. The driver and the hook DLL only produce events; `PanoptesService` does all of the logging and decides what to scan.

| Component | Source | Role |
|-----------|--------|------|
| Kernel driver (`Panoptes.sys`) | `src/driver` | Kernel callbacks and a file system minifilter (see [Kernel Driver Callbacks](#kernel-driver-callbacks)). Injects the hook DLL into new processes. |
| Hook DLL (`PanoptesDLLx64.dll`, `PanoptesDLLx86.dll`) | `src/hook` | Hooks ntdll inside each injected process (see [Userland Hooks](#userland-hooks)). |
| `PanoptesService` | `src/service` | Collects the driver's and the hooks' events, writes the log, queues scans, quarantines detections and shows tray notifications. |
| Containers and scanners | `src/container`, `src/extensibility`, `src/scanner` | Scan files for the service in isolated processes (see [Extensibility Modules](#extensibility-modules)); `PanoptesScan` and `PanoptesScanCLI` request scans on demand. |

### Driver to service: the device object

The driver exposes `\\.\Panoptes` and delivers events by inverted call. The service keeps several `IOCTL_PANOPTES_GET_EVENT` requests pending, and the driver completes one with each event: a `PANO_EVENT_HEADER` (the event's size, type and drop counts) followed by the event's data. The format is shared by both sides in `src/driver/include/pano_events.h`.

- When no request is pending, events are buffered in a FIFO of up to 2048 events. Events that arrive when it is full are dropped, and the count is reported in the next delivered header.
- Events are only produced while a service is connected. With no consumer they are dropped rather than buffered, so a service that starts or restarts is not handed a stale backlog; these drops are counted separately.
- The service's own file activity (its log, database and scans) is not reported, so it does not feed back into itself.

The service also configures the driver through IOCTLs on the same device, from the configuration file:

| IOCTL | Setting | Effect |
|-------|---------|--------|
| `IOCTL_PANOPTES_SET_INJECTION_EXCLUSIONS` | `DontInject` | Images the hook DLL is not injected into |
| `IOCTL_PANOPTES_SET_FILE_EVENTS` | `FileEvents` | Which groups of file system events the minifilter reports |
| `IOCTL_PANOPTES_TERMINATE_PROCESS` | | Terminates a process from the kernel |

The driver still registers a legacy ETW provider, but it only logs the driver starting and stopping.

### Hook DLL to service: ETW

Each injected process registers the hook DLL's `Panoptes.Hook` TraceLogging provider. The service runs a real-time ETW session (`Panoptes Hook Trace`) for it and logs each event alongside the driver's events. Writing an event is a single `NtTraceEvent` syscall, which is not hooked, so logging from inside a hook cannot recurse.

### Service to containers: gRPC

The service and the containers talk over gRPC (`proto/src/panoptes.proto`). Containers register with the service (`Hello`), are health-checked (`HealthCheck`), receive scan requests (`PEScan`) and return results (`ScanResults`); the scanners queue scans through the service (`QueuePeScan`). The containers run in a job object, so they end with the service.

### What gets scanned and logged

- Every event is written to `C:\ProgramData\Panoptes\Logs\pano.log` as one JSON object per line (NDJSON), with `Event` as the first key. The log rotates at 5 MB to `pano1.log`, `pano2.log`, and so on. Paths in `LogExclusions` are not logged but are still scanned.
- Created and modified files are scanned once their writes settle, and only if they are PE files; paths in `Exclusions` are skipped. Scan results are kept in a RocksDB database keyed by the file's MD5 hash, so a file already scanned is answered from the database instead of being scanned again.
- Malicious files are moved to `C:\ProgramData\Panoptes\Quarantine` when `QuarantineMaliciousFiles` is set, and a tray notification is shown.
- Debug builds of the service also echo each logged event to its console.

## Core Components

### Kernel Driver Callbacks

The kernel driver (`src/driver`) registers the following callbacks. The events they produce are defined in `src/driver/include/pano_events.h`.

| Callback | Registered with | What it does |
|----------|-----------------|--------------|
| Process notify (`ProcessCreateCallback`) | `PsSetCreateProcessNotifyRoutineEx` | Reports process creation (process ID, parent process ID, creating process and thread, image path and command line) and termination. Tracks each new process's architecture and whether it is protected, for injection. |
| Image load notify (`LoadImageNotifyRoutine`) | `PsSetLoadImageNotifyRoutine` | Drives the hook DLL injection. Once a tracked process has loaded `ntdll.dll`, `kernel32.dll` and `KernelBase.dll`, it queues a kernel APC that loads `C:\Program Files\Panoptes\PanoptesDLLx64.dll` or `PanoptesDLLx86.dll` into the process. Driver loads are not reported. |
| File system minifilter (`pano_filter.cpp`) | `FltRegisterFilter` / `FltStartFiltering` | Pre- and post-operation callbacks on file system I/O, described below. |

The minifilter reports:

| Operation | Events |
|-----------|--------|
| `IRP_MJ_CREATE` | File created, overwritten or superseded, and files opened with `FILE_DELETE_ON_CLOSE` (reported as a delete) |
| `IRP_MJ_CREATE_NAMED_PIPE` | Named pipe created; clients connecting to a named pipe are reported through `IRP_MJ_CREATE` |
| `IRP_MJ_CREATE_MAILSLOT` | Mailslot created; clients opening a mailslot are reported through `IRP_MJ_CREATE` |
| `IRP_MJ_WRITE` / `IRP_MJ_CLEANUP` | Writes are counted per handle and reported as one file-modified event when the handle closes (or periodically, while a handle keeps writing) |
| `IRP_MJ_SET_INFORMATION` | File marked for deletion; file renamed or moved |
| `IRP_MJ_SET_SECURITY` | Security descriptor changed, with which parts (owner, DACL, ...) |
| `IRP_MJ_SET_EA` | Extended attributes written |

The driver does not inject into:
- protected processes,
- processes whose signature policy only allows Microsoft-signed images (e.g. Chromium-based processes such as `msedge.exe`), because code integrity would reject the hook DLL,
- images in the configuration's `DontInject` list.

Planned callbacks:
- `ObRegisterCallbacks`: process, thread and desktop handle operations
- `CmRegisterCallbackEx`: registry modifications
- `PsSetCreateThreadNotifyRoutine`: thread creation

### Userland Hooks

The hook DLL (`src/hook`, `PanoptesDLLx64.dll` and `PanoptesDLLx86.dll`) is injected by the driver early in process creation and hooks the following ntdll exports with [Microsoft Detours](https://github.com/microsoft/Detours). Each hook calls the real function first and only reports a successful call, unless noted. "Remote" means the target is a different process than the one the hook runs in.

| API | Reported when | Event |
|-----|---------------|-------|
| `NtWriteVirtualMemory` | The buffer starts with the `MZ` magic bytes of a PE image. Reports whether the target is remote and whether the destination memory is executable. | `PEWritten` |
| | The write overlaps the target's PEB page, e.g. process hollowing rewriting `ImageBaseAddress`. From x64 a WOW64 target's 32-bit PEB counts too. Reports the offset into the PEB. | `PEBWritten` |
| `NtReadVirtualMemory` | The read overlaps the target's PEB page. Informational: debuggers and tools such as Task Manager read other processes' PEBs routinely. | `PEBRead` |
| `NtProtectVirtualMemory` | Memory is made executable (`PAGE_EXECUTE`, `PAGE_EXECUTE_READ`, `PAGE_EXECUTE_READWRITE` or `PAGE_EXECUTE_WRITECOPY`, with any modifiers). Reports the old and new protection. | `PEMadeExecutable` |
| `NtAllocateVirtualMemory`, `NtAllocateVirtualMemoryEx` | Memory is allocated with an executable protection. Reports the base and size the kernel returned. | `ExecutableAllocated` |
| `NtMapViewOfSection`, `NtMapViewOfSectionEx` | A view is mapped into a remote process. Reports whether any page of the view is executable and whether it is an image. | `RemoteViewMapped` |
| `NtUnmapViewOfSection`, `NtUnmapViewOfSectionEx` | A view with any executable page is unmapped, e.g. the first step of process hollowing. The view is queried *before* the call, since its protection is gone afterwards; the whole view is walked, so an image whose first page is its read-only header still counts. | `ExecutableUnmapped` |
| `NtCreateThreadEx` | A thread is created in a remote process. Reports the start address and creation flags (e.g. suspended). | `RemoteThreadCreated` |
| `NtQueueApcThread`, `NtQueueApcThreadEx2` | An APC is queued to a thread in a remote process. Reports the routine and flags (`0x1` is a special user APC, which runs without the thread waiting alertably). `QueueUserAPC` goes through `NtQueueApcThreadEx2`, which passes ntdll's APC dispatcher as the routine. | `ApcQueued` |
| `NtSetInformationProcess` | Setting `ProcessProtectionInformation` (class 61) is attempted. Reported *whether or not it succeeds*: only the kernel can change a process's protection, so the attempt itself is the signal. | `ProtectionSetAttempt` |

The hooks report through an ETW TraceLogging provider, `Panoptes.Hook` (`{D9AA2FDD-2853-4A97-A42F-E77E42921704}`), with the detection keyword `0x1`. Every event carries the API, `TargetProcessId` and `Remote`; the process the hook ran in is the process ID in the event header. The service consumes the provider and writes the events to the same log as the driver's events. Debug builds also send each event to `OutputDebugString` as a `[Panoptes]` message, which the hook tests check.

Known gaps and noise:
- `NtQueueApcThreadEx` is not hooked, so APCs queued through it directly are missed.
- Executable allocations and protection changes in a process's own memory are common (JIT compilers in .NET and browsers), and `FreeLibrary` unmaps executable images, so local events are noisy. Remote events are the stronger signal.
- `CreateProcess` writes to the new child's PEB, so every process launch produces a remote `PEBWritten`.
- Detours' own protection changes when placing and removing the hooks are reported by the `NtProtectVirtualMemory` hook.

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
- View logs: `C:\ProgramData\Panoptes\Logs` (or browse them with the log viewer below)

### Log Viewer TUI (`tools/`)

`tools/pano_tui.py` is a terminal UI for browsing a Panoptes log by process, which is quicker than reading the raw NDJSON. It pairs each process's creation and termination events and groups every other event (file activity, hook detections) under the process it happened in, so you can open a process and see what it did during its lifetime.

```powershell
pip install textual
python tools/pano_tui.py C:\ProgramData\Panoptes\Logs\pano.log
```

It needs `proc_window.py`, which does the start/end pairing, in the same folder. `--slack <seconds>` widens each process's lifetime by that many seconds either side when matching events to it.

| Screen | Keys |
|--------|------|
| Process list | `Enter` open a process, `/` filter, `s` cycle the sort (tree, start, events, image, PID), `h` hide or show processes that were already running when the log started, `q` quit |
| Process view | `/` filter its events, `t` include its child processes, `r` include events other processes aimed at it (e.g. a remote `PEBWritten` or `RemoteThreadCreated`), `Esc` back |

The default tree sort indents child processes under their parent, and when filtering, the parents of a match stay visible (dimmed) for context. In the process view, the highlighted event is shown in full at the bottom.

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

Each hooked API also has a test for both architectures, `Test_<API>x64.exe` and `Test_<API>x86.exe` (e.g. `Test_NtWriteVirtualMemoryx64.exe`), plus `Test_PanoptesDLL<arch>.exe`, which checks the hooks are placed and removed. They check the `[Panoptes]` messages the hooks emit, so they only test anything in Debug builds. The Debug `TargetPackage` (`bin/TargetPackage.zip`) includes them with a `run-hook-tests.ps1` script for running them on a KDNET target.

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


