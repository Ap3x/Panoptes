# Panoptes Kernel Driver (`Panoptes.sys`)

The driver watches the system from the kernel and injects the [hook DLL](../hook/README.md) into new processes. It only produces events: it hands them to [`PanoptesService`](../service/README.md), which does all of the logging. See the [main README](../../README.md) for how the components fit together.

## Kernel callbacks

| Callback | Registered with | What it does |
|----------|-----------------|--------------|
| Process notify (`ProcessCreateCallback`) | `PsSetCreateProcessNotifyRoutineEx` | Reports process creation (process ID, parent process ID, creating process and thread, image path and command line) and termination. Tracks each new process's architecture and whether it is protected, for injection. |
| Image load notify (`LoadImageNotifyRoutine`) | `PsSetLoadImageNotifyRoutine` | Drives the hook DLL injection (below). Driver loads are not reported. |
| File system minifilter (`pano_filter.cpp`) | `FltRegisterFilter` / `FltStartFiltering` | Pre- and post-operation callbacks on file system I/O (below). |

Planned callbacks:
- `ObRegisterCallbacks`: process, thread and desktop handle operations
- `CmRegisterCallbackEx`: registry modifications
- `PsSetCreateThreadNotifyRoutine`: thread creation

### Minifilter

| Operation | Events |
|-----------|--------|
| `IRP_MJ_CREATE` | File created, overwritten or superseded, and files opened with `FILE_DELETE_ON_CLOSE` (reported as a delete) |
| `IRP_MJ_CREATE_NAMED_PIPE` | Named pipe created; clients connecting to a named pipe are reported through `IRP_MJ_CREATE` |
| `IRP_MJ_CREATE_MAILSLOT` | Mailslot created; clients opening a mailslot are reported through `IRP_MJ_CREATE` |
| `IRP_MJ_WRITE` / `IRP_MJ_CLEANUP` | Writes are counted per handle and reported as one file-modified event when the handle closes (or periodically, while a handle keeps writing) |
| `IRP_MJ_SET_INFORMATION` | File marked for deletion; file renamed or moved |
| `IRP_MJ_SET_SECURITY` | Security descriptor changed, with which parts (owner, DACL, ...) |
| `IRP_MJ_SET_EA` | Extended attributes written |

Each group of events can be turned off with the `FileEvents` setting (see the [service README](../service/README.md#configuration)). A group that is off is dropped at the start of its callbacks.

## Hook DLL injection

Once a tracked process has loaded `ntdll.dll`, `kernel32.dll` and `KernelBase.dll`, the image load callback queues a kernel APC that loads `C:\Program Files\Panoptes\PanoptesDLLx64.dll` or `PanoptesDLLx86.dll` (matching the process's architecture) into it. The driver does not inject into:
- protected processes,
- processes whose signature policy only allows Microsoft-signed images (e.g. Chromium-based processes such as `msedge.exe`), because code integrity would reject the hook DLL,
- images in the `DontInject` list.

## Talking to the service: `\\.\Panoptes`

The driver delivers events by inverted call. The service keeps several `IOCTL_PANOPTES_GET_EVENT` requests pending, and the driver completes one with each event: a `PANO_EVENT_HEADER` (the event's size, type and drop counts) followed by the event's data. The event types and layouts are shared with the service in [`include/pano_events.h`](include/pano_events.h).

- When no request is pending, events are buffered in a FIFO of up to 2048 events. Events that arrive when it is full are dropped, and the count is reported in the next delivered header.
- Events are only produced while a service is connected. With no consumer they are dropped rather than buffered, so a service that starts or restarts is not handed a stale backlog; these drops are counted separately.
- The service's own file activity (its log, database and scans) is not reported, so it does not feed back into itself.
- Only SYSTEM and Administrators can open the device.

The service configures the driver through IOCTLs on the same device:

| IOCTL | Setting | Effect |
|-------|---------|--------|
| `IOCTL_PANOPTES_SET_INJECTION_EXCLUSIONS` | `DontInject` | Images the hook DLL is not injected into. Applies to processes not injected yet. |
| `IOCTL_PANOPTES_SET_FILE_EVENTS` | `FileEvents` | Which groups of file system events the minifilter reports |
| `IOCTL_PANOPTES_TERMINATE_PROCESS` | | Terminates a process from the kernel |

The driver also registers a legacy ETW provider, which only logs the driver starting and stopping.

## Building

The driver needs the [Windows Driver Kit](https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk) and is off by default:

```powershell
cmake --preset default -DBUILD_DRIVER=ON
cmake --build build/default --config Debug --target PanoptesDriver
```

The package (`Panoptes.sys`, `.inf`, `.cat` and the test certificate `.cer`) goes to `bin/<config>/driver`. It is test-signed, so the machine it loads on needs test signing turned on (`bcdedit /set testsigning on`, then reboot). `sign-panoptes.ps1` signs other binaries with the same certificate.

## Debugging on a KDNET target

A Debug build with every component also produces `bin/TargetPackage.zip` (the `TargetPackage` target, or the **Package Debug Build for KDNET Target** VS Code task): the driver, service, containers, hook DLLs and hook tests, signed with the driver's certificate. On the target, run its `install.ps1` from an elevated prompt; it stops any running copy, trusts the certificate, installs the driver and hook DLLs, and starts the driver. Symbols stay on the host in `bin/Debug`.
