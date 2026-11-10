# Panoptes Hook DLL (`PanoptesDLLx64.dll`, `PanoptesDLLx86.dll`)

The [driver](../driver/README.md) injects this DLL early in each new process. It hooks ntdll exports with [Microsoft Detours](https://github.com/microsoft/Detours) to catch code injection and process tampering, and reports what it sees to [`PanoptesService`](../service/README.md) over ETW. There is one DLL per architecture: 64-bit processes get the x64 DLL and 32-bit (WOW64) processes the x86 one. See the [main README](../../README.md) for how the components fit together.

## Hooked APIs

Each hook calls the real function first and only reports a successful call, unless noted. "Remote" means the target is a different process than the one the hook runs in.

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

Exports missing from a process's ntdll (e.g. the `Ex` variants on older Windows) are skipped.

## Events

The hooks report through an ETW TraceLogging provider, `Panoptes.Hook` (`{D9AA2FDD-2853-4A97-A42F-E77E42921704}`), at warning level (`PEBRead` is informational) with the detection keyword `0x1`. Every event carries the API, `TargetProcessId` and `Remote`; the process the hook ran in is the process ID in the event header, which the writer cannot change. The service consumes the provider through a real-time ETW session (`Panoptes Hook Trace`) and writes the events to the same log as the driver's events.

Writing an event is a single `NtTraceEvent` syscall, which is not hooked, so logging from inside a hook cannot recurse. Debug builds also send each event to `OutputDebugString` as a `[Panoptes]` message, which the tests check.

## Known gaps and noise

- `NtQueueApcThreadEx` is not hooked, so APCs queued through it directly are missed.
- Executable allocations and protection changes in a process's own memory are common (JIT compilers in .NET and browsers), and `FreeLibrary` unmaps executable images, so local events are noisy. Remote events are the stronger signal.
- `CreateProcess` writes to the new child's PEB, so every process launch produces a remote `PEBWritten`.
- Detours' own protection changes when placing and removing the hooks are reported by the `NtProtectVirtualMemory` hook.

## Building

The DLLs are built by the main project (`BUILD_HOOK`, on by default), or on their own with the `hook` preset, which only installs Detours:

```powershell
cmake --preset hook
cmake --build build/hook --config Debug
```

The x64 DLL is built by the main project and the x86 DLL by a Win32 sub-build of this folder; both go to `bin/<config>`.

## Tests

`test/` has one test per hooked API (and its `Ex` variants), built for both architectures, plus `Test_PanoptesDLL`, which checks the hooks are placed and removed:

```powershell
cmake --preset hook-tests
cmake --build build/hook --config Debug
.\bin\Debug\tests\Test_NtWriteVirtualMemoryx64.exe
```

Each test relaunches itself as a debuggee: the child loads the hook DLL and runs the cases, and the parent, as its debugger, captures the `[Panoptes]` messages and checks each case produced exactly the expected ones. The cases cover both sides of every check: what must be reported, and what must not (local targets, non-executable memory, failed calls). The messages only exist in Debug builds, so other configurations report SKIPPED.

- [`test/hook_test_harness.hpp`](test/hook_test_harness.hpp) is the shared harness. Remote targets (a suspended `cmd.exe`, and from x64 a WOW64 one) are started before the first case, so what process creation itself triggers is reported as setup.
- To debug the hooks, run a test with `--child`: the cases then run directly in the debugged process, so breakpoints in `src/hook` are hit (nothing is checked in that mode). In VS Code, use the **Debug Hook Test** launch configuration.
- The Debug `TargetPackage` (see the [driver README](../driver/README.md#debugging-on-a-kdnet-target)) installs the tests to `C:\Program Files\Panoptes\tests` on the target, next to the DLL the driver injects, and includes `run-hook-tests.ps1` to run them all.
