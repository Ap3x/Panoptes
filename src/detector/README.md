# PanoptesDetector (behavioral rules)

Evaluates YAML rules over the events `PanoptesService` logs. Each rule step is an
[expr](https://expr-lang.org) expression. Steps are chained with `sequence` / `by` / `maxspan` / `until`,
the same model as EQL's `sequence by`. See [rules/injection.yaml](rules/injection.yaml).

```
src/main.go             flags, live loop (reconnect, sweep, report) and replay mode
src/detectionlog.go     detection.log writer
src/rules/              YAML → compiled expr programs; hasFlag()/lower() helpers
src/engine/             partial-match state machine keyed by join value, event reordering
src/source/             gRPC client (port from SOFTWARE\Panoptes\SRV_PORT) and NDJSON replay
src/pb/                 generated from proto/src/panoptes.proto (go generate)
rules/                  the shipped rules (*.yaml)
test/                   tests of the shipped rules; also a place for sample logs to replay
tools/lolbas/           generator for rules/lolbas.yaml
```

Unit tests sit next to the code they test (`src/engine/engine_test.go`, `src/detectionlog_test.go`),
as Go requires. Run everything from this folder with `go test ./...`.

## Build

The CMake build (`BUILD_DETECTOR`, on by default) runs `go build` into `bin\<config>` and copies
`rules\` next to it, and TargetPackage includes both. Release builds it as a GUI-subsystem exe
(`-ldflags=-H=windowsgui`) so the service's copy runs without a console or `conhost.exe`; it
prints nothing when run from a terminal, so replay with a Debug build or a plain `go build`.
Debug stays a console exe and shows its log in a console window. The generated code in `src/pb` is
checked in. Regenerate it after changing `proto/src/panoptes.proto`:

```powershell
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
$env:PATH += ";$PWD\..\..\build\default\vcpkg_installed\x64-windows\tools\protobuf"
go generate ./...
go mod tidy
go build -o PanoptesDetector.exe ./src
```

## Rule development without the service

```powershell
.\PanoptesDetector.exe -rules rules -replay C:\ProgramData\Panoptes\Logs\pano.log
```

Matches are printed as JSON lines. Replay uses the log's `Time`, which has milliseconds
(logs written before that have whole seconds, so `maxspan` is approximate for them). Live
events carry a FILETIME. Each event keeps its `Seq` from the log, so replayed detections name
the same lines a live run would.

Replay reads the file once and exits. Live mode does not read `pano.log` at all: it streams
events from the service over `SubscribeEvents` and evaluates each one as it arrives.

## Detection log

Each detection is appended to `-detection-log` as one JSON object per line, like `pano.log`.
Live mode writes to `%ProgramData%\Panoptes\Logs\detection.log` by default. Replay writes a file
only when `-detection-log` is given, so replaying test logs doesn't add to the real one. Like
`pano.log`, it rotates at 5 MB to `detection1.log`, `detection2.log`, and so on (old files are
kept), and after a restart the detector continues in the newest one.

```json
{"Time":"2026/11/10 21:05:48.123","Rule":"process_hollowing","Description":"...","Severity":"critical",
 "Action":"kill","Key":"1948","TargetPID":13292,"Image":"C:\\Users\\...\\loader.exe",
 "EventSequences":[1763241926000412,1763241926000415],"Reported":true,"Events":[{...}, {...}]}
```

- `Time` is when the detector matched, in UTC, in the same format as `pano.log`.
- `Key` is the join value (usually the victim PID). `TargetPID` is the process the action applies to.
- `Image` is `TargetPID`'s image. It comes from the matched events (an event that process
  logged, or a hook event's `TargetImage` when it is the target). If no event names it, live
  mode asks Windows while the process is still running, as long as it was created before the
  match, so a reused PID is never named. It is `""` when neither knows.
- `EventSequences` is the `Seq` of each matched event, in step order. See below.
- `Reported` is whether the service accepted the detection (live only).
- `Events` are the matching log events, unchanged.

The service's `Detection` line in `pano.log` carries the same `Image` and `EventSequences`.

### Event sequence numbers and labeled data

Every driver and hook event in `pano.log` has a `Seq`. The service hands them out from one
counter, in the order it writes the lines, and the detector's event stream uses the same
number. The counter starts at the service's start time in microseconds since 1970 and counts
up by one per event. So `Seq` keeps increasing across restarts and identifies one line across
every `pano*.log` file, and it stays below 2^53, so JSON readers that parse numbers as doubles
read it exactly. The service's own lines (`Detection`, scan results) have no `Seq`.

To turn detections into labeled training data, read `pano*.log` and index the lines by `Seq`.
For each `Detection` line (or `detection.log` record), the lines named in `EventSequences` are
positive examples for its `Rule`. Lines no detection names are unlabeled. They are not
necessarily benign.

If the file can't be opened, the detector logs a warning and keeps detecting and reporting.

## Event order

Driver events reach the service almost immediately. Hook events go through an ETW real-time
session that flushes about once a second, so a hook event can arrive after a driver event that
happened later. For example, the `ProcessTerminated` of an injection victim can arrive before
the injection itself. Before matching, the detector holds events for `-reorder` (default 2s) and
releases them sorted by event time. Live, the engine's clock is "now minus the delay".

Events that arrive later than the delay are processed out of order and counted in the log.

Reordering trusts each event's time, but driver and hook events are timestamped by different
clocks: the driver uses system time, and ETW converts the hook's QPC timestamps to system time
from when its session started, so the two drift apart. A hook event can then carry a time
slightly before the `ProcessCreated` it follows, and sort ahead of it. To keep such sequences,
a step can match an event up to `-tolerance` (default 2s) before the previous step's event,
but only when one of the two is a hook event and the other is not. Events from the same source
share a clock, so their order is kept as it is. `-tolerance 0` turns this off.
`FileModified` is ordered by when the driver reported it: when the handle was closed, or while a
handle that is still open keeps writing (`StillOpen`). Its `FirstWriteTime` field says when the
writes began.

## Field notes

- `TargetProcessId` is `0` when the hooked call's handle couldn't be queried, even after the hook
  re-opened it for query access. Remote hook events also carry `TargetResolved` (`false` in that
  case), and `remote_target_unresolved` alerts on them. The engine never joins on `0`.
- `Image` is `System` for PID 4 (kernel-mode registry and file activity) and the bare name for
  minimal processes such as `Registry` and `MemCompression`, which have no image file.
- `RemoteViewMapped` and `ExecutableUnmapped` carry `IsImage`, a `MEM_IMAGE` view. `Image` is
  always the process's image path. Logs written before this change have `"Image": true` on those
  two events.

## Running with the service

The service starts `PanoptesDetector.exe -rules <its folder>\rules` (plus `-debug-service` in Debug
builds) when the exe is next to it, and ends it when the service stops. It accepts the event
stream and detection reports only from `PanoptesDetector.exe` in its own folder. A copy run
from elsewhere gets `PermissionDenied`.

`ReportDetection` writes a `Detection` event to `pano.log`. Its `Response` says what the service
did. Without `EnforceDetectionActions` in `panoptes.config`, `kill` and `quarantine` rules only
alert. See the [service README](../service/README.md#configuration) for what is never killed.

## Rules

| File | Rules |
|------|-------|
| `injection.yaml` | `remote_thread_injection`, `remote_apc_injection`, `process_hollowing`, `remote_rwx_allocation`, `mapped_section_injection`, `remote_target_unresolved` |
| `hollowing.yaml` | `peb_image_base_overwrite`, `unmap_then_write_hollowing`, `remote_image_unmapped`, `early_bird_apc` |
| `evasion.yaml` | `being_debugged_tampered`, `process_protection_tamper`, `lsass_peb_read`, `remote_pe_made_executable` |
| `commandline.yaml` | `shadow_copy_deletion`, `encoded_powershell`, `defender_disabled`, `event_log_cleared` |
| `registry.yaml` | Persistence: `registry_run_key_persistence`, `registry_winlogon_persistence`, `registry_ifeo_debugger`, `registry_silent_process_exit`, `registry_appinit_dlls`, `registry_com_hijack`, `registry_service_written_directly`, `registry_persistence_key_permissions_changed`. Privilege escalation: `registry_uac_bypass`. Credential access: `registry_lsa_package_added`, `registry_lsa_protection_weakened`, `registry_wdigest_enabled`, `registry_credential_hive_saved`, `registry_credential_read`, `registry_credential_hive_loaded`. Defense evasion: `registry_defender_disabled`, `registry_defender_exclusion_added`, `registry_security_service_disabled`, `registry_panoptes_tampered`, `registry_hive_replaced` |
| `lolbas.yaml` | 187 `lolbas_<binary>_<n>` rules, generated (see below) |

Rule names must be unique across files.

### LOLBAS rules

`rules/lolbas.yaml` is generated from the [LOLBAS](https://lolbas-project.github.io) catalog by
`tools/lolbas`. Don't edit it by hand. Regenerate it when the catalog changes:

```powershell
go run ./tools/lolbas            # downloads the catalog and rewrites rules/lolbas.yaml
go run ./tools/lolbas -list      # prints each rule's binary and tokens instead, for review
```

Each LOLBAS example command becomes a `ProcessCreated` rule. The process image must be the
binary, and the command line must contain the command's distinctive tokens: flags (matched with
`-` or `/`), verbs, and DLL names with their entry points. Paths, placeholders and example
values are left out. The generator skips three kinds of command:

- commands that are only the binary and a file, since they'd fire on every normal run;
- commands with fewer than three tokens for binaries in everyday use (`cmd`, `msiexec`, `csc`,
  `dotnet`, `regsvr32`, ...). A named DLL with its entry point still counts, except calls
  Windows makes constantly, such as `shell32.dll,Control_RunDLL`;
- scripts, which run under a host process the rule can't name.

All LOLBAS rules only alert. `test/lolbas_test.go` checks real technique command lines against
everyday ones. The catalog is GPL-3.0, the same license as Panoptes.

`test/rules_test.go` runs every shipped rule against events
that should and should not match. Add a case there when adding a rule.
