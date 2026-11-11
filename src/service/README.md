# PanoptesService

The service is the center of Panoptes. It collects events from the [driver](../driver/README.md) and the [hook DLL](../hook/README.md), writes the log, sends files to the [containers](../container/README.md) to scan, and acts on detections. See the [main README](../../README.md) for how the components fit together.

## What it does

- **Driver events:** opens `\\.\Panoptes`, keeps several `IOCTL_PANOPTES_GET_EVENT` requests pending, and logs each event the driver completes them with. At startup it sends the driver the `DontInject` and `FileEvents` settings.
- **Hook events:** runs a real-time ETW session (`Panoptes Hook Trace`) for the hook DLL's `Panoptes.Hook` provider and logs its events alongside the driver's. A session left behind by a previous run is replaced.
- **Scanning:** created and modified files are scanned once their writes settle, and only if they are PE files. Paths in `Exclusions` are skipped. Scan results are kept in a RocksDB database (`C:\ProgramData\Panoptes\database`) keyed by the file's MD5 hash, so a file already scanned is answered from the database instead of being scanned again.
- **Containers:** starts a container for each extensibility module and talks to it over gRPC (`proto/src/panoptes.proto`). The containers run in a job object, so they end with the service even if it is killed.
- **Detections:** shows a tray notification and, when `QuarantineMaliciousFiles` is set, moves the file to `C:\ProgramData\Panoptes\Quarantine`.
- **Behavioral detector:** starts [`PanoptesDetector.exe`](../detector/README.md) from its own folder (in the containers' job) when it is there. It streams every logged event to the detector over `SubscribeEvents`. When the detector calls `ReportDetection`, the service logs a `Detection` event with a `Response`, shows a tray notification, and, with `EnforceDetectionActions`, kills or quarantines. Both RPCs only accept calls from `PanoptesDetector.exe` in the service's folder. The service finds the caller from the TCP connection, because the server has no credentials.

The service publishes its gRPC port under `SOFTWARE\Panoptes` in the registry (`HKLM`; `HKCU` in Debug builds, which run unelevated), where the containers and scanners find it.

## Logs

Every event is written to `C:\ProgramData\Panoptes\Logs\pano.log` as one JSON object per line (NDJSON), with `Event` as the first key. The log rotates at 5 MB to `pano1.log`, `pano2.log`, and so on (old files are kept); after a restart the service continues in the newest one. Paths in `LogExclusions` are not logged but are still scanned. Debug builds also echo each event to the console.

Hook events arrive about a second after they happen, often after the process has exited. Their `Image` and `TargetImage` therefore come from the driver's `ProcessCreated` for that PID: the service remembers each image until a minute after the process exits, and picks the process that had that PID at the event's time. Processes that started before the service are looked up from Windows instead, and are empty if they have already exited.

The [log viewer](../../tools/README.md) in `tools/` browses a log by process.

## Running

Run `PanoptesService.exe` as Administrator, with the driver already running.

| Flag | Effect |
|------|--------|
| `--driver` | Debug builds only: use the driver. Without it, Debug builds skip the driver so the service can be debugged unelevated. Release builds always need it. |
| `--stop` | Asks a running service to shut down cleanly and waits (up to 15 seconds) for it to exit. |
| `--wait` | Pauses before any initialization, so a debugger can attach first. |

## Configuration

The service reads `panoptes.config`, a JSON file, from its folder. Check it with the [linter](../linter/README.md) before deploying.

| Key | Type | Description |
|-----|------|-------------|
| `Exclusions` | Path patterns | Files that are not scanned |
| `LogExclusions` | Path patterns (`*` wildcards) | Events for these paths are not logged; the files are still scanned. Named pipes and mailslots are matched in the form programs open them (`\\.\pipe\name`). |
| `DontInject` | File names or full paths (`*`, `?` wildcards) | Processes the hook DLL is not injected into, e.g. `msedge.exe`, `C:\Tools\app.exe` or `C:\Tools\*` (`*` also matches subfolders) |
| `FileEvents` | List | The file system event groups the driver reports: `Create`, `Write`, `DeleteRename`, `PipeMailslot`, `Security`, `ExtendedAttributes` |
| `QuarantineMaliciousFiles` | Boolean | Move detected files to the quarantine folder |
| `EnforceDetectionActions` | Boolean (default `false`) | Carry out the `kill` and `quarantine` actions of detector rules. When off, those detections are logged and notified only. Kills are always refused for PID 0 and 4, the service, its containers and detector, critical processes, and a process ID reused since the match. Quarantine skips paths in `Exclusions`. |

The default configuration is [`assets/panoptes.config`](../../assets/panoptes.config).
