# Scanners

Two tools that ask a running [`PanoptesService`](../service/README.md) to scan a file. They find the service through the gRPC port it publishes under `SOFTWARE\Panoptes` in the registry, and queue the scan with `QueuePeScan`; the result is logged and, for a detection, shown as a tray notification like any other scan. See the [main README](../../README.md) for how the components fit together.

| Tool | Usage |
|------|-------|
| `PanoptesScan.exe` | `PanoptesScan.exe <file>`. Behind the **Scan with Panoptes** right-click menu entry the installer adds (installed to `C:\Program Files\Panoptes\tools`). |
| `PanoptesScanCLI.exe` | `PanoptesScanCLI.exe -file <file>`. For the command line and scripts. |

The service sends the file to every extension that's running: [PanoptesYara](../extensibility/README.md#panoptesyara) always, and [PanoptesML](../extensibility/README.md#panoptesml) when it's installed. Each reports separately, and the results are merged into the file's entry in the service's database (`yara_scan`, `ml_scan`). The file is flagged when either finds it malicious. A file already scanned is answered from the database, and any extension whose result the entry lacks still scans it. For example, a file scanned before PanoptesML was installed gets its ML scan. Files in the configuration's `Exclusions` are not scanned.

`PanoptesScanCLI` waits until every extension has reported, then prints the merged result. Use `-timeout <seconds>` to change the wait (120 by default; PanoptesML's first scan loads its model). While it waits, it polls the service; polls start no scans and show no notifications. If an extension didn't report in time, it says which one and exits with 1. `PanoptesScan` doesn't wait: the tray notification reports a detection.
