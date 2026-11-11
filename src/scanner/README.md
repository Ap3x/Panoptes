# Scanners

Two tools that ask a running [`PanoptesService`](../service/README.md) to scan a file. They find the service through the gRPC port it publishes under `SOFTWARE\Panoptes` in the registry, and queue the scan with `QueuePeScan`; the result is logged and, for a detection, shown as a tray notification like any other scan. See the [main README](../../README.md) for how the components fit together.

| Tool | Usage |
|------|-------|
| `PanoptesScan.exe` | `PanoptesScan.exe <file>`. Behind the **Scan with Panoptes** right-click menu entry the installer adds (installed to `C:\Program Files\Panoptes\tools`). |
| `PanoptesScanCLI.exe` | `PanoptesScanCLI.exe -file <file>`. For the command line and scripts. |

Files in the configuration's `Exclusions` are not scanned, and a file already scanned is answered from the service's database.
