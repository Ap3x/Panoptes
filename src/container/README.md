# PanoptesContainer

A container is a separate process that hosts one [extensibility module](../extensibility/README.md) (a DLL that scans files) and connects it to [`PanoptesService`](../service/README.md) over gRPC. Running each module in its own process isolates faults: a module that crashes or hangs takes down its container, not the service. See the [main README](../../README.md) for how the components fit together.

## How it works

1. The service starts one container per module, passing the module's path: `PanoptesContainer.exe "<folder>\ext\PanoptesYara.dll"`.
2. The container changes to its own folder (modules load their data, such as `rules.pkg`, relative to it) and loads the module.
3. It starts a gRPC server for scan requests (`PEScan`).
4. It reads the service's gRPC port from `SOFTWARE\Panoptes` in the registry and calls the module's `PanoBind` with it, retrying with backoff until the module has registered with the service (`Hello`).
5. Each scan request is passed to the module's `PanoEntry`; the module reports the result to the service (`ScanResults`).
6. On shutdown it calls the module's `PanoUnbind`.

The service runs its containers in a job object, so they end with it. A container can also be started by hand, e.g. to debug a module:

```powershell
.\PanoptesContainer.exe "C:\Program Files\Panoptes\ext\PanoptesYara.dll"
```
