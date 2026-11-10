# Extensibility Modules

Extensibility modules are DLLs that scan files. Each one runs inside its own [container](../container/README.md) process, which gives:
- fault isolation: a module that crashes takes down its container, not the service,
- easy module addition: a module is a DLL with three exports,
- parallel scanning across modules.

See the [main README](../../README.md) for how the components fit together.

## PanoptesYara

The core detection module (`PanoptesYara/`, installed as `ext\PanoptesYara.dll`).

- Scans files with [VirusTotal/Yara-X](https://github.com/VirusTotal/yara-x) using compiled rules from `rules.pkg` in the container's folder. Custom rules work, as do collections such as [awesome-yara](https://github.com/InQuest/awesome-yara).
- Verifies each scanned file's Authenticode signature (embedded or catalog) with `WinVerifyTrust` and reports the result: signed, trusted and the signer.

Compile your own rules with the Yara-X CLI and place `rules.pkg` in `C:\Program Files\Panoptes\`:

```powershell
yr.exe compile <PATH_TO_YARA_RULES_FOLDER> -o rules.pkg
```

Its tests are in `PanoptesYara/test` (`Test_PanoptesYara.exe`, built with `BUILD_TESTS`).

## Writing a module

A module exports three functions, declared in [`core/ExtensibilityCore.h`](core/ExtensibilityCore.h):

| Export | Signature | Called |
|--------|-----------|--------|
| `PanoBind` | `int PanoBind(int ContainerPort)` | Once the container's gRPC server is running, with the service's port from the registry. The module registers with the service (`Hello`); the container retries with backoff until it has. |
| `PanoEntry` | `bool PanoEntry(PeScan* data)` | For each file to scan; `PeScan` holds the file's path and hash |
| `PanoUnbind` | `bool PanoUnbind()` | Once, when the container shuts down |

The module reports its results to the service over gRPC (`ScanResults`), as `PanoptesYara` does in `src/service_client_yara.cpp`. To have the service start a container for a new module, add it to `BuildContainerCommandLine` in `src/service/src/containers.cpp`.
