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

## PanoptesML

An optional module (`PanoptesML/`, installed as `ext\PanoptesML.dll`) that scores static PE files with an [ONNX](https://onnx.ai) model. The file is only read: its features come from its bytes and headers, and it is never loaded or run.

- Computes 278 features per file: a byte histogram, overall and per-section entropy, header fields (32/64-bit, DLL, subsystem), import counts, which data directories are present, writable and executable sections, an entry point outside executable code, and the overlay size. The layout is `PanoMlFeature` in [`PanoptesML/include/PanoptesML.h`](PanoptesML/include/PanoptesML.h), version `PANO_ML_FEATURE_VERSION`.
- Only PE files get a verdict: the model is trained on PE files (EMBER2024's Win32, Win64 and .NET records), so its score for anything else means nothing. Other files are reported with `is_pe` false, `malicious` false and an `error` saying so. Files over 256 MB are skipped.
- Runs its model with [ONNX Runtime](https://onnxruntime.ai), on one thread. The model is built into the DLL, encrypted (see below), or else loaded from `model.onnx` in its own folder (`ext`). It is loaded on the first scan and kept.
- Reports `ml_scan` to the service for every file it's sent: `score` (0 to 1), `threshold` (0.5), `malicious`, `model`, `feature_version`, `is_pe`, and `error` when the file wasn't scored (not a PE, unreadable, too large, or the model failed to load). The service treats `malicious` like a YARA match: it notifies, and quarantines when that's enabled. Reporting even the files it couldn't score lets the service and `PanoptesScanCLI` know the ML scan is done.

### The model

PanoptesML doesn't ship a model, so it needs one before it can score files. Put it at `assets/ml/model.onnx`, and the build encrypts it into the DLL. Without it, every scan fails with "cannot load model.onnx". The model must:

- take one float tensor of shape `[N, 278]` (N may be dynamic), in the order of `PanoMlFeature`;
- output a float tensor whose last value is the malicious probability: `[N, 1]`, or `[N, 2]` for (benign, malicious). A scikit-learn classifier exported with `skl2onnx` works if `zipmap` is disabled (`options={"zipmap": False}`). Its label output is skipped, and the probabilities are read.

To try the pipeline before a real model exists, `PanoptesML/tools/maketestmodel` (Go) writes a placeholder (a fixed logistic regression on four features, not a detector). It encodes the ONNX protobuf itself, so it needs only Go:

```powershell
cd src\extensibility\PanoptesML\tools
go run ./maketestmodel ../../../../assets/ml/model.onnx
```

The output goes to `assets/ml/model.onnx`, where the build picks it up; it only needs regenerating after the generator changes.

A model trained on one feature version doesn't work with another. Changing the features means raising `PANO_ML_FEATURE_VERSION` and retraining.

#### The embedded, encrypted model

By default no `model.onnx` is shipped. When PanoptesML is built, `tools/sealmodel` (Go) encrypts `assets/ml/model.onnx` with AES-256-GCM under a new random key. The result is linked into `PanoptesML.dll` as the RCDATA resource `PANOML_MODEL`, and the key is compiled in from a generated header (`model_key.h`, in the build folder only). At the first scan, the DLL decrypts the model in memory with Windows CNG (`src/model_seal.cpp`), hands it to ONNX Runtime and wipes the decrypted copy. Results report the model as `embedded model.onnx`.

- The model can't be copied out of the install folder or opened in a model viewer, and the plain model doesn't appear in the DLL.
- GCM authenticates it: a DLL whose model was modified fails with "authentication failed; the DLL's model was modified or corrupted" instead of scoring with it.
- This hides the model; it doesn't make it secret. The key is in the DLL (stored as two masked halves, so it isn't one searchable run of bytes), and the plain model is in the container's memory while it loads. Someone who reverse-engineers the DLL or reads that memory can recover it.
- The build needs Go for this. `-DPANOPTES_ML_EMBED_MODEL=OFF` skips it: `model.onnx` is then copied next to the DLL unencrypted, as before, and the package includes it.
- A DLL without an embedded model loads `model.onnx` from its folder. A DLL with one ignores any `model.onnx`, and the build deletes one left next to it, so it isn't packaged by mistake.

### Training on EMBER2024

`PanoptesML/tools/embertrain` (Go) trains a model on [EMBER2024](https://huggingface.co/datasets/joyce8/EMBER2024) (Apache-2.0). It is plain Go without cgo, so it builds into one static binary for a NAS or any Linux machine with the data:

```powershell
cd src\extensibility\PanoptesML\tools
$env:GOOS = "linux"; $env:GOARCH = "amd64"; $env:CGO_ENABLED = "0"   # arm64 for ARM NASes
go build -trimpath -o embertrain ./embertrain
```

On that machine:

```sh
cd /volume1/ember
./embertrain train -data Win64_train/ Win32_train/ Dot_Net_train/ Win64_test/ Win32_test/ Dot_Net_test/ -out model.onnx
```

- **train** takes EMBER's folders directly with `-data`: every `.jsonl` file in them (any number of folders, searched recursively; extract the zips first, they are not read). Flags and folders can come in any order. The first run computes PanoptesML's features from the JSONL into `-cache` (by default a `data` folder next to `-out`), and later runs reuse them. That conversion is the slow part, and training reads the data once per epoch, so it's done once rather than each pass. It's redone when a source file changes or is added, when `-types` changes, or with `-reconvert`. An interrupted conversion is never reused. A `-data` folder without any `.jsonl` is taken as an already converted one.
- The test folders are optional: without them, only the validation results (the last training weeks) are reported.
- The conversion keeps the Win32, Win64 and .NET records (`-types`). It writes `train.pmlf`, `test.pmlf` and `challenge.pmlf`, at about 1.1 KB a record, plus `sources.json`, which lists what they came from. A file's split comes from its path: `test` or `challenge` in its name, its folders, or the folder given; anything else is train. Folders named otherwise can be given with `-train`, `-test` or `-challenge` instead. It ends with counts of what it kept and skipped, and of each `file_type` it saw. `embertrain convert -out <data> <folders>` runs only this step. `train -data <data>` with only that converted folder trains on what's there.
- Training fits a neural network (278 → 128 → 64 → 1, `-hidden`) and streams `train.pmlf` from disk each epoch, so it needs little memory. The last training weeks (`-valid-from-week`, default 46 of 0-51) are held out: training stops when their AUC stops improving, and the threshold is set on them for `-target-fpr` (1% by default). It then reports detection and false-positive rates on the test and challenge sets. `-sample 0.05` trains on 5% of the records for a quick first run.
- The model takes the raw features: the standardization is folded into its first layer. By default the threshold is baked in (`-bake-threshold`): the output is shifted so the chosen threshold scores 0.5, PanoptesML's fixed `PANO_ML_THRESHOLD`. The scores are then a ranking rather than probabilities. The threshold, target false-positive rate and metrics are stored in the model's metadata (`panoptes.*`).
- Put the result at `assets/ml/model.onnx` and rebuild PanoptesML.
- **eval** scores EMBER records with a model: `embertrain eval -model model.onnx -data Win64_test/`. It reports the AUC; what PanoptesML's 0.5 threshold detects and flags; the detection rate at 0.1%, 1% and 5% false positives; and the same by week, to show how the model ages. It runs the model in Go (`internal/onnx`, which supports the operators embertrain exports). `eval -check <PanoptesMLQuery -json output>` confirms that this matches the DLL's scores for the same features.

How EMBER's records map to the features is in `embertrain/features.go`, beside the C++ it must match (`src/pe_features.cpp`). One feature can't be reproduced exactly: when a file's entry point is in no section, EMBER names the first executable section instead, so `entry_outside_executable` is 0 in training where PanoptesML computes 1. Section entropy and overlay can also differ slightly, because `pefile` aligns section offsets and our parser doesn't. To compare the two for the same files, use `embertrain inspect <file.jsonl>` and `PanoptesMLQuery -json`, which both print one JSON line per file with its features.

### Building

PanoptesML is off by default. Turn it on with `-DBUILD_ML=ON`:

```powershell
cmake --preset default -DBUILD_ML=ON
cmake --build build/default --config Debug --target PanoptesML
```

ONNX Runtime needs a newer protobuf than the gRPC the rest of Panoptes is pinned to. PanoptesML therefore has its own vcpkg manifest (`PanoptesML/vcpkg.json` and `vcpkg-configuration.json`, with a newer baseline) and builds as a separate sub-build with its own `vcpkg_installed`. None of its packages reach the other components. The first build compiles ONNX Runtime and gRPC from source, which takes a long while; later builds come from the vcpkg binary cache.

`PanoptesML/vcpkg-overlays/onnx` overrides vcpkg's `onnx` port for this build only. It's the same port with `ONNX_DISABLE_STATIC_REGISTRATION=ON` added, which ONNX Runtime requires; without it, every model fails to load with a `SchemasRegisterer` assertion.

The service starts a container for PanoptesML only when `ext\PanoptesML.dll` exists.

### Testing with PanoptesMLQuery

`PanoptesMLQuery.exe` (`PanoptesML/tools/mlquery`, Go) scores files with the DLL directly, without the service or a container. It's built into `bin\<config>` with PanoptesML when Go is installed, and the TargetPackage includes it next to `ext\`.

```powershell
PanoptesMLQuery.exe C:\Windows\System32\notepad.exe       # score and verdict
PanoptesMLQuery.exe -features C:\samples\sample.exe       # plus the named features
PanoptesMLQuery.exe -json -r C:\samples > features.jsonl  # one JSON line per file, every feature
```

It loads `ext\PanoptesML.dll` from next to itself (or `-dll <path>`), and the DLL uses its embedded model (or `model.onnx` from its own folder). It exits 1 if any file couldn't be scored. With `-json`, each line holds the file's 278 features in model order, so its output can also be used to build a training set.

The tool calls the DLL's test exports, `PanoMlScoreFile` and `PanoMlFeatureName` (declared in `PanoptesML.h`). They run the same feature extraction and model as a container scan, but return the result instead of sending it to the service. The result struct, `PanoMlTestResult`, has a fixed layout that `main.go` repeats, so the tool and the DLL must be built from the same sources; a mismatch is reported rather than read.

## Writing a module

A module exports three functions, declared in [`core/ExtensibilityCore.h`](core/ExtensibilityCore.h):

| Export | Signature | Called |
|--------|-----------|--------|
| `PanoBind` | `int PanoBind(int ContainerPort)` | Once the container's gRPC server is running, with the service's port from the registry. The module registers with the service (`Hello`); the container retries with backoff until it has. |
| `PanoEntry` | `bool PanoEntry(PeScan* data)` | For each file to scan; `PeScan` holds the file's path and hash |
| `PanoUnbind` | `bool PanoUnbind()` | Once, when the container shuts down |

The module reports its results to the service over gRPC (`ScanResults`), as `PanoptesYara` does in `src/service_client_yara.cpp`. To have the service start a container for a new module, add it to `BuildContainerCommandLine` and `StartContainers` in `src/service/src/containers.cpp`.
