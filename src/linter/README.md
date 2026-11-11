# PanoptesLinter

Checks a Panoptes configuration file before it is deployed: that it is valid JSON, has no unknown keys, has every required key, and that every setting the [service](../service/README.md#configuration) reads is valid (for example, that `FileEvents` only names known groups and `DontInject` entries are file names or full paths without wildcards). It prints `[+] Panoptes Configuration is valid`, or the problems it found. See the [main README](../../README.md) for how the components fit together.

```powershell
.\PanoptesLinter.exe panoptes.config
```

Its tests are in `test/` (`Test_Linter.exe`, built with `BUILD_TESTS`).
