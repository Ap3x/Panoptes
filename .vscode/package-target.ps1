# Collects the Debug build outputs needed to run Panoptes on a separate KDNET target
# machine. PDBs are left out on purpose: the debugger on the host loads symbols from
# bin\Debug, so only the binaries need to go to the target.
#
# Package layout:
#   Panoptes\                 Service working folder (service, container, Yara, scanners)
#   Program Files\Panoptes\   Hook DLLs; the driver injects them from C:\Program Files\Panoptes
#   Program Files\Panoptes\tests\
#                             Hook tests (x64 and x86), when the build has them (BUILD_TESTS)
#   driver\                   Driver package (sys, inf, cat, cer)
#   install.ps1               Run elevated on the target to put everything in place
#   run-hook-tests.ps1        Runs the installed hook tests and summarizes the results
#
# The hook tests are installed under the hook DLL folder because each test loads the DLL from
# the folder above its own. That is the file the driver injects, so with the driver running the
# test's LoadLibrary reuses the injected copy instead of placing a second set of hooks.
#
# Every packaged executable and DLL is signed with the certificate that signed Panoptes.sys,
# so install.ps1 trusting Panoptes.cer covers all of them. -ToolsDir is the Windows SDK bin\<version>\x64
# folder with signtool.exe (by default the newest installed SDK)
param(
    [string]$BuildDir = (Join-Path $PSScriptRoot '..\bin\Debug'),
    [string]$OutDir = (Join-Path $PSScriptRoot '..\bin\TargetPackage'),
    [string]$ToolsDir,
    [switch]$Zip
)

$ErrorActionPreference = 'Stop'
$BuildDir = (Resolve-Path $BuildDir).Path
$marker = '.panoptes-package'

$layout = [ordered]@{
    'Panoptes' = @(
        'PanoptesService.exe',
        'Resources.dll',
        'panoptes.config',
        'PanoptesContainer.exe',
        'rules.pkg',
        'ext\PanoptesYara.dll',
        'PanoptesScan.exe',
        'PanoptesScanCLI.exe'
    )
    'Program Files\Panoptes' = @(
        'PanoptesDLLx64.dll',
        'PanoptesDLLx86.dll'
    )
    'driver' = @(
        'driver\Panoptes.sys',
        'driver\Panoptes.inf',
        'driver\panoptes.cat',
        'driver\Panoptes.cer'
    )
}

# Check everything exists before touching the output folder
$missing = foreach ($files in $layout.Values) {
    foreach ($file in $files) {
        if (-not (Test-Path (Join-Path $BuildDir $file))) { $file }
    }
}
if ($missing) {
    Write-Host "Missing from ${BuildDir}:" -ForegroundColor Red
    $missing | ForEach-Object { Write-Host "  $_" }
    Write-Host 'Build the Debug configuration (including the driver and hook DLLs) first.'
    exit 1
}

# The hook tests are optional: they are only built with BUILD_TESTS. Each test is built for
# both architectures (Test_<API>x64.exe and Test_<API>x86.exe); the Yara and linter tests in the
# same folder have no architecture suffix and are not packaged
$hookTests = @(Get-ChildItem (Join-Path $BuildDir 'tests') -Filter 'Test_*.exe' -ErrorAction SilentlyContinue |
    Where-Object { $_.BaseName -match '^Test_.+(x64|x86)$' } |
    ForEach-Object { "tests\$($_.Name)" } |
    Sort-Object)
if ($hookTests) {
    $unpaired = foreach ($test in $hookTests) {
        $other = if ($test -match 'x64\.exe$') { $test -replace 'x64\.exe$', 'x86.exe' } else { $test -replace 'x86\.exe$', 'x64.exe' }
        if ($hookTests -notcontains $other) { $other }
    }
    if ($unpaired) {
        Write-Host "Hook tests missing from ${BuildDir}:" -ForegroundColor Red
        $unpaired | ForEach-Object { Write-Host "  $_" }
        Write-Host 'Rebuild with BUILD_TESTS so both architectures are built.'
        exit 1
    }
    $layout['Program Files\Panoptes\tests'] = $hookTests
}
else {
    Write-Host 'No hook tests in the build (configure with BUILD_TESTS to include them); packaging without them.' -ForegroundColor Yellow
}

# Only clear a folder this script created, never an arbitrary path passed as -OutDir
if (Test-Path $OutDir) {
    if (-not (Test-Path (Join-Path $OutDir $marker))) {
        Write-Host "$OutDir exists and was not created by this script. Choose another -OutDir." -ForegroundColor Red
        exit 1
    }
    Remove-Item $OutDir -Recurse -Force
}
New-Item -ItemType Directory -Path $OutDir | Out-Null
$OutDir = (Resolve-Path $OutDir).Path
New-Item -ItemType File -Path (Join-Path $OutDir $marker) | Out-Null

foreach ($destination in $layout.Keys) {
    foreach ($file in $layout[$destination]) {
        # Keep the ext\ subfolder inside the service folder; flatten driver\ into its own folder
        $relative = if ($destination -eq 'Panoptes') { $file } else { Split-Path $file -Leaf }
        $target = Join-Path (Join-Path $OutDir $destination) $relative
        New-Item -ItemType Directory -Path (Split-Path $target) -Force | Out-Null
        Copy-Item (Join-Path $BuildDir $file) $target
    }
}

# The certificate install.ps1 trusts must be the one that signed the driver
$driverSigner = (Get-AuthenticodeSignature (Join-Path $OutDir 'driver\Panoptes.sys')).SignerCertificate
if (-not $driverSigner) {
    Write-Host 'driver\Panoptes.sys is not signed. Rebuild the driver.' -ForegroundColor Red
    exit 1
}
$packagedCer = New-Object Security.Cryptography.X509Certificates.X509Certificate2 (Join-Path $OutDir 'driver\Panoptes.cer')
if ($packagedCer.Thumbprint -ne $driverSigner.Thumbprint) {
    Write-Host "driver\Panoptes.cer ($($packagedCer.Thumbprint)) is not the certificate that signed Panoptes.sys ($($driverSigner.Thumbprint)). Rebuild the driver." -ForegroundColor Red
    exit 1
}

# Sign every packaged executable and DLL (service, container, Yara, scanners, Resources and
# the hook DLLs) with the driver's certificate. The packaged copies are signed, leaving the
# build outputs as they are
$binaries = Get-ChildItem $OutDir -Recurse -Include *.exe, *.dll | ForEach-Object FullName
$signArgs = @{ Files = $binaries; Thumbprint = $driverSigner.Thumbprint }
if ($ToolsDir) { $signArgs.ToolsDir = $ToolsDir }
& (Join-Path $PSScriptRoot '..\src\driver\sign-panoptes.ps1') @signArgs
if ($LASTEXITCODE -ne 0) {
    Write-Host 'Signing the packaged binaries failed.' -ForegroundColor Red
    exit 1
}

$install = @'
# Run elevated on the target. Installs the Panoptes driver and hook DLLs from this package.
# Re-running it replaces an installed copy: the running driver and Panoptes processes are
# stopped first. Pass -StopOnly to just stop them.
param([switch]$StopOnly)

$ErrorActionPreference = 'Stop'
$package = $PSScriptRoot

$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host 'Run this script from an elevated PowerShell.' -ForegroundColor Red
    exit 1
}

# The driver service state (RUNNING, STOPPED, STOP_PENDING, ...), or $null if it is not installed
function Get-DriverState {
    $output = sc.exe query Panoptes
    if ($LASTEXITCODE -ne 0) { return $null }
    if (($output | Out-String) -match 'STATE\s+:\s+\d+\s+(\w+)') { return $Matches[1] }
    return $null
}

# The service keeps requests pending on \\.\Panoptes, and the driver cannot unload while
# that handle is open, so the user mode side goes first.
#
# The service is asked to shut down cleanly with --stop, which closes its driver handle and
# ETW session and waits (up to 15 seconds) for it to exit. This package's copy of the exe is
# used rather than the running one: an older build without --stop would ignore the flag and
# try to start a second instance. --stop reaches the service through a session-local event,
# so a service in another session, or one too old to have the event, is force-stopped below
if (Get-Process PanoptesService -ErrorAction SilentlyContinue) {
    $serviceExe = Join-Path $package 'Panoptes\PanoptesService.exe'
    Write-Host 'Stopping PanoptesService...'
    $stop = Start-Process $serviceExe -ArgumentList '--stop' -Wait -PassThru -WindowStyle Hidden
    if ($stop.ExitCode -eq 0) {
        Write-Host '  stopped cleanly'
    }
    else {
        Write-Host "  --stop failed (exit code $($stop.ExitCode)); forcing it to stop" -ForegroundColor Yellow
    }
}

# Containers started by hand and the scanners are not owned by the service, and anything
# --stop could not stop is ended here
$remaining = Get-Process PanoptesService, PanoptesContainer, PanoptesScan, PanoptesScanCLI -ErrorAction SilentlyContinue
if ($remaining) {
    $remaining | Stop-Process -Force
    Start-Sleep -Seconds 1

    # A killed service leaves its real-time ETW session behind. The next start replaces it,
    # but there is no reason to leave it running in the meantime
    logman stop 'Panoptes Hook Trace' -ets 2>&1 | Out-Null
}

# fltmc unload is refused (the filter only detaches on a mandatory unload), so stop the service
$state = Get-DriverState
if ($state -and $state -ne 'STOPPED') {
    Write-Host 'Stopping the Panoptes driver...'
    sc.exe stop Panoptes | Out-Null
    for ($i = 0; $i -lt 20 -and (Get-DriverState) -ne 'STOPPED'; $i++) {
        Start-Sleep -Milliseconds 500
    }
    if ((Get-DriverState) -ne 'STOPPED') {
        Write-Host "The Panoptes driver did not stop (state: $(Get-DriverState))." -ForegroundColor Red
        Write-Host 'It is demand start, so it will not load after a reboot. Reboot, then run this again.'
        exit 1
    }
}

if ($StopOnly) {
    Write-Host 'Panoptes is stopped.'
    exit 0
}

if (-not ((bcdedit /enum '{current}') -match 'testsigning\s+Yes')) {
    Write-Host 'Test signing is off. Run "bcdedit /set testsigning on", reboot, then run this again.' -ForegroundColor Yellow
    exit 1
}

# The driver injects the hook DLLs from this fixed path. Processes it injected into keep
# the old DLLs loaded after it stops; a loaded DLL can be renamed but not overwritten, so
# in-use copies are set aside and deleted on a later run once nothing has them loaded
$hookDir = 'C:\Program Files\Panoptes'
New-Item -ItemType Directory -Path $hookDir -Force | Out-Null
foreach ($file in Get-ChildItem (Join-Path $package 'Program Files\Panoptes') -File) {
    $destination = Join-Path $hookDir $file.Name
    Get-ChildItem "$destination.*.old" -ErrorAction SilentlyContinue |
        Remove-Item -Force -ErrorAction SilentlyContinue
    try {
        Copy-Item $file.FullName $destination -Force
    }
    catch {
        Rename-Item $destination "$($file.Name).$(Get-Date -Format yyyyMMddHHmmss).old"
        Copy-Item $file.FullName $destination -Force
    }
}

# The hook tests go next to the hook DLLs: each test loads ..\PanoptesDLL<arch>.dll, which is
# then the file the driver injects. The folder is replaced, so tests removed from the package
# do not linger
$packagedTests = Join-Path $package 'Program Files\Panoptes\tests'
$testDir = Join-Path $hookDir 'tests'
if (Test-Path $packagedTests) {
    if (Test-Path $testDir) {
        Remove-Item $testDir -Recurse -Force
    }
    Copy-Item $packagedTests $testDir -Recurse
    Write-Host "Installed the hook tests to $testDir"
}

# The driver and every packaged executable and DLL are signed with this certificate. Trusting
# it as a root and a trusted publisher on the local machine makes their signatures valid here
$cert = Join-Path $package 'driver\Panoptes.cer'
foreach ($store in 'Root', 'TrustedPublisher') {
    certutil -f -addstore $store $cert | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Failed to add Panoptes.cer to the local machine $store store." -ForegroundColor Red
        exit 1
    }
}
$thumbprint = (New-Object Security.Cryptography.X509Certificates.X509Certificate2 $cert).Thumbprint
Write-Host "Trusted the Panoptes signing certificate ($thumbprint)"

$signed = @(Join-Path $package 'driver\Panoptes.sys') +
    (Get-ChildItem $hookDir -Filter *.dll | ForEach-Object FullName) +
    (Get-ChildItem $testDir -Filter *.exe -ErrorAction SilentlyContinue | ForEach-Object FullName) +
    (Get-ChildItem (Join-Path $package 'Panoptes') -Recurse -Include *.exe, *.dll | ForEach-Object FullName)
foreach ($file in $signed) {
    $signature = Get-AuthenticodeSignature $file
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Thumbprint -ne $thumbprint) {
        Write-Host "  $file : $($signature.Status) ($($signature.StatusMessage))" -ForegroundColor Yellow
    }
    else {
        Write-Host "  $file : signature valid"
    }
}

# Panoptes.inf is a legacy minifilter INF (a plain [DefaultInstall] section), which
# pnputil only stages in the driver store; InstallHinfSection runs DefaultInstall and
# creates the service
$inf = Join-Path $package 'driver\Panoptes.inf'
rundll32.exe setupapi.dll,InstallHinfSection DefaultInstall 132 $inf
Start-Sleep -Seconds 2

sc.exe qc Panoptes | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Host 'The Panoptes driver service was not created. Try right-clicking driver\Panoptes.inf and choosing Install.' -ForegroundColor Red
    exit 1
}
sc.exe start Panoptes

Write-Host ''
Write-Host 'Next, from an elevated prompt in the Panoptes folder:'
Write-Host '  .\PanoptesService.exe --driver'
Write-Host '  .\PanoptesContainer.exe "<this folder>\Panoptes\ext\PanoptesYara.dll"'
if (Test-Path $testDir) {
    Write-Host 'To run the hook tests (no elevation needed):'
    Write-Host '  .\run-hook-tests.ps1'
}
'@
Set-Content -Path (Join-Path $OutDir 'install.ps1') -Value $install -Encoding utf8

if ($hookTests) {
    $runTests = @'
# Runs the hook tests install.ps1 put in C:\Program Files\Panoptes\tests and summarizes the
# results. No elevation is needed. Pass -Arch x64 or -Arch x86 to run one architecture, and
# -Test with part of a name (e.g. NtQueueApcThread) to run matching tests only.
#
# Each test loads C:\Program Files\Panoptes\PanoptesDLL<arch>.dll, the file the driver injects,
# so the results are the same with the driver running or stopped. The tests check the
# "[Panoptes]" messages the hooks send to OutputDebugString, which only Debug builds of the hook
# DLL emit; this package is a Debug build.
#
# To debug a test under WinDbg (locally, or from the KDNET host with the symbols in the host's
# bin\Debug\tests), launch it with --child: that runs the cases directly in the debugged process
# instead of in a child the test debugs itself, so breakpoints in the hooks are hit. Nothing is
# checked against the expected messages in that mode.
param(
    [ValidateSet('all', 'x64', 'x86')]
    [string]$Arch = 'all',
    [string]$Test = ''
)

$testDir = 'C:\Program Files\Panoptes\tests'
if (-not (Test-Path $testDir)) {
    Write-Host "$testDir does not exist. Run install.ps1 from an elevated prompt first." -ForegroundColor Red
    exit 1
}

$tests = Get-ChildItem $testDir -Filter 'Test_*.exe' |
    Where-Object { $_.BaseName -match '(x64|x86)$' -and ($Arch -eq 'all' -or $_.BaseName.EndsWith($Arch)) } |
    Where-Object { $_.BaseName -like "*$Test*" } |
    Sort-Object Name
if (-not $tests) {
    Write-Host 'No hook tests match.' -ForegroundColor Red
    exit 1
}

$driver = sc.exe query Panoptes | Out-String
$driverState = if ($driver -match 'STATE\s+:\s+\d+\s+(\w+)') { $Matches[1] } else { 'not installed' }
Write-Host "Panoptes driver: $driverState"
Write-Host ''

$results = foreach ($exe in $tests) {
    & $exe.FullName | ForEach-Object { Write-Host $_ }
    $passed = $LASTEXITCODE -eq 0
    Write-Host ''
    [pscustomobject]@{ Test = $exe.BaseName; Result = if ($passed) { 'PASS' } else { 'FAIL' } }
}

$results | Format-Table -AutoSize | Out-String | Write-Host
$failed = @($results | Where-Object Result -eq 'FAIL')
if ($failed) {
    Write-Host "$($failed.Count) of $($results.Count) hook tests failed" -ForegroundColor Red
    exit 1
}
Write-Host "All $($results.Count) hook tests passed" -ForegroundColor Green
'@
    Set-Content -Path (Join-Path $OutDir 'run-hook-tests.ps1') -Value $runTests -Encoding utf8
}

if ($Zip) {
    $zipPath = "$OutDir.zip"
    if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
    Compress-Archive -Path (Join-Path $OutDir '*') -DestinationPath $zipPath
    Write-Host "Package written to $zipPath"
}
else {
    Write-Host "Package written to $OutDir"
}
