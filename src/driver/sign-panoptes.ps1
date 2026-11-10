# Signs files with the Panoptes test-signing certificate, the self-signed "CN=Panoptes"
# certificate in the current user's PanoptesCertStore. The driver build signs Panoptes.sys
# with it, and .vscode/package-target.ps1 signs the hook DLLs with the same certificate.
#
# One certificate is reused rather than a new one made on every build, and it is always
# selected by thumbprint: with several CN=Panoptes certificates in the store, "signtool /a"
# picks one of them, which need not be the one exported as Panoptes.cer.
#
#   -Files       Files to sign
#   -Thumbprint  Sign with this certificate. By default the newest CN=Panoptes certificate with
#                a private key, created with makecert when there is none
#   -ExportCer   Also write the signing certificate to this .cer file
#   -ToolsDir    Windows SDK bin\<version>\x64 folder holding signtool.exe and makecert.exe.
#                By default the newest installed SDK
param(
    [Parameter(Mandatory)][string[]]$Files,
    [string]$Thumbprint,
    [string]$ExportCer,
    [string]$ToolsDir
)

$ErrorActionPreference = 'Stop'
$storeName = 'PanoptesCertStore'
$subject = 'CN=Panoptes'

if (-not $ToolsDir) {
    $signtool = Get-ChildItem 'C:\Program Files (x86)\Windows Kits\10\bin\*\x64\signtool.exe' -ErrorAction SilentlyContinue |
        Sort-Object { [version]$_.Directory.Parent.Name } -Descending -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if (-not $signtool) {
        Write-Host 'signtool.exe not found. Install the Windows SDK or pass -ToolsDir.' -ForegroundColor Red
        exit 1
    }
    $ToolsDir = $signtool.DirectoryName
}
$signtoolPath = Join-Path $ToolsDir 'signtool.exe'
$makecertPath = Join-Path $ToolsDir 'makecert.exe'

function Get-PanoptesCertificates {
    $path = "Cert:\CurrentUser\$storeName"
    if (-not (Test-Path $path)) { return @() }
    Get-ChildItem $path | Where-Object { $_.Subject -eq $subject -and $_.HasPrivateKey }
}

if ($Thumbprint) {
    $cert = Get-PanoptesCertificates | Where-Object Thumbprint -eq $Thumbprint
    if (-not $cert) {
        Write-Host "Certificate $Thumbprint is not in CurrentUser\$storeName (with its private key)." -ForegroundColor Red
        exit 1
    }
}
else {
    $cert = Get-PanoptesCertificates | Sort-Object NotBefore, Thumbprint -Descending | Select-Object -First 1
    if (-not $cert) {
        Write-Host "Creating the $subject signing certificate in CurrentUser\$storeName"
        & $makecertPath -r -pe -ss $storeName -n $subject | Out-Host
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        $cert = Get-PanoptesCertificates | Sort-Object NotBefore, Thumbprint -Descending | Select-Object -First 1
    }
}

Write-Host "Signing with $subject ($($cert.Thumbprint))"
& $signtoolPath sign /sha1 $cert.Thumbprint /s $storeName /fd sha256 /t http://timestamp.digicert.com /v @Files | Out-Host
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

if ($ExportCer) {
    Export-Certificate -Cert $cert -FilePath $ExportCer -Type CERT | Out-Null
    Write-Host "Exported the certificate to $ExportCer"
}
exit 0
