# Waits until PanoptesService is listening on the gRPC port it publishes in
# HKCU\SOFTWARE\Panoptes\SRV_PORT (Debug builds), then gives the Yara container a few seconds
# to bind to the service. Used as a preLaunchTask for the scanner debug configs.
param(
    [int]$TimeoutSeconds = 60,
    [int]$SettleSeconds = 5
)

$deadline = (Get-Date).AddSeconds($TimeoutSeconds)
Write-Host "Waiting for PanoptesService..."

while ((Get-Date) -lt $deadline) {
    $service = Get-Process -Name PanoptesService -ErrorAction SilentlyContinue
    $port = (Get-ItemProperty -Path 'HKCU:\SOFTWARE\Panoptes' -Name SRV_PORT -ErrorAction SilentlyContinue).SRV_PORT

    if ($service -and $port) {
        $listening = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue |
            Where-Object { $service.Id -contains $_.OwningProcess }
        if ($listening) {
            Write-Host "PanoptesService is listening on port $port. Waiting $SettleSeconds seconds for the container to bind..."
            Start-Sleep -Seconds $SettleSeconds
            exit 0
        }
    }

    Start-Sleep -Milliseconds 500
}

Write-Host "Timed out after $TimeoutSeconds seconds waiting for PanoptesService. Check that the service started and did not exit with an error."
exit 1
