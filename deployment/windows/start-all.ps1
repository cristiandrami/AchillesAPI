# Opens the lab in a new terminal, sets up optional local AI, then runs the demo.
param([switch]$WithAI, [switch]$DownloadModel, [switch]$IncludeLegacyChecks, [switch]$RunWriteDemo)
$ErrorActionPreference = 'Stop'
$Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$LabScript = Join-Path $PSScriptRoot 'start-lab.ps1'
$alreadyRunning = $false
try {
    $existing = Invoke-RestMethod 'http://127.0.0.1:8000/health' -TimeoutSec 2
    if ($existing.service -eq 'achillesapi-full-lab') {
        Write-Host 'Training lab is already running on port 8000.'
        $alreadyRunning = $true
    } else {
        throw 'Port 8000 is already used by another application. Stop it before starting this lab.'
    }
} catch {
    if ($_.Exception.Message -like '*already used by another*') { throw }
}
if (-not $alreadyRunning) {
    Write-Host 'Opening the vulnerable laboratory in a NEW PowerShell window...'
    $escaped = $LabScript.Replace("'", "''")
    $command = "& '$escaped'"
    Start-Process -FilePath 'powershell.exe' -ArgumentList @('-NoExit','-ExecutionPolicy','Bypass','-Command',"`"$command`"")
}
Write-Host 'Waiting for local API health check...'
$ready = $false
for ($i=0; $i -lt 90; $i++) {
    Start-Sleep -Seconds 2
    try {
        $health = Invoke-RestMethod 'http://127.0.0.1:8000/health' -TimeoutSec 2
        if ($health.status -eq 'ok' -and $health.service -eq 'achillesapi-full-lab') { $ready = $true; break }
    } catch { }
}
if (-not $ready) { throw 'The lab did not start. Check the new PowerShell window.' }
if ($WithAI) {
    & (Join-Path $PSScriptRoot 'start-ai.ps1') -DownloadModel:$DownloadModel
}
& (Join-Path $PSScriptRoot 'run-lab-demo.ps1') -WithAI:$WithAI -IncludeLegacyChecks:$IncludeLegacyChecks -RunWriteDemo:$RunWriteDemo
