# Prepare local Ollama for AchillesAPI. The initial model download needs Internet.
# Run with -DownloadModel if the base model is not installed yet.
param([switch]$DownloadModel)
$ErrorActionPreference = 'Stop'
$Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
if (-not (Get-Command ollama -ErrorAction SilentlyContinue)) {
    throw 'Ollama not found. Install Ollama for Windows and reopen PowerShell.'
}
try {
    $response = Invoke-WebRequest -Uri 'http://127.0.0.1:11434/api/tags' -TimeoutSec 2 -UseBasicParsing
    Write-Host 'Ollama already running.'
} catch {
    Write-Host 'Starting local Ollama service...'
    $exe = (Get-Command ollama).Source
    Start-Process -FilePath $exe -ArgumentList 'serve' -WindowStyle Hidden | Out-Null
    $ready = $false
    for ($i = 0; $i -lt 25; $i++) {
        Start-Sleep -Seconds 1
        try {
            Invoke-WebRequest 'http://127.0.0.1:11434/api/tags' -TimeoutSec 2 -UseBasicParsing | Out-Null
            $ready = $true
            break
        } catch { }
    }
    if (-not $ready) { throw 'Ollama did not respond at 127.0.0.1:11434.' }
}
$installed = & ollama list
if ($LASTEXITCODE -ne 0) { throw 'Unable to list Ollama models.' }
if (-not ($installed -match 'llama3\.2:3b')) {
    if (-not $DownloadModel) {
        throw 'Missing llama3.2:3b. Run this script with -DownloadModel (requires Internet).' 
    }
    Write-Host 'Downloading base model llama3.2:3b (first run only)...'
    & ollama pull llama3.2:3b
    if ($LASTEXITCODE -ne 0) { throw 'Model download failed.' }
}
Write-Host 'Creating local AchillesAPI model from deployment/Modelfile...'
& ollama create achilles-local -f (Join-Path $Root 'deployment\Modelfile')
if ($LASTEXITCODE -ne 0) { throw 'Local model creation failed.' }
Write-Host 'AI ready: achilles-local on http://127.0.0.1:11434'
