$ErrorActionPreference = 'Stop'
Set-Location (Resolve-Path (Join-Path $PSScriptRoot '..\..'))
Write-Host 'Training API ONLY on http://127.0.0.1:8765/docs'
uv run --extra dev uvicorn labs.independent_api.app:app --host 127.0.0.1 --port 8765
