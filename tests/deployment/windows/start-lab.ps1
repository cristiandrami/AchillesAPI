# Start AchillesAPI's complete training API on the local machine only.
# Run this script from any folder. Ctrl+C stops the server.
$ErrorActionPreference = 'Stop'
$Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location $Root
if (-not (Get-Command uv -ErrorAction SilentlyContinue)) {
    throw 'uv is not installed or not in PATH. Install uv and reopen PowerShell.'
}
Write-Host '1/3 - Installing project and lab dependencies (Python 3.12)...'
uv sync --python 3.12 --extra dev
if ($LASTEXITCODE -ne 0) { throw 'uv sync failed.' }
Write-Host '2/3 - Generating real OpenAPI schema from lab routes...'
uv run python -m achillesapi.lab.export_spec
if ($LASTEXITCODE -ne 0) { throw 'OpenAPI export failed.' }
Write-Host '3/3 - Starting training API on http://127.0.0.1:8000'
Write-Host 'Swagger: http://127.0.0.1:8000/docs'
Write-Host 'Press Ctrl+C to stop; do not expose this vulnerable lab to other networks.'
uv run uvicorn achillesapi.lab.full_app:app --host 127.0.0.1 --port 8000 --no-access-log
