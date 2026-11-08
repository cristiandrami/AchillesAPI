# Start only on local loopback. Open a new PowerShell window for the scanner.
$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
Push-Location $Root
try {
    uv run --extra dev uvicorn labs.v020_service.app:app --host 127.0.0.1 --port 8780
} finally { Pop-Location }
