$ErrorActionPreference = "Stop"
$root = Resolve-Path (Join-Path $PSScriptRoot '..\..')
Set-Location $root
$env:PYTHONPATH = (Join-Path $root 'labs\multi_resource_demo')
uv run --python 3.12 --extra dev uvicorn app:app --host 127.0.0.1 --port 8790
