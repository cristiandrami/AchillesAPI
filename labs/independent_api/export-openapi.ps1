$ErrorActionPreference = 'Stop'
Set-Location (Resolve-Path (Join-Path $PSScriptRoot '..\..'))
uv run --extra dev python -c "import json; from labs.independent_api.app import app; from pathlib import Path; Path('labs/independent_api/openapi.json').write_text(json.dumps(app.openapi(), indent=2), encoding='utf-8')"
