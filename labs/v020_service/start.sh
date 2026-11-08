#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
exec uv run --extra dev uvicorn labs.v020_service.app:app --host 127.0.0.1 --port 8780
