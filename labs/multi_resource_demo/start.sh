#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
PYTHONPATH=labs/multi_resource_demo uv run --python 3.12 --extra dev uvicorn app:app --host 127.0.0.1 --port 8790
