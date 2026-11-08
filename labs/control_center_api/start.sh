#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
uv run --python 3.12 --extra dashboard uvicorn labs.control_center_api.app:app --host 127.0.0.1 --port 8795
