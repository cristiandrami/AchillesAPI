#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
uv run --python 3.12 --with 'fastapi>=0.115,<1.0' --with 'uvicorn>=0.30,<1.0' --with 'pydantic>=2.7,<3.0' python -m uvicorn app:app --host 127.0.0.1 --port 8795 --no-access-log
