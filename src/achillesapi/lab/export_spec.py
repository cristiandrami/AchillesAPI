"""Generate the full laboratory's Swagger file without running its web server."""

from __future__ import annotations

import json
from pathlib import Path

from achillesapi.lab.full_app import app


def main() -> None:
    """Write the local lab's OpenAPI document to examples/ (no network needed).

    This lets AchillesAPI read a stable Swagger file while the lab runs in
    a different terminal. Regenerate the file after changing the lab routes.
    """
    root = Path(__file__).resolve().parents[3]
    output = root / "examples" / "full_lab_openapi.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(app.openapi(), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"OpenAPI written to {output}")


if __name__ == "__main__":
    main()
