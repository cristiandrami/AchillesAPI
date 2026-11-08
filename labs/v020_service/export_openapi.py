"""Export the actual FastAPI specification, not a manually duplicated Swagger."""
import json
from pathlib import Path
from labs.v020_service.app import app

path = Path(__file__).with_name("openapi.json")
path.write_text(json.dumps(app.openapi(), indent=2) + "\n", encoding="utf-8")
print(path)
