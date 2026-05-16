import sys
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[2]
APP_DIR = ROOT_DIR / "app"

for path in (ROOT_DIR, APP_DIR):
    as_str = str(path)
    if as_str not in sys.path:
        sys.path.insert(0, as_str)
