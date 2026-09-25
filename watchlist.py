"""Loads config/watchlist.json — the one place the actual watch targets live."""
import json
from pathlib import Path

_CONFIG_PATH = Path(__file__).parent / "config" / "watchlist.json"
WATCHLIST = json.loads(_CONFIG_PATH.read_text())
