from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_json(path: str | Path) -> Any:
    p = Path(path)
    with p.open(encoding="utf-8") as f:
        return json.load(f)


def summarize_caveats(caveats: list[dict]) -> list[dict]:
    out = []
    for c in caveats:
        item = {"type": c.get("type"), "cid": c.get("cid")}
        if c.get("type") == "third":
            item["location"] = c.get("location")
        out.append(item)
    return out
