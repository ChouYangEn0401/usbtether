"""Deterministic JSON encoding used for everything that gets hashed or signed."""

from __future__ import annotations

import json
from typing import Any


def canonical_json(obj: Any) -> bytes:
    """Encode ``obj`` as canonical JSON: sorted keys, no whitespace, ASCII only.

    Payloads that are signed or hashed must not contain floats, because their textual
    form is not guaranteed to be identical across implementations.
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
