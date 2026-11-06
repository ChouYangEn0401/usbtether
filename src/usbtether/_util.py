"""Small helpers shared by the token and registry modules."""

from __future__ import annotations

import contextlib
import os
from datetime import datetime, timezone
from pathlib import Path


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def atomic_write(path: Path, data: bytes, *, private: bool = False) -> None:
    """Write ``data`` so that readers see either the old or the new content, never a mix.

    The data is written to a sibling temporary file, flushed to disk, then renamed over
    ``path``. ``private`` additionally restricts permissions where the OS supports it.
    """
    tmp = path.with_name(path.name + ".tmp")
    try:
        with open(tmp, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        if private:
            with contextlib.suppress(OSError):
                os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            tmp.unlink()
        raise
