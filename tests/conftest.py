"""Conftest fuer AethelGard MVP1 Tests.

Stellt sicher, dass ``src/`` im ``sys.path`` enthalten ist, sodass
``import aethelgard`` auch ohne editable install funktioniert (und
ohne dass der Aufrufer ``PYTHONPATH`` setzen muss).
"""

from __future__ import annotations

import sys
from pathlib import Path

_SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if _SRC_DIR.is_dir() and str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))
