"""Entry point of the installed ``usbtether.exe`` (PyInstaller, no console window).

No arguments opens the desktop panel; ``usbtether.exe open <file>`` is what Explorer runs on a
double-clicked ``.utenc``; every other CLI command works too (its output is not visible because
the exe has no console - use ``pip install usbtether`` for the console CLI).
"""

import sys

from usbtether.cli import main

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:] or ["app"]))
