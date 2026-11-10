"""Allow running the launcher with ``python -m lv24_vigil``."""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
