"""Package entry point for the nonactivating direct-mask contract CLI."""

import sys

from .calculator import _main


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
