#!/usr/bin/env python3
"""Launcher so Raqib runs as `python3 raqib.py ...` without installing.
The real command lives in the raqib package."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from raqib.__main__ import main
if __name__ == "__main__":
    sys.exit(main())
