"""
main.py — Top-level CLI shim (allows: python main.py analyze <file>)
"""
import sys
from securemailscope.main import main

if __name__ == "__main__":
    sys.exit(main())
