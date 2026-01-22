"""
Entry point for running security validator as a module.

Usage:
    python -m security_py path/to/scan
    python -m security_py --help
"""

from .core.security_validator import main

if __name__ == "__main__":
    main()
