#!/usr/bin/env python3
import sys
import os

# Ensure we can import the package
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from shellforge.main import main

if __name__ == "__main__":
    main()
