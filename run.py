"""
Simple runner script for Cloud Scanner during development.
Usage: python run.py [options]
"""

import sys
import os
from cloud_scanner.cli.commands import cli

if __name__ == "__main__":
    # Ensure current directory is in python path
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    
    # Run the CLI
    cli()
