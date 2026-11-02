#!/usr/bin/env python3
#DESCRIPTION: This file is the thin launcher at the repo root. It exists
#             so "python3 poltergeist.py" works immediately after cloning
#             the repo, with no install step required. All the real logic
#             lives inside the poltergeist/ package; this file's only job
#             is to find that package and call its main() function.

#import sys and os so we can make sure Python can find the poltergeist
#package folder sitting right next to this file, even if the tool is
#launched from a different working directory.
import sys
import os

#Insert this file's own folder at the very front of the import search
#path, so "import poltergeist" always finds the local package first.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

#import main from the real CLI module, where every actual flag, the
#wizard, and the menu are implemented.
from poltergeist.cli import main

#Only run main() if this file was executed directly (not imported), which
#is the standard Python pattern for a script that can also be imported.
if __name__ == "__main__":
    #Hand off control entirely to the real entrypoint.
    main()
