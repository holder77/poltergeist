#DESCRIPTION: This file marks the poltergeist folder as a real Python package
#             so that "import poltergeist" and "from poltergeist import cli" work
#             from anywhere once the project is installed with pip install -e .

#Set the package version number as a plain string so other files and the
#command line "--version" flag can display it without guessing. Bumped to
#1.0 - the tool is considered feature-complete for its first real use.
__version__ = "1.0"

#Set a short one-line description of the whole tool, reused by argparse
#and by the README generation step later if we automate that.
__description__ = "Poltergeist - modular cross-platform blue team audit tool"

#Set the author/copyright line and project URL as plain strings, kept
#here (not hand-typed separately in cli.py's banner and gui/app.py's
#header) so both front ends are reading the exact same text and can never
#drift out of sync with each other.
__author__ = "Josh Holder"
__copyright__ = f"(c) 2026 {__author__}"
__url__ = "https://github.com/holder77"
