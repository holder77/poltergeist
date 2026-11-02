# -*- mode: python ; coding: utf-8 -*-
#DESCRIPTION: PyInstaller build spec for Poltergeist.exe. This file MUST
#             be run on an actual Windows machine - PyInstaller bundles
#             the real interpreter and libraries of whichever OS it's
#             run on; it does not cross-compile. There is no way to
#             produce a genuine Windows .exe from a Linux machine with
#             this tool (or any other common one), so build_exe.bat
#             (right next to this file) is meant to be double-clicked (or
#             run from a Windows command prompt) on Windows itself.
#
#             Run with:  pyinstaller poltergeist.spec
#             (build_exe.bat does this for you, after installing
#             PyInstaller and generating poltergeist.ico - see both of
#             those in this same folder.)
#
#             Produces dist/Poltergeist.exe - a single-file, console-less
#             executable with poltergeist.manifest (requireAdministrator)
#             and poltergeist.ico embedded, so launching it at all
#             triggers Windows' own UAC elevation prompt automatically
#             (see poltergeist.manifest's own top comment for exactly
#             what that does and does not cover).

import os

#This spec file's own folder (packaging/windows/), and the repo root two
#levels up from it - PyInstaller spec files are plain Python, executed by
#PyInstaller itself, so ordinary path math works here the same as
#anywhere else in this project.
SPEC_DIR = os.path.dirname(os.path.abspath(SPEC))
REPO_ROOT = os.path.abspath(os.path.join(SPEC_DIR, "..", ".."))

#The thin launcher at the repo root is the real entry point - the exact
#same file "python3 poltergeist.py" runs, so the packaged .exe and a
#plain source checkout always start exactly the same way, with no
#separate "frozen" entry point to keep in sync.
a = Analysis(
    [os.path.join(REPO_ROOT, "poltergeist.py")],
    pathex=[REPO_ROOT],
    binaries=[],
    #Oracle's offline CVE hint file (modules/oracle.py reads this at scan
    #time) is plain data, not code - PyInstaller only bundles .py files
    #it can see imported, so data files have to be listed explicitly the
    #same way pyproject.toml's own [tool.setuptools.package-data] already
    #does for a normal "pip install".
    datas=[
        (os.path.join(REPO_ROOT, "poltergeist", "data", "cve_hints.json"), "poltergeist/data"),
    ],
    #Defensive, not strictly required: PyInstaller's own static analysis
    #walks "import"/"from ... import ..." statements wherever they
    #appear in a file (not just at module top level), so the gui
    #package's own deliberately-lazy imports (poltergeist/gui/__init__.py
    #imports app.py only inside launch_gui(), specifically so a machine
    #with no Tkinter can still import poltergeist.gui to find that out -
    #see that file's own module docstring) are ordinarily still found.
    #Listed here anyway as cheap insurance in case a future refactor ever
    #makes one of these imports less literal (built from a string,
    #behind an extra layer of indirection, etc) in a way static analysis
    #can no longer follow.
    hiddenimports=[
        "poltergeist.gui.app",
        "poltergeist.gui.theme",
        "poltergeist.gui.dialogs",
        "poltergeist.gui.wizard",
        "poltergeist.gui.icon",
        "poltergeist.gui.notify_sound",
        "poltergeist.gui.console",
        "poltergeist.gui.live_dashboard",
        "poltergeist.gui.folder_browser",
        "poltergeist.gui.log_viewer",
        "poltergeist.gui.findings_view",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="Poltergeist",
    #Passing a.binaries/a.datas straight into EXE() (rather than holding
    #them back for a separate COLLECT() step) is what makes this a
    #single, self-contained .exe file with nothing else alongside it -
    #this is what makes "right-click -> Run as administrator" on one
    #plain file work the way it was asked for, rather than a whole
    #folder of DLLs the .exe depends on.
    #console=False means this runs as a windowed app with no black
    #terminal window behind it, matching a normal double-clicked desktop
    #program - correct for the GUI, which is what a flagless launch
    #always tries first. Anyone who specifically wants the text menu or
    #a scripted/headless flag (--text, --check, --monitor, etc) can still
    #get it by running Poltergeist.exe from an existing terminal/Command
    #Prompt window instead of double-clicking it - console=False hides
    #an application-owned console window, it does not prevent print()
    #output from reaching a terminal that already exists.
    console=False,
    #Embed the requireAdministrator manifest right in the .exe itself -
    #this is the actual mechanism behind "right-click -> Run as
    #administrator" (and, with this manifest, a PLAIN double-click too -
    #see poltergeist.manifest's own top comment).
    manifest=os.path.join(SPEC_DIR, "poltergeist.manifest"),
    #The .exe's own file/taskbar icon - built by generate_icon.py (run
    #automatically by build_exe.bat before this spec is invoked) from
    #the exact same ghost-mascot geometry gui/icon.py draws the live
    #runtime window icon from.
    icon=os.path.join(SPEC_DIR, "poltergeist.ico"),
    upx=False,
)
