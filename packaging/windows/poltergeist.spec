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
#
#             This .exe ALSO bundles a full, plain-text copy of its own
#             poltergeist.py + poltergeist/ source tree inside itself,
#             under a "_deploy_source" folder - see
#             _collect_deploy_source_datas() below for why: the README
#             deliberately tells people to copy this one .exe file
#             anywhere they like, so there is usually no real source tree
#             sitting next to it for the "set up a remote machine over
#             SSH" feature to copy up to that (almost always Linux)
#             target - a compiled Windows .exe obviously cannot run
#             there. config.py's DEPLOYABLE_SOURCE_ROOT is what reads
#             this bundled copy back out again at runtime.

import os
import sys

#This spec file's own folder (packaging/windows/), and the repo root two
#levels up from it - PyInstaller spec files are plain Python, executed by
#PyInstaller itself, so ordinary path math works here the same as
#anywhere else in this project.
SPEC_DIR = os.path.dirname(os.path.abspath(SPEC))
REPO_ROOT = os.path.abspath(os.path.join(SPEC_DIR, "..", ".."))

#Import modules/remote.py's own deploy-exclusion rule directly, rather
#than hand-copying/duplicating it here, so the files this .exe bundles
#for ITS OWN remote-deploy feature can never silently drift out of sync
#with the exact same rule deploy_to_target() itself uses for a normal
#source checkout's deploy. REPO_ROOT has to go on sys.path first since
#this spec file is executed on its own, not run as part of a normal
#"import poltergeist" from an already-installed package.
sys.path.insert(0, REPO_ROOT)
from poltergeist.modules.remote import _is_excluded_from_deploy


#Define _collect_deploy_source_datas, which builds the (source, dest_dir)
#pairs PyInstaller's own "datas" list needs to bundle a full, plain-text
#copy of poltergeist.py and the entire poltergeist/ package tree inside
#the finished .exe, landing at "_deploy_source/poltergeist.py" and
#"_deploy_source/poltergeist/..." once PyInstaller's onefile bootloader
#extracts it at runtime - exactly mirroring a real source checkout's own
#layout, so config.py's DEPLOYABLE_SOURCE_ROOT can hand that extracted
#folder straight to deploy_to_target() with no special-casing on the
#receiving end at all.
def _collect_deploy_source_datas():
    #Always include the thin top-level launcher - this is the exact file
    #a remote Linux target's "python3 poltergeist.py" command looks for.
    pairs = [(os.path.join(REPO_ROOT, "poltergeist.py"), "_deploy_source")]
    #Walk the whole poltergeist/ package the same way deploy_to_target()
    #itself walks a real checkout, applying the exact same exclusion rule.
    for current_dir, subdirs, files in os.walk(os.path.join(REPO_ROOT, "poltergeist")):
        #Prune excluded folders in place, same reasoning as deploy_to_target().
        subdirs[:] = [d for d in subdirs if not _is_excluded_from_deploy(d)]
        #Work out this folder's path relative to the repo root (e.g.
        #"poltergeist" or "poltergeist/modules"), so the bundled copy
        #lands at the matching "_deploy_source/..." location.
        relative_dir = os.path.relpath(current_dir, REPO_ROOT)
        dest_dir = os.path.join("_deploy_source", relative_dir)
        for filename in files:
            #Skip anything on the same never-deploy list deploy_to_target()
            #itself honors.
            if _is_excluded_from_deploy(filename):
                continue
            pairs.append((os.path.join(current_dir, filename), dest_dir))
    return pairs


#The thin launcher at the repo root is the real entry point - the exact
#same file "python3 poltergeist.py" runs, so the packaged .exe and a
#plain source checkout always start exactly the same way, with no
#separate "frozen" entry point to keep in sync.
a = Analysis(
    [os.path.join(REPO_ROOT, "poltergeist.py")],
    pathex=[REPO_ROOT],
    binaries=[],
    #The bundled "_deploy_source" copy (see _collect_deploy_source_datas()
    #above) already includes poltergeist/data/cve_hints.json, so no
    #separate manual entry for it is needed here any more - one single
    #source of data files instead of two that could quietly drift apart.
    datas=_collect_deploy_source_datas(),
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
