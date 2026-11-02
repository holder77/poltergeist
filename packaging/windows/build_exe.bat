@echo off
REM DESCRIPTION: Run this ON WINDOWS to build Poltergeist.exe. Double-click
REM it, or run it from a Command Prompt opened in this same folder
REM (packaging\windows\). It does three things, in order: installs the two
REM build-time-only tools this needs (PyInstaller, Pillow - neither is a
REM runtime dependency of the shipped program itself, see this folder's
REM other files for why), renders the .exe's own file icon from the exact
REM same ghost-mascot geometry the live GUI uses, then runs PyInstaller
REM against poltergeist.spec, which embeds poltergeist.manifest
REM (requireAdministrator) right into the finished .exe.
REM
REM This CANNOT be run from Linux/macOS to produce a working .exe -
REM PyInstaller bundles the real interpreter and libraries of whatever OS
REM it's actually running on; it does not cross-compile. This script must
REM be run on a real Windows machine (or a Windows VM) with Python 3.8+
REM already installed.
REM
REM When it finishes, the finished, self-contained file is at:
REM   dist\Poltergeist.exe
REM Copy that one file anywhere you like - right-click it and choose
REM "Run as administrator" (or just double-click it; see
REM poltergeist.manifest's own comment for why both work the same way).

echo === Poltergeist Windows .exe build ===
echo.

REM Always run from this script's own folder, no matter how it was
REM launched (double-click, a shortcut, a different starting directory in
REM an already-open Command Prompt) - so dist\ and build\ always land
REM right here, predictably, every time.
cd /d "%~dp0"

echo [1/4] Installing/upgrading build-time tools (pyinstaller, pillow)...
python -m pip install --upgrade pyinstaller pillow
if errorlevel 1 (
    echo.
    echo FAILED to install pyinstaller/pillow - is Python installed and on PATH?
    echo Try "python --version" in a new Command Prompt to check.
    pause
    exit /b 1
)

echo.
echo [2/4] Installing Poltergeist's own runtime dependencies (psutil, paramiko)...
python -m pip install --upgrade -r "%~dp0..\..\requirements.txt"
if errorlevel 1 (
    echo.
    echo FAILED to install Poltergeist's own dependencies - see the error above.
    pause
    exit /b 1
)

echo.
echo [3/4] Rendering the .exe's file icon (poltergeist.ico) from the ghost mascot...
python "%~dp0generate_icon.py"
if errorlevel 1 (
    echo.
    echo FAILED to render poltergeist.ico - see the error above.
    pause
    exit /b 1
)

echo.
echo [4/4] Running PyInstaller (this can take a minute or two)...
python -m PyInstaller --noconfirm --clean "%~dp0poltergeist.spec"
if errorlevel 1 (
    echo.
    echo FAILED - PyInstaller reported an error above.
    pause
    exit /b 1
)

echo.
echo === Done ===
echo Poltergeist.exe is at: %~dp0dist\Poltergeist.exe
echo Right-click it and choose "Run as administrator" (or just double-click -
echo the built-in manifest makes Windows prompt for elevation automatically).
pause
