#DESCRIPTION: This module is the "lockfile" idea - it answers "exactly
#             what software versions are installed on this box, and did
#             any of them just CHANGE?" It is a STATE module like
#             persistence.py, users.py, and integrity.py: collect() is
#             called once at baseline time and again at check time, and
#             cli.py's diff logic flags anything new, missing, or changed.
#             A red team quietly downgrading a package to a vulnerable
#             version, or installing a brand new one, shows up here the
#             same way a changed file would. It also doubles as half of
#             "the Oracle": the Oracle checks live service BANNERS,
#             this module checks the INSTALLED PACKAGE LIST, which
#             catches software that isn't even running yet.

#import platform so we know which package manager to query.
import platform

#import subprocess so we can actually run the package manager commands.
import subprocess

#Store whether we are on Windows once for the whole module to reuse.
IS_WINDOWS = platform.system() == "Windows"

#Windows-only fix for a real bug report: collect_windows() below shells
#out to a real "powershell" process on every single scan (packages.py is
#a STATE module, re-collected every scan by exorcise.py's diff, same as
#persistence.py) - without this, that's a visible PowerShell window
#flashing open and closed once per scan. See modules/users.py's own copy
#of this exact fix for the full explanation; the short version is
#CREATE_NO_WINDOW tells Windows not to allocate a console for the child
#process at all, and the ternary keeps this safe to import on Linux too.
_HIDE_CONSOLE_KWARGS = {"creationflags": subprocess.CREATE_NO_WINDOW} if IS_WINDOWS else {}


#Define run_command, the same small wrapper pattern used in every other
#module, kept local so this module stays a self-contained, copy-pasteable
#example of how to write a new state module.
def run_command(command):
    #Try to run the command and capture its text output.
    try:
        #Give the command up to 30 seconds; a full package list can be
        #slow. **_HIDE_CONSOLE_KWARGS suppresses the flashing PowerShell
        #window this would otherwise pop open on Windows.
        result = subprocess.run(command, capture_output=True, text=True, timeout=30,
                                 shell=isinstance(command, str), **_HIDE_CONSOLE_KWARGS)
        #Return just the text that was printed to standard output.
        return result.stdout
    #If the command is missing or errors out, do not crash the whole scan.
    except Exception:
        #Return an empty string so the caller can treat it as "nothing".
        return ""


#Define collect_linux, which tries every common Linux package manager in
#turn and uses whichever one actually exists on this box.
def collect_linux():
    #Start with an empty dictionary of package name -> version.
    packages = {}
    #Try Debian/Ubuntu style systems first, via dpkg-query.
    dpkg_output = run_command(["dpkg-query", "-W", "-f=${Package}=${Version}\\n"])
    #If dpkg actually produced output, this is a Debian-family box.
    if dpkg_output:
        #Loop over each "name=version" line it printed.
        for line in dpkg_output.splitlines():
            #Only process lines that actually contain the "=" separator.
            if "=" in line:
                #Split on the first "=" only, in case a version string
                #itself contains an equals sign.
                name, _, version = line.partition("=")
                #Record this package's version.
                packages[name] = version
        #Return early since we found a working package manager.
        return packages
    #Try RHEL/Fedora/CentOS style systems next, via rpm.
    rpm_output = run_command(["rpm", "-qa", "--qf", "%{NAME}=%{VERSION}-%{RELEASE}\\n"])
    #If rpm actually produced output, this is an RPM-family box.
    if rpm_output:
        #Loop over each "name=version" line it printed.
        for line in rpm_output.splitlines():
            #Only process lines that actually contain the "=" separator.
            if "=" in line:
                #Split on the first "=" only.
                name, _, version = line.partition("=")
                #Record this package's version.
                packages[name] = version
        #Return early since we found a working package manager.
        return packages
    #If neither dpkg nor rpm produced anything, this is some other distro
    #(Arch, Alpine, etc) - return an empty dict rather than guessing wrong.
    #TODO: add pacman (-Q) and apk (info -v) support here for those distros.
    return packages


#Define collect_windows, which lists installed programs through
#PowerShell's Get-ItemProperty over the uninstall registry keys - the
#same source Control Panel's "Programs and Features" list uses.
def collect_windows():
    #Start with an empty dictionary of package name -> version.
    packages = {}
    #Build the PowerShell one-liner that reads both the 32-bit and 64-bit
    #uninstall registry hives and prints "name|version" per line.
    ps_command = (
        "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*, "
        "HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* "
        "| Where-Object { $_.DisplayName } "
        "| ForEach-Object { $_.DisplayName + '|' + $_.DisplayVersion }"
    )
    #Run that PowerShell command and read its output.
    output = run_command(["powershell", "-NoProfile", "-Command", ps_command])
    #Loop over every "name|version" line it printed.
    for line in output.splitlines():
        #Only process lines that actually contain the "|" separator.
        if "|" in line:
            #Split on the first "|" only.
            name, _, version = line.partition("|")
            #Record this program's version, stripping stray whitespace.
            packages[name.strip()] = version.strip()
    #Hand back everything we found.
    return packages


#Define collect, the function modules/__init__.py registers for this
#module's STATE_MODULES entry, matching every other state module's shape.
def collect(config):
    #Get the raw {name: version} dictionary for whichever OS we are on.
    raw_packages = collect_windows() if IS_WINDOWS else collect_linux()
    #Convert it into the same "pkg:<name>" -> version key format every
    #other state module uses, so cli.py's diff logic treats it identically
    #to a changed file or a new cron job.
    return {f"pkg:{name}": version for name, version in raw_packages.items()}
