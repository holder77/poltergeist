#DESCRIPTION: This file is the front door of the whole program. Whether
#             someone types "python3 poltergeist.py", "poltergeist", or
#             "poltergeist --monitor", execution ends up in main() at the
#             bottom of this file. This file owns the interactive setup
#             wizard (which calls discovery.py to suggest real answers, or
#             modules/remote.py to probe a remote target the same way),
#             the main menu, and run_action() - the ONE place both this
#             text menu and the GUI dispatch an action from, so a local
#             vs. remote target, and the baseline lock, are each handled
#             in exactly one place instead of twice.

#import argparse so the tool can be driven by command line flags for
#scripting/automation, not only through the interactive menu.
import argparse

#import sys so the elevation check below can print its warning to stderr
#(not stdout, since it's an error condition) and exit with a nonzero code.
import sys

#import os so we can detect whether we are running with admin/root rights.
import os

#import platform so we can tell Windows admin-checking apart from Linux,
#and so the wizard can suggest this machine's own hostname as a label.
import platform

#import time so the --monitor loop can sleep between passes.
import time

#import getpass so a password or key passphrase can be typed into the
#wizard WITHOUT echoing to the screen or ending up in shell history -
#see ask_secret() below.
import getpass

#import json so --discover-json can print discovery data for a remote
#wizard page to read back over SSH.
import json

#import our own config module's three functions for loading, saving, and
#defaulting the settings file, plus REPO_ROOT, the repo's own top folder -
#a remote target's "deploy" step needs to know exactly what to copy there.
#DASHBOARD_PORT is THIS instance's own web Dashboard port (8765 for the
#first running instance, 8766 for a second simultaneous one, and so on -
#see config.py's own _select_instance_paths() for the full reasoning).
from .config import load_config, save_config, default_config, config_exists, REPO_ROOT, DEPLOYABLE_SOURCE_ROOT, DASHBOARD_PORT

#import discover from discovery.py so the wizard can suggest real values
#for a LOCAL target instead of asking the user to type raw IPs and ports
#from memory.
from .discovery import discover

#import Log from evidence.py, the shared object every check reports through.
from .evidence import Log

#import both module registries, so this file can loop over them generically
#instead of hardcoding "run persistence, then users, then integrity...".
from .modules import STATE_MODULES, LIVE_MODULES

#import the deception module directly (not through the registries) since
#planting canaries is an opt-in action, not an automatic check.
from .modules import deception

#import the lockdown module directly for the same reason: mute() and
#individual firewall rules are deliberate commands, never automatic.
from .modules import lockdown

#import the oracle module for the opt-in service/version + CVE hint scan.
from .modules import oracle

#import the snapshot module for the opt-in VSS/LVM safety net.
from .modules import snapshot

#import the tripwire module directly (not through the registries) since
#ADDING a new watched folder is a one-time setup action, even though its
#check() already runs automatically every pass through LIVE_MODULES.
from .modules import tripwire

#import log_review directly so --list-logs/--read-log can call its
#shared list_available_logs()/read_log_content() functions - the exact
#same ones the GUI's local "View System Logs" picker calls in-process
#(see log_review.py's own comment on those two functions for why one
#implementation covers both the local and the "run this flag over SSH on
#a remote target" case).
from .modules import log_review

#import fs_browse directly so --list-dir can call its shared
#list_directory() function - same "one implementation, local or over
#SSH" reasoning as log_review above.
from .modules import fs_browse

#import the remote module: everything needed to set up and run against
#ONE other machine over SSH (key, specific key file, or password - see
#its own module docstring). It never sees a secret this file does not
#hand it directly, and it never writes one to disk.
from .modules import remote

#import the exorcise functions: the baseline itself, the diff-and-restore
#logic, and the new lock/reset pair that keeps a baseline from being
#silently retaken mid-competition.
from .exorcise import run_baseline, run_exorcise, is_baseline_locked, reset_baseline

#import the report module, the "Scribe", which turns findings.jsonl into
#a Markdown incident report on demand.
from . import report

#import the dashboard module, the localhost-only live findings page.
from . import dashboard

#import the role profile helpers so the wizard can tailor its suggestions
#to the kind of machine being defended.
from . import role_profiles

#import the quickscan module - now the canonical "run everything, once"
#implementation every front end and flag ultimately calls into.
from . import quickscan

#import the glossary printer, the tool's own in-app "what do these mean" help.
from .help_text import print_glossary

#import the version/author/copyright/URL strings from the package's own
#__init__.py - the ONE place they're defined - so the banner's
#version/copyright line below and gui/app.py's own header line are
#always reading the exact same text, never two hand-typed copies that
#can drift apart.
from . import __version__, __author__, __copyright__, __url__

#Store whether we are on Windows once for the whole file to reuse.
IS_WINDOWS = platform.system() == "Windows"

#Define the ASCII ghost mascot as a constant so it only has to be typed
#once and can be printed wherever we want to show the Poltergeist banner -
#the text menu here, and the GUI's own header, which imports this exact
#constant rather than keeping a second copy of the art anywhere. The
#literal "P O L T E R G E I S T" wordmark line used to sit right under
#the ghost's own feet here - removed by request, since both front ends
#already say the name in plain text right next to this art anyway (the
#text menu's own "POLTERGEIST: <target>" header line just above it, and
#the GUI's big title label next to it) - printing it a third time, in
#letter-spaced ASCII, was redundant.
GHOST_BANNER = r"""
⠀⠀⠀⣀⡤⠚⠋⠉⠉⠛⠒⢤⡀⠀⠀⠀
⠀⠀⣠⠏⠁⠀⠀⠀⠀⠀⠀⠈⠳⡄⠀⠀
⠀⢠⠇⠀⣤⣶⣤⡀⢠⣶⣦⡄⠀⢱⠀⠀
⠀⣞⠀⠀⢿⣿⡿⠃⠹⣿⣿⠇⠀⠘⡇⠀
⠀⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⠀
⢰⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⠀
⢸⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⡇
⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣧
⢻⠀⠀⣀⡀⠀⠀⠀⡀⠀⠀⠀⠀⠀⠀⣿
⠘⠦⠖⠋⠓⠤⠴⠒⠳⢤⡤⠖⠒⢦⣠
"""

#The version/copyright line printed right under the banner (text menu)
#and shown under the tagline in the GUI header - one shared string, built
#from the single source of truth in __init__.py, so there is only ever
#one place to update this instead of two that could say different things.
VERSION_LINE = f"v{__version__}  -  {__copyright__}  -  {__url__}"


#Define is_admin, a small cross-platform check for elevated privileges,
#since most of what this tool needs to see requires root/Administrator.
def is_admin():
    #Wrap in a try block since the Windows-specific call can fail oddly.
    try:
        #On Linux, UID 0 means we are root.
        if not IS_WINDOWS:
            #os.getuid only exists on Unix-like systems.
            return os.getuid() == 0
        #On Windows, ask the shell32 API whether we are elevated.
        import ctypes
        #IsUserAnAdmin returns a nonzero value if we are elevated.
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    #If the check itself fails for any reason, assume we are not admin.
    except Exception:
        #Return False so the tool at least warns the user either way.
        return False


#Build the one-paragraph message shown (one way or another) whenever
#is_admin() comes back False and this program is about to refuse to run.
#Kept as its own string so the GUI popup, the text-mode stderr print, and
#any future caller all say the exact same thing.
_ELEVATION_REQUIRED_MESSAGE = (
    "Poltergeist needs to run elevated - almost every module (open ports, "
    "running processes, protected log files, the firewall...) sees far "
    "less, or nothing at all, without it.\n\n"
    "Windows: right-click Poltergeist.exe (or your shortcut to it) and "
    "choose \"Run as administrator\".\n"
    "Linux: run it with sudo, e.g.  sudo python3 poltergeist.py\n\n"
    "Closing now."
)


#Define enforce_elevation_or_exit, called once from main() below, right
#after the handful of pure config-free utility flags (--discover-json,
#--list-dir, --list-logs, --read-log, --glossary) have already had their
#chance to run and return - those are harmless, read-only, and (for the
#"--discover-json"/"--list-*" ones) are also what a REMOTE target's own
#deployed copy is invoked with over SSH, already wrapped in its own
#"sudo -S" by modules/remote.py before Python even starts there, so
#gating them here a second time would be redundant at best and could
#break remote probing at worst. Everywhere else - the interactive text
#menu, the GUI, and every scripted/headless flag (--check, --baseline,
#--monitor, etc.) - genuinely needs elevated rights to see anything
#real, so rather than let someone run it for ten minutes and wonder why
#every section comes back empty, this refuses to even start and says so
#plainly, once, up front. "prefer_gui" picks how that refusal is shown:
#a real popup window when this run was headed for the GUI (the common
#case - launched by double-clicking, or no flags at all), or a plain
#stderr message + nonzero exit for a text-mode or scripted invocation,
#where there may be no display to pop a window on at all.
def enforce_elevation_or_exit(prefer_gui):
    #Already elevated - nothing to do, let main() carry on exactly as
    #before this check existed.
    if is_admin():
        return
    #Not elevated. Try a real native popup first if this run was headed
    #for the GUI - but only if that actually works; a prefer_gui=True
    #guess can still be wrong (Tkinter missing, no display at all on a
    #headless Linux box someone forgot --text on), so this falls back to
    #the plain stderr message rather than silently printing nothing.
    if prefer_gui:
        try:
            #Import tkinter here, not at module load time - this file
            #must stay importable even on a box with no Tkinter at all.
            import tkinter as tk
            from tkinter import messagebox
            #A real window is required to own a messagebox, but there's
            #no reason to actually show one - build it invisible, show
            #the popup on top of it, then tear both down immediately.
            popup_root = tk.Tk()
            popup_root.withdraw()
            messagebox.showerror("Poltergeist - elevation required", _ELEVATION_REQUIRED_MESSAGE)
            popup_root.destroy()
            #The popup was shown successfully - done, skip the stderr path.
            sys.exit(1)
        #Tkinter missing, no display, or anything else - fall through to
        #the plain-text path below instead of crashing on the way out.
        except Exception:
            pass
    #Either a text-mode/scripted run, or the GUI popup itself wasn't
    #possible - print plainly to stderr (this IS an error condition, not
    #normal output) and exit with a nonzero code either way. Indent every
    #line of the message (not just the first), so it reads as one clean
    #indented block instead of the later lines jamming against the margin.
    indented_message = "\n".join(f"  {line}" if line else "" for line in _ELEVATION_REQUIRED_MESSAGE.split("\n"))
    print(f"\n{indented_message}\n", file=sys.stderr)
    sys.exit(1)


#Define ask, the basic "prompt with a default" input helper used by every
#question in the wizard below.
def ask(prompt, default=""):
    #Build the "[default]" suffix shown after the prompt, if there is one.
    default_display = f" [{default}]" if default != "" else ""
    #Actually read the user's typed answer from the keyboard.
    typed_answer = input(f"  {prompt}{default_display}: ").strip()
    #Return what they typed, or the default if they just pressed Enter.
    return typed_answer if typed_answer else default


#Define ask_list, a wrapper around ask() for settings that are really a
#comma separated list (networks, ports, trusted IPs).
def ask_list(prompt, default_list):
    #Turn the default list into a comma separated string to display.
    default_display = ",".join(str(item) for item in default_list)
    #Ask the question using the normal ask() helper.
    raw_answer = ask(f"{prompt} (comma separated)", default_display)
    #Split the answer on commas and strip whitespace from each piece,
    #dropping any empty strings caused by trailing commas.
    return [piece.strip() for piece in raw_answer.split(",") if piece.strip()]


#Define ask_yes_no, a wrapper around ask() for plain yes/no questions.
def ask_yes_no(prompt, default_is_yes=False):
    #Build the default display text, either "y" or "n".
    default_text = "y" if default_is_yes else "n"
    #Ask the question and read back whatever the user typed.
    raw_answer = ask(f"{prompt} (y/n)", default_text).lower()
    #Treat anything starting with "y" as yes, everything else as no.
    return raw_answer.startswith("y")


#Define ask_secret, used ONLY for a password or key passphrase. Unlike
#ask() above, this never echoes what is typed and never shows a default,
#since there is never a safe default secret to show. If this terminal
#cannot hide typed input at all (some IDEs, or input piped from a file),
#getpass falls back to a visible prompt on its own and warns about it -
#we let that warning through rather than silently going fully blind.
def ask_secret(prompt):
    #Try the normal, hidden-input path first.
    try:
        #getpass.getpass never echoes what is typed.
        return getpass.getpass(f"  {prompt}: ")
    #A handful of unusual environments cannot do hidden input at all.
    except Exception:
        #Warn plainly, then fall back to a normal, visible prompt rather
        #than crash the whole wizard over this one question.
        print("  (this terminal cannot hide typed input here - it will be visible)")
        #Reuse the ordinary ask() helper with no default to show.
        return ask(prompt, "")


#Define secret_from_environment, a deliberate, opt-in escape hatch for
#scripted/headless use (a cron job, say) against a remote target whose
#auth_mode needs a password or key passphrase - there is no human present
#to type one into the wizard in that case. Poltergeist itself still never
#WRITES this anywhere; whatever process sets this one environment
#variable before launching Poltergeist is responsible for that
#variable's own security.
def secret_from_environment(target):
    #Look for the one environment variable this escape hatch reads.
    raw_secret = os.environ.get("POLTERGEIST_SSH_SECRET")
    #If it was not set, there is no secret to offer at all.
    if not raw_secret:
        #Return an empty dict, same shape as "no secret needed".
        return {}
    #Put it under whichever key this target's auth_mode actually expects.
    if target.get("auth_mode") == "password":
        #A plain password login.
        return {"password": raw_secret}
    if target.get("auth_mode") == "key_file":
        #A passphrase-protected key file.
        return {"passphrase": raw_secret}
    #Any other auth_mode (agent_or_default) needs no secret at all.
    return {}


#Define run_wizard, the full interactive setup flow. It always starts by
#asking WHICH machine this install is pointed at (local, or a remote
#machine over SSH), then probes that machine (locally in-process, or
#remotely via modules/remote.py) and asks the human to confirm or edit
#every discovered default, same as before. previous_config, when given,
#seeds every question's default with whatever was already saved, so
#re-running this (which now happens on every single launch - see
#run_menu() below) is just pressing Enter through everything that has
#not changed, not retyping a whole setup from scratch. Returns a
#(config, secret) tuple on success, or (None, {}) if a remote target
#could not be reached - secret is the small, NEVER-saved dictionary
#holding whatever password/passphrase this run's connection actually
#needed; see modules/remote.py's module docstring for why that is never
#written to config.json, a log, or anywhere else on disk.
def run_wizard(previous_config=None):
    #Print a header so it is obvious the wizard has started.
    print("\n== Setup wizard == (press Enter to accept the shown default)")
    #Start from whatever was already configured, if anything.
    previous_config = previous_config or {}
    previous_target = previous_config.get("target") or default_config()["target"]

    #--- which machine ---
    print("\n  Which machine is this install going to monitor?")
    print("    1) This machine (local)")
    print("    2) A remote machine over SSH")
    #Default to whichever mode was already set up, so reconfirming the
    #same target is just pressing Enter here too.
    default_machine_choice = "2" if previous_target.get("mode") == "remote" else "1"
    machine_choice = ask("Pick a number", default_machine_choice)

    #Start building this run's target dict and its (never-saved) secret.
    target = {}
    secret = {}

    if machine_choice == "2":
        #A remote target, reached over SSH. This is Linux-only for now -
        #deploy/run both assume a POSIX shell and a "python3" on PATH,
        #which most default Windows installs do not have even when an
        #SSH server is running. If this genuinely IS a Windows box with
        #both of those, nothing below hard-blocks it; the connection
        #attempt itself is the real test.
        print("  (remote targets are Linux-only for now - a Windows box over SSH may come later)")
        target["mode"] = "remote"
        target["host"] = ask("Remote host/IP", previous_target.get("host", ""))
        target["port"] = int(ask("SSH port", str(previous_target.get("port") or 22)) or 22)
        target["user"] = ask("SSH username", previous_target.get("user", ""))
        target["remote_path"] = ask("Remote install folder (relative to that user's home)", previous_target.get("remote_path") or "poltergeist")
        target["label"] = ask("Friendly label for this machine", previous_target.get("label") or target["host"])

        #Ask which of the three ways in this connection should use.
        print("  How do you log in?")
        print("    1) SSH agent / default key (~/.ssh) - the normal case")
        print("    2) A specific private key file")
        print("    3) Username + password")
        auth_default = {"agent_or_default": "1", "key_file": "2", "password": "3"}.get(previous_target.get("auth_mode"), "1")
        auth_choice = ask("Pick a number", auth_default)
        if auth_choice == "2":
            #A specific key file, picked by path.
            target["auth_mode"] = "key_file"
            target["key_path"] = ask("Path to the private key file", previous_target.get("key_path", ""))
        elif auth_choice == "3":
            #Plain username + password.
            target["auth_mode"] = "password"
            target["key_path"] = ""
        else:
            #Agent or the usual ~/.ssh default key files.
            target["auth_mode"] = "agent_or_default"
            target["key_path"] = ""

        #Collect whatever secret this auth mode actually needs, held only
        #in this one local variable for the rest of this run.
        if target["auth_mode"] == "password":
            #A password login needs exactly one secret.
            secret["password"] = ask_secret("SSH password (not saved - you'll re-enter it next launch too)")
        elif target["auth_mode"] == "key_file":
            #A key MIGHT need a passphrase; blank means it does not.
            typed_passphrase = ask_secret("Key passphrase (leave blank if it has none - not saved)")
            if typed_passphrase:
                #Only record it if something was actually typed.
                secret["passphrase"] = typed_passphrase

        #Actually attempt the connection: deploy, push a minimal remote
        #config, and ask the remote side to probe and report on itself.
        print(f"  Connecting to {target['user']}@{target['host']}:{target['port']}...")
        #Use whatever evidence_dir already exists purely as somewhere to
        #cache this host's trusted key during setup - the real evidence_dir
        #question comes right after this either way, local or remote.
        probe_scratch_config = {"evidence_dir": previous_config.get("evidence_dir") or default_config()["evidence_dir"]}
        #DEPLOYABLE_SOURCE_ROOT, not REPO_ROOT - the two are the same
        #folder for a plain "python poltergeist.py" checkout, but REPO_ROOT
        #alone would be wrong here when this is the packaged .exe (see
        #config.py's own long comment on DEPLOYABLE_SOURCE_ROOT for the
        #full story: deploy needs real, plain-text .py source to copy up
        #to the - almost always Linux - target, and that is never just
        #sitting next to a copied-anywhere single .exe file).
        discovered, error = remote.probe_target_remote(probe_scratch_config, target, secret, DEPLOYABLE_SOURCE_ROOT)
        #A key that needs a passphrase we did not supply is a specific,
        #recoverable case - ask for one and retry once instead of just
        #failing the whole wizard over a detail we can still fix right now.
        if discovered is None and target["auth_mode"] == "key_file" and "passphrase" not in secret and "passphrase" in (error or "").lower():
            #Ask for the missing passphrase.
            typed_passphrase = ask_secret("That key needs a passphrase - enter it")
            if typed_passphrase:
                #Record it and try the whole connect-and-probe step again.
                secret["passphrase"] = typed_passphrase
                #Same DEPLOYABLE_SOURCE_ROOT as the first attempt just
                #above, for the same reason.
                discovered, error = remote.probe_target_remote(probe_scratch_config, target, secret, DEPLOYABLE_SOURCE_ROOT)
        #If it still did not work, stop the wizard here rather than ask a
        #dozen more questions about a machine we cannot actually reach.
        if discovered is None:
            #Explain exactly what went wrong.
            print(f"  Could not set up {target['label']}: {error}")
            print("  Setup was not completed. Fix the issue above and run Setup again.")
            #Return (None, {}) so the caller knows this attempt failed.
            return None, {}
        #Confirm success and what kind of machine we are now looking at.
        print(f"  Connected. {target['label']} is a {'Windows' if discovered.get('is_windows') else 'Linux'} machine.")
    else:
        #A plain local target: this machine, auditing itself.
        target["mode"] = "local"
        target["label"] = ask("Friendly label for this machine", previous_target.get("label") or platform.node() or "this machine")
        target["host"] = ""
        target["port"] = 22
        target["user"] = ""
        target["remote_path"] = "poltergeist"
        target["auth_mode"] = "agent_or_default"
        target["key_path"] = ""
        #Probe this machine directly, in-process.
        print("  Probing this machine...")
        discovered = discover()

    #Record which OS this target actually runs, straight from the real
    #probe above (never guessed) - local or remote either way. This is
    #purely for the GUI's own dynamic OS-aware taskbar icon (see
    #gui/icon.py) to read back later without re-probing anything; the
    #text menu itself has no use for it.
    target["os"] = "windows" if discovered.get("is_windows") else "linux"

    #--- evidence_dir, asked early since it needs no discovered data ---
    default_evidence_dir = previous_config.get("evidence_dir") or default_config()["evidence_dir"]
    evidence_dir = os.path.abspath(ask("Evidence directory (on THIS machine, where reports/logs are kept)", default_evidence_dir))

    #Start the real config with what we have collected so far.
    new_config = {"target": target, "evidence_dir": evidence_dir}

    #Print every interface the probe found, for context before the
    #networks question below - whichever machine discovered came from.
    for interface in discovered["interfaces"]:
        #Print the interface name, IP, and subnet on one line.
        print(f"    found interface {interface['name']}: {interface['ip']} ({interface['net']})")
    #If a default gateway was found, print it too.
    if discovered["gateway"]:
        #Show the gateway so the user recognizes it as a trusted IP.
        print(f"    default gateway: {discovered['gateway']}")

    #Every question below defaults to the PREVIOUSLY SAVED value first,
    #falling back to freshly discovered data only when there is no saved
    #value yet (first-ever setup, or a brand new target) - reconfirming
    #an existing setup is just pressing Enter through all of this.
    new_config["networks"] = ask_list("Networks being defended (CIDR)", previous_config.get("networks") or sorted(set(discovered["subnets"])))
    new_config["vpn_networks"] = ask_list("VPN / red-team-access ranges (CIDR, blank if none)", previous_config.get("vpn_networks") or sorted(set(discovered["vpn_subnets"])))
    #Deliberately NOT pre-filled with the discovered gateway any more -
    #"Trusted external IPs" is used by network.py to SILENTLY skip a
    #connection's plain listing entirely, and on a flat, single-subnet
    #lab/competition box the gateway address is exactly where a C2 pivot
    #can sit. Type it in here yourself if you are sure traffic through it
    #is routine - it is shown above for reference either way. (The
    #beacon-timing check still watches every destination regardless of
    #this list, trusted or not - see network.py's own comment.)
    new_config["trusted_ips"] = ask_list("Trusted external IPs (scoring engine, teammates - NOT auto-filled with the gateway any more, see above)", previous_config.get("trusted_ips") or [])
    #Show what is listening right now before asking which of those ports
    #should count as "expected".
    listening_summary = ", ".join(f"{item['port']}/{item['proc']}" for item in discovered["listening"]) or "none"
    print(f"  Listening right now: {listening_summary}")
    expected_default = previous_config.get("expected_ports") or sorted(item["port"] for item in discovered["listening"])
    expected_ports_raw = ask_list("Ports that SHOULD be listening (only accept blindly on a clean box)", expected_default)
    new_config["expected_ports"] = [int(p) for p in expected_ports_raw if str(p).isdigit()]
    watch_ports_raw = ask_list("Always-suspicious ports", previous_config.get("watch_ports") or [4444, 1337, 31337, 5555, 6666, 9001, 1234])
    new_config["watch_ports"] = [int(p) for p in watch_ports_raw if str(p).isdigit()]
    new_config["cpu_threshold"] = float(ask("Flag process above this CPU %", str(previous_config.get("cpu_threshold", 80))))
    new_config["mem_threshold"] = float(ask("Flag process above this memory %", str(previous_config.get("mem_threshold", 50))))

    #Print every known role profile as a numbered list before asking.
    role_keys = role_profiles.list_roles()
    print("  What kind of machine is this (the one being MONITORED)? (only changes which files get suggested below)")
    #Loop over every role and print its number and plain-English label.
    for index, role_key in enumerate(role_keys, start=1):
        #Print "1) Linux - web server" style lines.
        print(f"    {index}) {role_profiles.ROLE_PROFILES[role_key]['label']}")
    #Default to whichever role was already set, falling back to the first.
    previous_role_index = (role_keys.index(previous_config["role"]) + 1) if previous_config.get("role") in role_keys else 1
    role_choice = ask("Pick a number", str(previous_role_index))
    #Translate the typed number back into a role key, falling back safely
    #to the first role if the user typed something that is not valid.
    try:
        #Convert to an integer index and look up the matching role key.
        new_config["role"] = role_keys[int(role_choice) - 1]
    #If the typed value was not a valid number in range, fall back safely.
    except (ValueError, IndexError):
        #Default to the first role in the list.
        new_config["role"] = role_keys[0]

    #Both of these come straight out of the discovered dict - computed on
    #whichever machine is actually being monitored, local or remote - so
    #a remote target's suggestions are never checked against the
    #analyst's OWN filesystem by mistake (see discovery.py's comments).
    role_suggested_paths = discovered["role_paths"].get(new_config["role"], [])
    combined_default = previous_config.get("critical_paths") or sorted(set(role_suggested_paths + discovered["default_critical_paths"]))
    new_config["critical_paths"] = ask_list("Files/dirs to hash and protect (on the monitored machine)", combined_default)

    #Ask whether tampered critical files should be auto-restored, making
    #very clear that the tampered copy is always saved first either way.
    new_config["auto_restore"] = ask_yes_no("Auto-restore tampered files (tampered copy is ALWAYS saved first)", previous_config.get("auto_restore", False))
    #Ask how often the main view's automatic scan should repeat.
    new_config["interval"] = int(ask("How often the main view auto-scans, in seconds", str(previous_config.get("interval", 15))))

    #A gentle, non-blocking caution if a baseline is already locked in -
    #this wizard never clears that lock itself (see exorcise.reset_baseline
    #for the only way to do that), but it is worth saying plainly that
    #pointing at a different target makes an old baseline meaningless.
    if is_baseline_locked(new_config):
        #Print one clear, informational line and move on.
        print(f"  Note: a baseline is already locked in for {target['label']}. This wizard will not clear it, but pointing at a DIFFERENT target makes that baseline meaningless until you reset it.")

    #Make sure the evidence directory actually exists before we finish.
    os.makedirs(new_config["evidence_dir"], exist_ok=True)
    #Save the completed config to disk through config.py's save function.
    save_config(new_config)
    #Confirm to the user that the wizard is done.
    print("  Settings saved.")

    if target["mode"] == "remote":
        #Now that every question has been answered, push the REAL, final
        #config up to the remote side, replacing the bare placeholder
        #written during the connect/probe step above - every future
        #action on that machine uses these real settings. It needs its
        #OWN evidence_dir (inside where it was deployed) and sees itself
        #as a plain "local" target, same as during probing.
        remote_final_config = dict(new_config)
        #BARE "evidence", not remote_join(remote_root, "evidence") - see
        #probe_target_remote()'s own long comment on minimal_remote_config
        #in modules/remote.py for exactly why prefixing this with
        #remote_root double-nests it one directory too deep for
        #pull_evidence() to ever find (every remote command already `cd`s
        #into remote_root before running poltergeist.py, so the remote
        #process's cwd IS remote_root by the time this value is read).
        remote_final_config["evidence_dir"] = "evidence"
        remote_final_config["target"] = {"mode": "local"}
        print("  Sending final settings to the remote machine...")
        pushed, push_error = remote.push_remote_config(new_config, target, secret, remote_final_config)
        #This is a late, rare failure - the exact same connection just
        #worked moments ago to deploy and probe - but staying silent
        #about it would leave the remote side quietly running on its
        #bare probe-time placeholder config instead of what was just
        #configured, with nothing telling the user that happened.
        if not pushed:
            print(f"  Warning: the final settings could not be sent to {target['label']} ({push_error}). "
                  "It is still running on its placeholder setup from the connection test - run Setup again to retry.")

    #Hand back the finished config AND this run's in-memory secret so the
    #caller can keep using both for the rest of this session.
    return new_config, secret


#Define run_wizard_or_keep, a small wrapper used by every caller of
#run_wizard() so a FAILED remote setup attempt never destroys a working
#previous configuration - it falls back to whatever was already there
#instead. Returns (config_or_None, secret).
def run_wizard_or_keep(previous_config=None):
    #Run the wizard itself.
    new_config, secret = run_wizard(previous_config)
    #Success - hand back exactly what the wizard produced.
    if new_config is not None:
        #Nothing further to do.
        return new_config, secret
    #The wizard failed (almost always a remote connection problem). If
    #something was already configured, keep using it rather than leave
    #the tool with nothing at all.
    if previous_config:
        #Work out a label for the message, falling back sensibly.
        label = (previous_config.get("target") or {}).get("label") or "the local machine"
        #Say plainly that we are falling back, and to what.
        print(f"  Keeping previous settings ({label}).")
        #Hand back the previous config with an EMPTY secret - if that
        #config points at a remote target needing a password/passphrase,
        #the next action against it will fail with the same clear
        #connection error, which is the honest outcome here: we never
        #actually proved we can reach it this session.
        return previous_config, {}
    #There was no previous config either - nothing valid to hand back.
    return None, {}


#Define do_check, now a thin wrapper around quickscan.run() - the
#canonical "run everything, once" implementation - that first decides
#whether "everything" means running locally or dispatching to a remote
#target (see modules/remote.py's dispatch()). This is what every front
#end and every flag that wants a full scan pass actually calls.
def do_check(config, secret=None):
    #Work out which target this scan is actually running against.
    target = config.get("target") or {"mode": "local"}
    #A remote target: ask it to scan itself, then its findings are
    #already synced back locally by the time this call returns.
    if target.get("mode") == "remote":
        #Dispatch the "scan" action key, which maps to --quickscan.
        remote.dispatch(config, target, secret, "scan")
    #A local target: just run the canonical scan directly, in-process.
    else:
        #Fresh Log object for this one scan pass.
        quickscan.run(config, Log(config))


#Define do_monitor, which loops do_check forever on a timer until the
#user presses Ctrl+C. Used by the text menu's own "Sentinel: monitor"
#item and the --monitor flag; the GUI does not use this function at all -
#its main view keeps itself continuously refreshed on its own instead
#(see gui/app.py), since a persistent window has no Ctrl+C to wait for.
def do_monitor(config, secret=None):
    #Tell the user how often it will check and how to stop it.
    print(f"  Monitoring every {config['interval']}s. Ctrl+C to stop.")
    #Wrap the loop so Ctrl+C exits cleanly instead of printing a traceback.
    try:
        #Loop forever until interrupted.
        while True:
            #Run one full scan pass.
            do_check(config, secret)
            #Wait the configured interval before checking again.
            time.sleep(config["interval"])
    #Catch the keyboard interrupt raised by Ctrl+C.
    except KeyboardInterrupt:
        #Print a clean confirmation that monitoring has stopped.
        print("\n  Stopped.")


#Define show_recent_findings, which prints the tail of findings.jsonl so
#the user can quickly review what has already been logged.
def show_recent_findings(config):
    #Build the path to the findings log file.
    findings_path = os.path.join(config["evidence_dir"], "findings.jsonl")
    #If no findings have ever been logged, say so and stop.
    if not os.path.exists(findings_path):
        #Print a simple message instead of an empty or confusing list.
        print("  No findings yet.")
        #Return early since there is nothing else to show.
        return
    #import json locally here since it is only needed for this one display.
    import json as _json
    #Open the findings file and read every line into memory.
    with open(findings_path) as findings_file:
        #Read all lines, then keep only the most recent 25 of them.
        recent_lines = findings_file.read().splitlines()[-25:]
    #Loop over each of those recent lines.
    for line in recent_lines:
        #Parse the line back into a dictionary.
        record = _json.loads(line)
        #Print it in a readable, consistent one-line format.
        print(f"{record['ts']} [{record['severity']}] {record['module']}: {record['message']}")


#Define run_action, THE single place both the text menu below and the GUI
#(gui/app.py) dispatch any action from. It decides local-vs-remote and
#enforces the baseline lock in exactly one place, so neither front end
#has to duplicate (or risk disagreeing about) either of those rules.
#secret is the in-memory-only dict from run_wizard(); it is only ever
#actually used when config["target"]["mode"] == "remote". Returns True on
#success, False on a handled failure (an unrecognized rule, a missing
#baseline, and so on all print their own clear message first).
def run_action(config, secret, action_key, extra_input=None):
    #Work out which target this action runs against.
    target = config.get("target") or {"mode": "local"}
    #Whether this action needs to go over SSH instead of running in-process.
    is_remote = target.get("mode") == "remote"

    #A full scan pass - see do_check() above for the local/remote split.
    if action_key == "scan":
        #Run it and report success either way; do_check prints its own
        #findings/errors regardless.
        do_check(config, secret)
        return True

    #Take a brand new baseline - refused outright if one is already
    #locked in, the whole point of exorcise.is_baseline_locked().
    if action_key == "baseline":
        #Check the lock FIRST, before ever reaching the remote machine.
        if is_baseline_locked(config):
            #Explain exactly what to do instead.
            print("  A baseline is already locked in. Use 'Reset baseline' first if you really need to take a new one.")
            #Refuse the action.
            return False
        #Not locked - proceed, locally or remotely as appropriate.
        if is_remote:
            #Ask the remote target to baseline itself.
            return remote.dispatch(config, target, secret, "baseline")
        #Run it directly, in-process.
        run_baseline(config)
        return True

    #Clear the lock above. The caller (both front ends) is responsible
    #for making the human actually confirm this first with a typed
    #warning, the same pattern Shield: MUTE already uses - this function
    #trusts that already happened by the time it is called.
    if action_key == "baseline_reset":
        #Move (never delete) the old baseline into baseline_history/.
        history_dir = reset_baseline(config)
        #reset_baseline returns None if there was nothing to reset.
        if history_dir:
            #Say exactly where the old baseline now lives.
            print(f"  Baseline reset. The old one was moved to {history_dir}, never deleted.")
            return True
        #Nothing was actually locked in.
        print("  No baseline was locked in - nothing to reset.")
        return False

    #Plant a fresh set of canary (honeytoken) files.
    if action_key == "canaries":
        #Dispatch remotely, or run directly, as appropriate.
        if is_remote:
            return remote.dispatch(config, target, secret, "canaries")
        deception.plant_canaries(config)
        return True

    #Start seeding one new bait location with Canary.
    if action_key == "canary_add":
        #This action needs a folder path; refuse cleanly without one.
        if not extra_input:
            print("  No folder given.")
            return False
        if is_remote:
            return remote.dispatch(config, target, secret, "canary_add", extra_input)
        #Plant bait files into it right now. This returns None, not a
        #file count, if MAX_CANARY_FOLDERS is already reached and this
        #is a genuinely new folder (see add_folder()'s own comment) -
        #tell the person plainly instead of printing "0 files planted"
        #like something harmless happened.
        file_count = deception.add_folder(config, extra_input)
        if file_count is None:
            print(f"  Already seeding the maximum of {deception.MAX_CANARY_FOLDERS} locations. "
                  "Stop seeding one first (Canary: Stop Seeding a Location), or open a "
                  "separate instance of Poltergeist if you need to seed more at once.")
            return False
        #Confirm what just happened.
        print(f"  Now seeding {extra_input} ({file_count} bait files planted). Checked every scan.")
        return True

    #Stop seeding one bait location with Canary.
    if action_key == "canary_remove":
        #This action needs a folder path; refuse cleanly without one.
        if not extra_input:
            print("  No folder given.")
            return False
        if is_remote:
            return remote.dispatch(config, target, secret, "canary_remove", extra_input)
        #Stop seeding it and clean up the bait files planted there.
        deception.remove_folder(config, extra_input)
        #Confirm what just happened.
        print(f"  Stopped seeding {extra_input}.")
        return True

    #Start watching one folder with Tripwire.
    if action_key == "tripwire_add":
        #This action needs a folder path; refuse cleanly without one.
        if not extra_input:
            print("  No folder given.")
            return False
        if is_remote:
            return remote.dispatch(config, target, secret, "tripwire_add", extra_input)
        #Hash everything under it right now as the starting point. This
        #returns None, not a file count, if MAX_WATCHED_PATHS is already
        #reached and this is a genuinely new folder (see add_path()'s own
        #comment) - tell the person plainly instead of printing "None
        #files baselined" like something actually happened.
        file_count = tripwire.add_path(config, extra_input)
        if file_count is None:
            print(f"  Already watching the maximum of {tripwire.MAX_WATCHED_PATHS} folders. "
                  "Stop watching one first (Tripwire: Stop Watching a Folder), or open a "
                  "separate instance of Poltergeist if you need to watch more at once.")
            return False
        #Confirm what just happened and when it will be checked again.
        print(f"  Now watching {extra_input} ({file_count} files baselined). It will be checked every scan.")
        return True

    #Stop watching one folder with Tripwire.
    if action_key == "tripwire_remove":
        #This action needs a folder path; refuse cleanly without one.
        if not extra_input:
            print("  No folder given.")
            return False
        if is_remote:
            return remote.dispatch(config, target, secret, "tripwire_remove", extra_input)
        #Stop watching it and drop its stored hashes.
        tripwire.remove_path(config, extra_input)
        #Confirm what just happened.
        print(f"  Stopped watching {extra_input}.")
        return True

    #Apply one plain-English Shield rule.
    if action_key == "shield_rule":
        #This action needs the rule text; refuse cleanly without it.
        if not extra_input:
            print("  No rule given.")
            return False
        if is_remote:
            return remote.dispatch(config, target, secret, "shield_rule", extra_input)
        #Try to parse it into a structured rule.
        parsed = lockdown.parse_rule(extra_input)
        #If it parsed cleanly, apply it; otherwise explain what went wrong.
        if parsed:
            #Apply the single rule using a fresh Log object.
            lockdown.apply_rule(parsed, Log(config))
            return True
        #Tell the user their rule text did not match the expected format.
        print("  Could not understand that rule. Use: (block|allow) (ip|port) <value>")
        return False

    #Shield: MUTE - drop everything except trusted IPs. The caller is
    #responsible for making the human type the confirmation word first;
    #lockdown.mute() itself has no confirmation gate by design, and
    #neither does this dispatch - the friction lives at the call site,
    #same as it always has.
    if action_key == "shield_mute":
        if is_remote:
            return remote.dispatch(config, target, secret, "shield_mute")
        lockdown.mute(config, Log(config))
        return True

    #Oracle's service/version + CVE hint scan.
    if action_key == "oracle":
        if is_remote:
            return remote.dispatch(config, target, secret, "oracle")
        oracle.scan(config, Log(config))
        return True

    #Oracle's PRE-COMPETITION-ONLY OSINT hint refresh. Deliberately NEVER
    #dispatched to a remote target, same reasoning as "scribe" below: the
    #whole point is pulling fresh data from the open internet onto THIS
    #(the analyst's own) machine, before deploying to a target that is
    #meant to be air-gapped during the event - a remote, locked-down
    #target has no business making this call itself, it would only ever
    #find the same network unreachable that oracle.scan() already expects.
    if action_key == "oracle_refresh_hints":
        ok, added_count, message = oracle.refresh_hints_from_osint()
        print(f"  {message}")
        return ok

    #Medium's best-effort whole-volume snapshot.
    if action_key == "snapshot":
        if is_remote:
            return remote.dispatch(config, target, secret, "snapshot")
        snapshot.take_snapshot(config, Log(config))
        return True

    #Medium's folder-level revert - the caller (the GUI's own
    #"revert_folder" dialog flow, or the CLI's own --revert/--revert-
    #confirm check below) is responsible for making the human type the
    #RESTORE confirmation word first, the exact same division of
    #responsibility shield_mute above uses for MUTE.
    if action_key == "snapshot_revert":
        if is_remote:
            return remote.dispatch(config, target, secret, "snapshot_revert", extra_input)
        return snapshot.revert_directory(config, Log(config), extra_input)

    #The Scribe's Markdown incident report. Always local: it is built from
    #THIS machine's own findings.jsonl, which already holds a remote
    #target's synced-back findings too (see modules/remote.py's
    #pull_evidence), so there is nothing to run on a remote machine for
    #this one - it only ever reads a file that is already sitting right here.
    if action_key == "scribe":
        report.generate(config)
        return True

    #Nothing above matched - say so rather than silently doing nothing.
    print(f"  Unknown action: {action_key}")
    return False


#Define run_menu, the interactive loop shown when the tool is launched
#with no command line flags at all (or explicitly via --text).
def run_menu():
    #Print the ghost mascot banner first thing, every time.
    print(GHOST_BANNER)
    #Right under the ghost, the version/copyright/URL line - one shared
    #string with the GUI header's own copy (see VERSION_LINE above).
    print(f"  {VERSION_LINE}\n")
    #Belt-and-suspenders: main() already refuses to reach this point at
    #all without elevated rights (see enforce_elevation_or_exit above),
    #but keep this plain warning too in case run_menu() is ever called
    #directly by something other than main() - a test harness, say -
    #that bypassed that check.
    if not is_admin():
        #Print a clear one-line warning before anything else happens.
        print("  WARNING: not root/Administrator. Visibility will be limited.\n")
    #Always run the wizard on every launch - "a clean restart every time
    #we fire it up" - using whatever was already saved (if anything) only
    #as this run's DEFAULTS, never as a reason to skip asking entirely.
    previous_config = load_config() if config_exists() else None
    current_config, secret = run_wizard_or_keep(previous_config)
    #If there is still nothing valid (first-ever run, and the remote
    #setup failed), there is nothing left to do.
    if current_config is None:
        print("  No valid configuration yet. Exiting.")
        return
    #Auto-start the Dashboard in the background right now, so there is a
    #live page the moment the tool is up. Remember whether it actually
    #came up, so the Dashboard menu item below behaves correctly either way.
    dashboard_server = dashboard.start_background(DASHBOARD_PORT)
    #Loop forever, showing the menu, until the user chooses to quit.
    while True:
        #Re-check the lock every time the menu redraws, since taking or
        #resetting a baseline from this very menu should be reflected the
        #next time it is printed, not just after a restart.
        locked = is_baseline_locked(current_config)
        #Work out the current target's label for the header line.
        target_label = (current_config.get("target") or {}).get("label") or "this machine"
        #Print the header, then every menu option. Each line pairs the
        #cutesy module name with a short, literal description of what it
        #actually does, so nobody has to remember what "Oracle" or
        #"Scribe" means. Option 14 (Help) spells every name out in full.
        print(f"\n  POLTERGEIST: {target_label}")
        print("  == Setup & baseline ==")
        print("   1) Setup wizard               - re-confirm which machine you're monitoring, and every setting")
        #Option 2's own label (and behavior below) flips once a baseline
        #is locked in - this IS the lock the user asked for: "once we hit
        #that it's blocked to no longer use unless we accept a warning to
        #reset it".
        if locked:
            #Already baselined - this slot now resets instead.
            print("   2) Reset baseline             - clear the locked-in baseline (asks you to confirm first)")
        else:
            #Not baselined yet - this slot takes the first one.
            print("   2) Sentinel: baseline         - hash everything now; do this ONLY on a clean box")
        print("  == Checking ==")
        print("   3) Scan now                   - one command, one report: everything, right now")
        print("   4) Sentinel: monitor          - repeat the scan automatically on a timer (Ctrl+C to stop)")
        print("   5) Recent findings            - show the last 25 things that were flagged")
        print("  == Active defense (never kills or deletes anything) ==")
        print("   6) Plant canaries             - drop fake bait files; alert if anyone opens them")
        print("   7) Canary: choose a location  - pick a REAL folder to seed with bait files (a web root, a share...)")
        #Option 8's own label lists how many locations are currently
        #seeded (out of the hard MAX_CANARY_FOLDERS cap), the same
        #pattern Tripwire's own stop-watching option below already uses.
        seeded_count = len(deception.load_state(current_config)["bait_folders"])
        print(f"   8) Canary: stop a location    - stop seeding one location ({seeded_count}/{deception.MAX_CANARY_FOLDERS} seeded now)")
        print("   9) Tripwire: watch a folder   - start watching ONE folder live, outside any full baseline")
        #Option 10's own label lists how many folders are currently
        #watched (out of the hard MAX_WATCHED_PATHS cap), so the limit is
        #visible right here on the menu, not just discovered by trial
        #and error when a 4th "watch" is refused.
        watched_count = len(tripwire.load_state(current_config)["watched_paths"])
        print(f"  10) Tripwire: stop watching    - stop watching one folder ({watched_count}/{tripwire.MAX_WATCHED_PATHS} watched now)")
        print("  11) Shield: add one rule       - block/allow one IP or port (plain English)")
        print("  12) Shield: MUTE               - drop ALL traffic except your trusted IPs (asks to confirm)")
        print("  == Extra tools ==")
        print("  13) Oracle: scan services      - check running services AND installed packages against known CVEs")
        print("  14) Oracle: refresh OSINT hints - PRE-COMPETITION ONLY, pulls fresh CVE hints while you still have internet")
        print("  15) Medium: take snapshot      - best-effort whole-volume backup (VSS/LVM), if supported")
        print("  16) Medium: revert a folder    - roll ONE folder back to the last snapshot (asks you to confirm first)")
        print("  17) Scribe: write report       - turn everything logged so far into a Markdown incident report")
        print("  18) Dashboard                  - show the live findings page link (already running in the background)")
        print("\n  19) Help                       - what do these names actually mean?")
        print("  20) Quit")
        #Read the user's menu choice.
        choice = input("  > ").strip()
        #Branch based on which option they picked.
        if choice == "1":
            #Re-run the wizard, using the current config as this run's
            #defaults, and keep the current config if it fails.
            current_config, secret = run_wizard_or_keep(current_config)
            #A failure here with NO previous config at all ends the menu.
            if current_config is None:
                print("  No valid configuration. Exiting.")
                break
        elif choice == "2":
            #Behavior flips exactly the same way the label above did.
            if locked:
                #Ask for the typed confirmation before clearing anything.
                confirm = ask("Type RESET to clear the current baseline (it is moved to evidence/baseline_history/, never deleted)", "")
                #Only actually reset if they typed the exact word.
                if confirm == "RESET":
                    #Run the reset through the shared action dispatcher.
                    run_action(current_config, secret, "baseline_reset")
                else:
                    #Say plainly that nothing happened.
                    print("  Not reset.")
            else:
                #Not locked yet - take the first baseline.
                run_action(current_config, secret, "baseline")
        elif choice == "3":
            #Run one full scan pass right now.
            run_action(current_config, secret, "scan")
        elif choice == "4":
            #Start the continuous monitor loop (Ctrl+C to stop).
            do_monitor(current_config, secret)
        elif choice == "5":
            #Show the most recent findings already logged.
            show_recent_findings(current_config)
        elif choice == "6":
            #Plant a fresh set of canary (honeytoken) files.
            run_action(current_config, secret, "canaries")
        elif choice == "7":
            #Ask which real folder to start seeding with bait files.
            folder_to_seed = ask("Folder to seed with bait files (full path, on the monitored machine)", "")
            #Only proceed if the user actually typed something.
            if folder_to_seed:
                #Run it through the shared action dispatcher.
                run_action(current_config, secret, "canary_add", folder_to_seed)
        elif choice == "8":
            #Show which locations are currently seeded, as plain numbered
            #choices, the exact same pattern Tripwire's own stop-watching
            #option below uses.
            seeded_folders = deception.load_state(current_config)["bait_folders"]
            if not seeded_folders:
                #Nothing to stop seeding.
                print("  Not seeding any locations right now.")
            else:
                #Print each seeded location with its own pick number.
                print("  Currently seeded locations:")
                for index, seeded_folder in enumerate(seeded_folders, start=1):
                    print(f"   {index}) {seeded_folder}")
                #Read which one (by number) to stop seeding.
                pick = ask("Which one to stop seeding? (number, or blank to cancel)", "")
                #Only proceed on a genuinely valid pick.
                if pick.isdigit() and 1 <= int(pick) <= len(seeded_folders):
                    #Run it through the shared action dispatcher.
                    run_action(current_config, secret, "canary_remove", seeded_folders[int(pick) - 1])
                elif pick:
                    #Something was typed, but it was not a valid pick.
                    print("  Not a valid choice - nothing stopped.")
        elif choice == "9":
            #Ask which folder to start watching.
            folder_to_watch = ask("Folder to watch (full path, on the monitored machine)", "")
            #Only proceed if the user actually typed something.
            if folder_to_watch:
                #Run it through the shared action dispatcher.
                run_action(current_config, secret, "tripwire_add", folder_to_watch)
        elif choice == "10":
            #Show which folders are currently watched, as plain numbered
            #choices, rather than making the person retype a path by hand
            #for something this menu already knows the full list of.
            watched_paths = tripwire.load_state(current_config)["watched_paths"]
            if not watched_paths:
                #Nothing to stop watching.
                print("  Not watching any folders right now.")
            else:
                #Print each watched folder with its own pick number.
                print("  Currently watched folders:")
                for index, watched_path in enumerate(watched_paths, start=1):
                    print(f"   {index}) {watched_path}")
                #Read which one (by number) to stop watching.
                pick = ask("Which one to stop watching? (number, or blank to cancel)", "")
                #Only proceed on a genuinely valid pick.
                if pick.isdigit() and 1 <= int(pick) <= len(watched_paths):
                    #Run it through the shared action dispatcher.
                    run_action(current_config, secret, "tripwire_remove", watched_paths[int(pick) - 1])
                elif pick:
                    #Something was typed, but it was not a valid pick.
                    print("  Not a valid choice - nothing stopped.")
        elif choice == "11":
            #Explain the exact syntax before asking, so the user is not
            #guessing at the plain-English format.
            print('  Type a rule like: block ip 10.0.0.5   or   block port 4444   or   allow ip 10.0.0.5')
            #Read the typed rule.
            rule_text = ask("Rule", "")
            #Only proceed if the user actually typed something.
            if rule_text:
                #Run it through the shared action dispatcher.
                run_action(current_config, secret, "shield_rule", rule_text)
        elif choice == "12":
            #Ask for a clear typed confirmation before locking the firewall
            #down, since this is a destructive, hard-to-undo action.
            confirm = ask("Type MUTE to confirm locking down the firewall", "")
            #Only actually run it if they typed the exact confirmation word.
            if confirm == "MUTE":
                #Run it through the shared action dispatcher.
                run_action(current_config, secret, "shield_mute")
        elif choice == "13":
            #Run the Oracle's service + package scan.
            run_action(current_config, secret, "oracle")
        elif choice == "14":
            #Reach out (just this once, deliberately) to CISA's own KEV
            #feed and fold fresh hints into the offline file option 13
            #reads from. This is the one and only network call this
            #whole project makes to look up vulnerability data, and it is
            #meant to be run here on the analyst's own machine before a
            #competition starts, never mid-event.
            run_action(current_config, secret, "oracle_refresh_hints")
        elif choice == "15":
            #Attempt a best-effort VSS/LVM snapshot.
            run_action(current_config, secret, "snapshot")
        elif choice == "16":
            #Ask which real folder to roll back, then require the exact
            #typed confirmation word before actually overwriting it - the
            #same friction Shield: MUTE above already uses for a
            #different hard-to-undo action.
            folder_to_revert = ask("Folder to revert to the last snapshot (full path, on the monitored machine)", "")
            if folder_to_revert:
                confirm = ask(f"This OVERWRITES everything currently in {folder_to_revert} with whatever the last "
                              "snapshot held. Type RESTORE to confirm", "")
                if confirm == "RESTORE":
                    run_action(current_config, secret, "snapshot_revert", folder_to_revert)
                else:
                    print("  Not confirmed. Nothing was reverted.")
        elif choice == "17":
            #Generate the Markdown incident report from everything logged.
            run_action(current_config, secret, "scribe")
        elif choice == "18":
            #The Dashboard auto-started in the background the moment this
            #menu came up, so normally there is nothing left to do here but
            #remind the user where it is. Only if that auto-start failed
            #(the port was already taken by something else) do we fall
            #back to the old blocking behavior as a manual retry.
            if dashboard_server is not None:
                #Just reprint the link; the server is already running.
                print(f"  Dashboard already running in the background at http://127.0.0.1:{DASHBOARD_PORT}")
            else:
                #Fall back to trying to start it in the foreground instead.
                dashboard.run(DASHBOARD_PORT)
        elif choice == "19":
            #Print the full glossary of every cutesy module name.
            print_glossary()
        elif choice == "20":
            #Break out of the menu loop, ending the program.
            break


#Define main, the single entrypoint every launcher (poltergeist.py at the
#repo root, or the installed "poltergeist" command) actually calls.
def main():
    #Build the argument parser with a short description of the tool.
    parser = argparse.ArgumentParser(description="Poltergeist blue team audit tool")
    #Add a flag to force-run the setup wizard, even if a config exists.
    parser.add_argument("--wizard", action="store_true", help="run the setup wizard")
    #Add a flag to take a fresh baseline snapshot (refused if one is
    #already locked in).
    parser.add_argument("--baseline", action="store_true", help="take a baseline snapshot (refuses if one is already locked in - see --baseline-reset)")
    #Add an optional flag to clear a locked-in baseline, requiring the
    #exact confirmation word, the same friction --mute below requires.
    parser.add_argument("--baseline-reset", type=str, metavar="RESET", help='clear a locked-in baseline (moved to evidence/baseline_history/, never deleted) - e.g. --baseline-reset RESET')
    #Add a flag to run a single one-shot full scan.
    parser.add_argument("--check", action="store_true", help="run one full scan pass")
    #Add a flag to run the continuous monitor loop.
    parser.add_argument("--monitor", action="store_true", help="run the scan continuously on a timer")
    #Add an optional flag to override the configured scan interval.
    parser.add_argument("--interval", type=int, help="override the scan interval, in seconds")
    #Add a flag to plant a fresh set of canary (honeytoken) files.
    parser.add_argument("--canaries", action="store_true", help="plant a fresh set of canary (honeytoken) files")
    #Add a flag to run the Oracle's service/version + CVE hint scan.
    parser.add_argument("--oracle", action="store_true", help="scan running services for known-risky versions")
    #Add a flag for the PRE-COMPETITION-ONLY OSINT hint refresh - a single,
    #explicit, deliberate network call, never run automatically and never
    #dispatched to a remote target (see its own run_action branch above).
    parser.add_argument("--oracle-refresh-hints", action="store_true",
                         help="PRE-COMPETITION ONLY - pull fresh CVE hints from CISA's KEV feed into the offline hint file, while real internet access still exists")
    #Add a flag to attempt a best-effort VSS/LVM snapshot.
    parser.add_argument("--snapshot", action="store_true", help="attempt a whole-volume snapshot, if supported")
    #Add an optional flag to revert ONE folder back to the last snapshot -
    #this is destructive (it OVERWRITES live files), so it requires the
    #separate --revert-confirm RESTORE flag below too, the same two-piece
    #shape --baseline-reset/--mute use for their own typed confirmation,
    #just split across two flags here since this action also needs a path.
    parser.add_argument("--revert", type=str, metavar="FOLDER", help="revert this one folder back to the last snapshot - also requires --revert-confirm RESTORE")
    #The direct counterpart to --revert above - without the exact word,
    #--revert is refused, the same friction --mute/--baseline-reset use.
    parser.add_argument("--revert-confirm", type=str, metavar="RESTORE", help="required alongside --revert, e.g. --revert-confirm RESTORE")
    #Add a flag to write the Markdown incident report.
    parser.add_argument("--report", action="store_true", help="write a Markdown incident report from findings so far")
    #Add a flag to launch the localhost-only live dashboard.
    parser.add_argument("--dashboard", action="store_true", help="open the live findings dashboard (localhost only)")
    #Add an optional flag to apply one plain-English firewall rule and exit.
    parser.add_argument("--shield", type=str, help='apply one rule and exit, e.g. --shield "block ip 10.0.0.5"')
    #Add an optional flag to drop all traffic except trusted IPs, requiring
    #the exact confirmation word so this can never happen by accident.
    parser.add_argument("--mute", type=str, metavar="MUTE", help="drop all traffic except trusted IPs - e.g. --mute MUTE")
    #Add a flag to run the full scan once and exit - a plain synonym for
    #--check, kept for anyone already used to typing it.
    parser.add_argument("--quickscan", action="store_true", help="run one full scan and exit (same as --check)")
    #Add an optional flag to start watching a new folder with Tripwire.
    parser.add_argument("--watch", type=str, help="start watching this folder with Tripwire, baselining it right now")
    #Add an optional flag to stop watching a folder with Tripwire - the
    #direct counterpart to --watch above.
    parser.add_argument("--unwatch", type=str, help="stop watching this folder with Tripwire")
    #Add an optional flag to start seeding a new folder with Canary bait
    #files - the exact same shape as --watch above, for Canary instead.
    parser.add_argument("--seed", type=str, help="start seeding this folder with Canary bait files, planting them right now")
    #Add an optional flag to stop seeding a folder with Canary - the
    #direct counterpart to --seed above.
    parser.add_argument("--unseed", type=str, help="stop seeding this folder with Canary bait files")
    #Add a flag that prints this machine's own discovery data as JSON and
    #exits - this is what lets a remote wizard page get real, existence-
    #checked defaults for a target the exact same way a local one does
    #(see modules/remote.py's probe_target_remote), and it is handled
    #before any config/wizard machinery, same as --glossary, since the
    #whole point is to work on a machine that has no config of its own yet.
    parser.add_argument("--discover-json", action="store_true", help="print this machine's discovery data (networks, ports, OS, suggested paths) as JSON and exit - used internally when setting up a remote target, also useful standalone")
    #Add a flag that lists ONE folder's own contents as JSON and exits -
    #used internally so the GUI's folder-browser dialog (Tripwire's
    #"Watch a Folder" picker) can explore a REMOTE target's real
    #filesystem, one folder at a time, over SSH, the exact same way a
    #local browse explores this machine's own filesystem directly. A
    #bare "--list-dir" with nothing after it means "the OS-appropriate
    #starting point" (home directory, or the Windows drive list) - see
    #modules/fs_browse.py's own list_directory() for the full shape of
    #what gets printed.
    parser.add_argument("--list-dir", type=str, nargs="?", const="", default=None,
                         help="print one folder's own contents as JSON and exit - used internally by the GUI's remote folder browser")
    #Add a flag that lists which logs/Event Log channels THIS machine
    #actually has as JSON and exits - the remote-target half of "View
    #System Logs"' own log picker, same "run the same code over there"
    #idea as --list-dir just above.
    parser.add_argument("--list-logs", action="store_true",
                         help="print the list of logs/Event Log channels available on this machine as JSON and exit - used internally by the GUI's log viewer")
    #Add a flag that reads and analyzes ONE specific log/channel (by the
    #id --list-logs handed out) as JSON and exits - the remote-target
    #half of "View System Logs" opening one chosen log.
    parser.add_argument("--read-log", type=str,
                         help="read and analyze one specific log/channel (by id, from --list-logs) as JSON and exit - used internally by the GUI's log viewer")
    #Add a flag that prints the plain-English glossary of every module
    #name and exits immediately, with no config/wizard needed at all.
    parser.add_argument("--glossary", action="store_true", help="print what every module name (Sentinel, Oracle, etc) actually does, then exit")
    #Add a flag that explicitly asks for the gothic desktop GUI. This is
    #already the default when no flags at all are given and Tkinter is
    #available, so --gui mostly exists so --help documents that a GUI
    #exists at all, and for scripts/shortcuts that want to say so plainly.
    parser.add_argument("--gui", action="store_true", help="launch the desktop GUI (this is also the default with no flags, if Tkinter is available)")
    #Add a flag that skips the GUI attempt entirely and goes straight to
    #the plain text menu - useful over a plain SSH session with no
    #display, on a minimal box without Tkinter installed, or just by
    #preference. This only ever matters for how a LOCAL, flag-less launch
    #behaves; it has no bearing on what a remote target's own deployed
    #copy does, since that copy is always invoked with a specific flag.
    parser.add_argument("--text", action="store_true", help="always use the plain text menu instead of trying the GUI first")
    #Add a flag that prints the version/copyright/URL line and exits -
    #the same VERSION_LINE string shown under the banner and in the GUI
    #header, so "poltergeist --version" always matches what's on screen.
    parser.add_argument("--version", action="store_true", help="print the version number and exit")
    #Parse whatever arguments were actually passed on the command line.
    args = parser.parse_args()
    #--version is the most pure, config-free utility of all - handle it
    #before even --discover-json/--glossary below.
    if args.version:
        print(VERSION_LINE)
        return
    #--discover-json and --glossary are pure, config-free utilities and
    #must work before any config/wizard machinery is even considered.
    if args.discover_json:
        #Print this machine's own discovery data as one JSON line.
        print(json.dumps(discover()))
        #Return immediately; there is nothing else to do for this flag.
        return
    #--list-dir/--list-logs/--read-log are the same kind of pure,
    #config-free, "print one JSON answer and exit" utility as
    #--discover-json just above - none of them need (or touch) a saved
    #config at all, so they are handled here too, before any wizard/menu
    #machinery even starts.
    if args.list_dir is not None:
        #Print this one folder's own contents as one JSON line.
        print(json.dumps(fs_browse.list_directory(args.list_dir)))
        #Return immediately; there is nothing else to do for this flag.
        return
    if args.list_logs:
        #Print the list of logs/channels this machine actually has.
        print(json.dumps(log_review.list_available_logs()))
        #Return immediately; there is nothing else to do for this flag.
        return
    if args.read_log:
        #Print this one log/channel's own raw text + analysis.
        print(json.dumps(log_review.read_log_content(args.read_log)))
        #Return immediately; there is nothing else to do for this flag.
        return
    #The glossary is pure documentation and needs no machine config at
    #all, so handle it before anything else even looks for a config file.
    if args.glossary:
        #Print the full glossary.
        print_glossary()
        #Return immediately; there is nothing else to do for this flag.
        return
    #Work out, once, whether any scripted/headless action flag was passed -
    #reused both for the elevation check right below (so a scripted
    #invocation gets a plain stderr refusal, never an unexpected popup)
    #and for the interactive-vs-flag-driven branch right after it.
    any_action_flag = (args.wizard or args.baseline or args.baseline_reset or args.check or args.monitor
                        or args.canaries or args.oracle or args.oracle_refresh_hints or args.snapshot or args.revert
                        or args.report or args.dashboard or args.shield or args.mute or args.quickscan
                        or args.watch or args.unwatch)
    #Everything from here down genuinely needs elevated rights to see
    #anything real - refuse up front, once, rather than let someone run
    #for ten minutes and wonder why every section comes back empty. A
    #GUI popup is used only when this run was actually headed for the
    #GUI (no --text, and no scripted flag that bypasses it entirely).
    enforce_elevation_or_exit(prefer_gui=(not args.text and not any_action_flag))
    #If no ACTION flags at all were passed, this is a plain interactive
    #launch - decide between the GUI and the plain text menu. --gui and
    #--text are deliberately left out of this OR list, since neither one
    #requests a specific backend action; they only ever matter for the
    #decision made right below, once we already know no action was asked for.
    if not any_action_flag:
        #--text explicitly skips the GUI attempt and goes straight to the
        #plain text menu, no matter whether Tkinter is actually available.
        if args.text:
            #Hand off entirely to the text menu loop.
            run_menu()
            #Return immediately; the menu loop handles everything itself.
            return
        #Otherwise, try the GUI first (this is also what happens with no
        #flags at all, and what --gui explicitly asks for).
        gui_actually_ran = False
        try:
            #Import the gui package itself.
            from . import gui
            #Attempt to build and run the GUI window. Returns True only
            #if it actually started and the person has since closed it.
            gui_actually_ran = gui.launch_gui()
        #Catch anything at all that went wrong trying to even get this far.
        except Exception as gui_error:
            #Explain plainly what happened, without guessing why.
            print(f"  GUI not available ({gui_error}) - using the text menu instead.")
        #If the GUI never actually ran, fall back to the text menu instead
        #of the program simply doing nothing at all.
        if not gui_actually_ran:
            #Hand off to the text menu loop.
            run_menu()
        #Return either way; whichever path above handled everything.
        return
    #Specific flags were passed - this is scripted/headless use, so
    #unlike run_menu() above, the wizard is NOT forced on every call: load
    #whatever is already saved, and only run the wizard if nothing has
    #ever been configured here, or --wizard was explicitly asked for.
    if args.wizard:
        #Explicitly requested - run it, using whatever exists as defaults.
        active_config, secret = run_wizard_or_keep(load_config() if config_exists() else None)
    elif config_exists():
        #Already configured - load it, and pull any secret this target's
        #auth_mode needs from the environment (see secret_from_environment
        #above) rather than block on an interactive prompt that a script
        #has no way to answer.
        active_config = load_config()
        secret = secret_from_environment(active_config.get("target", {}))
    else:
        #Nothing configured yet - the wizard has to run at least once.
        active_config, secret = run_wizard_or_keep(None)
    #If there is still nothing valid to work with, stop here.
    if active_config is None:
        print("  No valid configuration. Exiting.")
        return
    #If the user passed a custom interval, override the loaded config with it.
    if args.interval:
        #Overwrite just the interval setting for this run.
        active_config["interval"] = args.interval
    #Run baseline if that flag was passed.
    if args.baseline:
        #Run it through the shared action dispatcher, lock and all.
        run_action(active_config, secret, "baseline")
    #Reset a locked-in baseline if that flag was passed, with the same
    #typed-confirmation requirement the interactive menu uses.
    if args.baseline_reset:
        #Only actually reset if the exact word was given.
        if args.baseline_reset == "RESET":
            #Run it through the shared action dispatcher.
            run_action(active_config, secret, "baseline_reset")
        else:
            #Print the expected format so the user can correct it.
            print('  Could not confirm. Use: --baseline-reset RESET')
    #Run a single full scan if either flag was passed - --check and
    #--quickscan are plain synonyms for the same action.
    if args.check or args.quickscan:
        #Run it through the shared action dispatcher.
        run_action(active_config, secret, "scan")
    #Run continuous monitoring if that flag was passed.
    if args.monitor:
        #Call our do_monitor helper, which loops do_check forever.
        do_monitor(active_config, secret)
    #Plant a fresh set of canary files if that flag was passed.
    if args.canaries:
        #Run it through the shared action dispatcher.
        run_action(active_config, secret, "canaries")
    #Run the Oracle's service/version scan if that flag was passed.
    if args.oracle:
        #Run it through the shared action dispatcher.
        run_action(active_config, secret, "oracle")
    #Run the PRE-COMPETITION-ONLY OSINT hint refresh if that flag was
    #passed - a single, explicit, deliberate network call.
    if args.oracle_refresh_hints:
        #Run it through the shared action dispatcher.
        run_action(active_config, secret, "oracle_refresh_hints")
    #Attempt a snapshot if that flag was passed.
    if args.snapshot:
        #Run it through the shared action dispatcher.
        run_action(active_config, secret, "snapshot")
    #Revert one folder back to the last snapshot if that flag was passed,
    #with the same typed-confirmation requirement the interactive menu
    #uses - split across two flags here since this action also needs a
    #path, unlike --mute/--baseline-reset's single combined flag.
    if args.revert:
        #Only actually run it if the exact confirmation word was given
        #too - a bare --revert FOLDER with no confirmation does nothing.
        if args.revert_confirm == "RESTORE":
            #Run it through the shared action dispatcher.
            run_action(active_config, secret, "snapshot_revert", args.revert)
        else:
            #Print the expected format so the user can correct it.
            print("  Could not confirm. Use: --revert FOLDER --revert-confirm RESTORE")
    #Write the incident report if that flag was passed.
    if args.report:
        #Run it through the shared action dispatcher.
        run_action(active_config, secret, "scribe")
    #Apply one plain-English firewall rule if that flag was passed.
    if args.shield:
        #Run it through the shared action dispatcher.
        run_action(active_config, secret, "shield_rule", args.shield)
    #Drop all traffic except trusted IPs if that flag was passed, with
    #the same typed-confirmation requirement the interactive menu uses.
    if args.mute:
        #Only actually run it if the exact confirmation word was given.
        if args.mute == "MUTE":
            #Run it through the shared action dispatcher.
            run_action(active_config, secret, "shield_mute")
        else:
            #Print the expected format so the user can correct it.
            print('  Could not confirm. Use: --mute MUTE')
    #Launch the dashboard if that flag was passed; this blocks until Ctrl+C.
    if args.dashboard:
        #Run the localhost-only live dashboard server, on THIS instance's
        #own port.
        dashboard.run(DASHBOARD_PORT)
    #Start watching a new folder with Tripwire if that flag was passed.
    if args.watch:
        #Run it through the shared action dispatcher.
        run_action(active_config, secret, "tripwire_add", args.watch)
    #Stop watching a folder with Tripwire if that flag was passed - the
    #direct counterpart to --watch above.
    if args.unwatch:
        #Run it through the shared action dispatcher.
        run_action(active_config, secret, "tripwire_remove", args.unwatch)
    #Start seeding a new folder with Canary bait files if that flag was
    #passed - the exact same shape as --watch above, for Canary instead.
    if args.seed:
        #Run it through the shared action dispatcher.
        run_action(active_config, secret, "canary_add", args.seed)
    #Stop seeding a folder with Canary if that flag was passed - the
    #direct counterpart to --seed above.
    if args.unseed:
        #Run it through the shared action dispatcher.
        run_action(active_config, secret, "canary_remove", args.unseed)
