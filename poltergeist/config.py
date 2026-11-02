#DESCRIPTION: This file is the single source of truth for Poltergeist's settings.
#             It knows where the config file lives, how to load it, how to save
#             it, and what a safe empty/default config looks like before the
#             setup wizard has ever been run. No other file should read or
#             write poltergeist_config.json directly; they should all call
#             the functions in here instead, so there is only one place that
#             can get the file format wrong.

#import the os module so we can build file paths that work on both Windows
#and Linux without hardcoding slashes or backslashes.
import os

#import sys so this file can tell whether it is running from a plain
#source checkout (python poltergeist.py) or from the packaged Windows
#.exe (see REPO_ROOT and DEPLOYABLE_SOURCE_ROOT just below for why that
#distinction matters) - sys.frozen and sys._MEIPASS are PyInstaller's own
#documented attributes for exactly this check, and sys.executable is the
#one path a frozen build can always trust.
import sys

#import the json module because the config file is stored as plain, human
#readable JSON so a teammate can open and hand-edit it if needed.
import json

#import atexit so the instance lock this file acquires below (see
#_select_instance_paths()) gets released automatically on a clean exit,
#without every single caller needing to remember to do it.
import atexit

#import psutil, already a dependency everywhere else in this project
#(discovery.py, modules/network.py, modules/processes.py), so the lock
#below can tell a genuinely still-running instance apart from a stale
#lock file left behind by one that crashed or was killed.
import psutil

#Build the absolute path to the folder this file lives in, so the config
#file is always found next to the code no matter where the tool is launched
#from (a teammate's Desktop, a USB stick, wherever) - THIS IS ONLY
#TRUSTWORTHY for a plain "python poltergeist.py" source checkout. A
#packaged Windows .exe (see packaging/windows/) runs every module out of
#PyInstaller's own in-memory/temp-extraction bundle instead of real files
#on disk, so __file__ here can point somewhere that is not a real,
#persistent folder at all once frozen - REPO_ROOT below corrects for that.
PACKAGE_DIR = os.path.dirname(os.path.abspath(__file__))

#Whether this process is the packaged .exe rather than a plain source
#checkout. getattr(..., False) rather than a bare sys.frozen because this
#attribute does not exist at all on a normal, non-frozen interpreter -
#PyInstaller's bootloader is what adds it.
IS_FROZEN = bool(getattr(sys, "frozen", False))

#Go one directory up from poltergeist/ to the repo root, which is where we
#want poltergeist_config.json and the evidence/ folder to actually live -
#UNLESS this is the packaged .exe, which the README deliberately tells
#people to "copy that one file anywhere you like" (see
#packaging/windows/build_exe.bat's own closing message). Once copied
#somewhere, PACKAGE_DIR's __file__-based math above no longer points at
#any real, writable folder the user can see - it points inside
#PyInstaller's own private bundle. The one path a frozen build can always
#trust is sys.executable: the actual .exe file's own location, which is
#exactly where a portable, double-clicked program's config/evidence
#belongs anyway (right next to the program itself, so moving the .exe
#takes its settings and evidence along with it).
REPO_ROOT = os.path.dirname(os.path.abspath(sys.executable)) if IS_FROZEN else os.path.dirname(PACKAGE_DIR)

#Define DEPLOYABLE_SOURCE_ROOT: the folder a REMOTE-target deploy should
#actually copy from (see modules/remote.py's deploy_to_target()). For a
#plain source checkout this is just REPO_ROOT - the same folder holding
#poltergeist.py and the poltergeist/ package tree already is the real,
#plain-text source a remote Linux target needs a copy of to run itself.
#
#The packaged .exe cannot use REPO_ROOT for this, even with the fix just
#above: REPO_ROOT for a frozen build now correctly points at wherever the
#user copied Poltergeist.exe to (fixing where ITS OWN config/evidence
#live), but there is usually no real poltergeist.py/poltergeist/ source
#tree sitting next to a copied single .exe file at all - that is the
#whole point of "copy that one file anywhere you like". Remote deploy
#still needs genuine, plain-text .py source to hand to the target's own
#python3 though (the target is almost always Linux, and an .exe obviously
#cannot run there), which is exactly why poltergeist.spec bundles a full,
#plain-text copy of that source INSIDE the .exe itself, under a
#"_deploy_source" folder (see that file's _collect_deploy_source_datas()
#for how it is built, kept automatically in sync with
#modules/remote.py's own deploy exclusion rules). sys._MEIPASS is
#PyInstaller's own documented attribute for where this one run's bundle
#was actually extracted to.
if IS_FROZEN:
    #Where the bundled, plain-text deploy source should be, if this build
    #actually included it (see poltergeist.spec).
    _bundled_deploy_source = os.path.join(getattr(sys, "_MEIPASS", ""), "_deploy_source")
    #Use the bundled copy if it is really there; an older or hand-built
    #.exe missing it falls back to REPO_ROOT (the .exe's own folder) -
    #strictly less likely to work than crashing outright would be wrong,
    #but it is still the best guess available without it.
    DEPLOYABLE_SOURCE_ROOT = _bundled_deploy_source if os.path.isdir(_bundled_deploy_source) else REPO_ROOT
else:
    #The normal case: a plain source checkout, where REPO_ROOT already is
    #exactly the folder a remote deploy needs to copy.
    DEPLOYABLE_SOURCE_ROOT = REPO_ROOT

#Define _MAX_INSTANCES, a sane upper bound on how many simultaneously
#running instances this file will ever look for a free slot among, purely
#so a pile of stuck/stale lock files can never turn _select_instance_paths
#below into an infinite loop. Nobody is realistically running more than a
#handful of Poltergeist instances at once in a single competition.
_MAX_INSTANCES = 25


#Define _is_lock_held_by_a_live_process, which reads a lock file (just a
#bare PID, written by whichever instance currently owns that config slot -
#see _select_instance_paths() below) and checks whether that PID actually
#belongs to a still-running process. A missing, empty, or unreadable lock
#file, or a PID that is no longer running (the instance that wrote it
#crashed, was killed, or was closed in some way that skipped the normal
#atexit cleanup), all count as "not held" - safe to reclaim.
def _is_lock_held_by_a_live_process(lock_path):
    #No lock file at all - definitely not held.
    if not os.path.exists(lock_path):
        return False
    try:
        with open(lock_path, "r") as lock_file:
            recorded_pid = int(lock_file.read().strip())
    #An empty or corrupted lock file is as good as no lock at all.
    except (ValueError, OSError):
        return False
    #psutil.pid_exists works the same way on Windows and Linux - exactly
    #the cross-platform check this project already leans on elsewhere.
    return psutil.pid_exists(recorded_pid)


#Define _select_instance_paths, which this file calls exactly ONCE, right
#below, the moment it is first imported - that happens exactly once per
#running Poltergeist process, so this effectively runs once per launch.
#
#Direct feedback from a real side-by-side test: two instances running at
#once (one per target, e.g. "sent1" and "sent2") were silently sharing
#the SAME poltergeist_config.json and evidence/ folder, since both are
#fixed paths next to the install. That meant whichever instance saved its
#settings LAST quietly overwrote the other's saved config, both instances
#showed the exact same (shared!) baseline lock and findings regardless of
#which target they were actually pointed at, and the "open a separate new
#instance to keep this one's baseline" advice this GUI itself now gives
#(see gui/app.py's _on_setup_clicked) was actively untrue.
#
#The fix: the FIRST instance to launch always claims the plain, unnumbered
#"poltergeist_config.json"/"evidence/" pair - every existing install's
#saved settings keep working exactly as before, no migration needed, and
#the common case of just one running instance never changes at all. Only
#once that slot is ACTIVELY held by another still-running process does a
#second (third, fourth...) simultaneous launch fall through to its own
#separate, numbered "poltergeist_config_2.json"/"evidence_2/" pair - a
#completely independent config, baseline, findings file, and (see
#DASHBOARD_PORT below) web Dashboard port, with nothing shared at all.
#Each slot is claimed with a small lock file (just this process's PID)
#next to its config file, released automatically on a clean exit (see
#atexit.register(_release_instance_lock) below) and self-healing on an
#unclean one (_is_lock_held_by_a_live_process above reclaims a slot the
#moment the PID that held it is no longer running, even if that process
#never got the chance to clean up after itself).
#
#This is deliberately a simple, best-effort lock (read-check-then-write,
#not real OS-level file locking) - two instances launched at the EXACT
#same instant could theoretically both claim the same slot, but that is
#an extreme edge case for a tool a human is clicking to open, and not
#worth the added complexity of a true cross-platform mutex here.
def _select_instance_paths():
    #Try the plain slot first, then each numbered one, until an unheld
    #one is found.
    for instance_number in range(1, _MAX_INSTANCES + 1):
        #Instance 1 is the plain, unnumbered pair; every one after that
        #gets "_2", "_3", and so on appended to both file names.
        suffix = "" if instance_number == 1 else f"_{instance_number}"
        candidate_config_path = os.path.join(REPO_ROOT, f"poltergeist_config{suffix}.json")
        candidate_evidence_dir = os.path.join(REPO_ROOT, f"evidence{suffix}")
        lock_path = candidate_config_path + ".lock"
        #Already held by a still-running process - try the next slot.
        if _is_lock_held_by_a_live_process(lock_path):
            continue
        #This slot is free (or its lock is stale) - claim it by writing
        #our own PID into its lock file.
        try:
            with open(lock_path, "w") as lock_file:
                lock_file.write(str(os.getpid()))
        #Could not even write the lock file (a read-only filesystem, odd
        #permissions) - treat this slot as unavailable rather than risk
        #two instances both believing they own it, and try the next one.
        except OSError:
            continue
        return instance_number, candidate_config_path, candidate_evidence_dir, lock_path
    #Every single slot up to the cap was actively held (an extreme,
    #unlikely pile-up) - fall back to the plain slot anyway rather than
    #refusing to start at all. Worst case, this behaves exactly like it
    #always did before this feature existed - no lock file this time,
    #since claiming one at this point would be a lie.
    return 1, os.path.join(REPO_ROOT, "poltergeist_config.json"), os.path.join(REPO_ROOT, "evidence"), None


#Define _release_instance_lock, registered with atexit right below so it
#runs automatically on a normal interpreter exit (closing the GUI window,
#Ctrl+C on the text menu, a --quickscan run finishing) - only ever removes
#the lock file if it STILL says our own PID, so this can never accidentally
#delete a different, later instance's lock in the rare case this process
#somehow lost its slot already.
def _release_instance_lock():
    if _INSTANCE_LOCK_PATH is None or not os.path.exists(_INSTANCE_LOCK_PATH):
        return
    try:
        with open(_INSTANCE_LOCK_PATH, "r") as lock_file:
            if lock_file.read().strip() == str(os.getpid()):
                os.remove(_INSTANCE_LOCK_PATH)
    #Never let cleanup-on-exit itself raise and mask whatever the program
    #was actually doing when it exited.
    except OSError:
        pass


#Actually select this process's own instance slot, once, right here at
#import time - INSTANCE_NUMBER, CONFIG_PATH, and DEFAULT_EVIDENCE_DIR
#(used by default_config() below) are then used exactly like plain
#constants everywhere else in the project, completely unchanged from
#before this feature existed for the common case of a single instance.
INSTANCE_NUMBER, CONFIG_PATH, DEFAULT_EVIDENCE_DIR, _INSTANCE_LOCK_PATH = _select_instance_paths()
atexit.register(_release_instance_lock)

#Define DASHBOARD_PORT, this instance's own web Dashboard port - 8765 for
#the first instance (unchanged from before), 8766 for a second
#simultaneously running one, 8767 for a third, and so on, so two
#instances' "Open Dashboard in Browser" buttons (and the status bar's own
#printed link) never collide or silently show each other's data. Every
#place that used to hardcode 8765 (gui/app.py, cli.py, dashboard.py's own
#default parameter) now reads this instead.
DASHBOARD_PORT = 8765 + (INSTANCE_NUMBER - 1)


#Define default_config as a function (not a plain dict) so every caller
#gets a fresh copy; sharing one dict object between callers would let one
#module's edits silently leak into another module's config.
def default_config():
    #Return a dictionary with every key the rest of the program expects to
    #exist, even though most of these empty/zero values get overwritten by
    #the setup wizard the first time someone actually runs the tool.
    return {
        #The declared type of machine this is (linux_web, windows_dc, etc),
        #used only to tailor the wizard's suggestions, nothing else.
        "role": "linux_generic",
        #List of CIDR networks (like "10.0.1.0/24") the team is defending.
        "networks": [],
        #List of CIDR networks that belong to VPN or red-team-access ranges.
        "vpn_networks": [],
        #List of IP addresses we trust by default (scoring engine, gateway).
        "trusted_ips": [],
        #List of ports that are expected to be open on a clean box.
        "expected_ports": [],
        #List of ports that should always be treated as suspicious.
        "watch_ports": [4444, 1337, 31337, 5555, 6666, 9001, 1234],
        #CPU percent a single process can use before we flag it.
        "cpu_threshold": 80.0,
        #Memory percent a single process can use before we flag it.
        "mem_threshold": 50.0,
        #List of files/folders whose hashes we track for tampering.
        "critical_paths": [],
        #Folder where all findings, backups, and captured samples go -
        #THIS instance's own evidence folder (see DEFAULT_EVIDENCE_DIR
        #above/_select_instance_paths' own comment for why this is not
        #always the plain "evidence/" - a second simultaneously running
        #instance gets its own "evidence_2/" automatically instead).
        "evidence_dir": DEFAULT_EVIDENCE_DIR,
        #Whether a changed critical file should be automatically restored
        #from its baseline copy (the tampered version is always saved first).
        "auto_restore": False,
        #How many seconds to wait between passes in --monitor mode, and how
        #often the GUI's main view automatically re-scans on its own.
        "interval": 15,
        #Which ONE machine this install is pointed at. "mode" is "local"
        #(audit the machine Poltergeist is actually running on, the usual
        #case) or "remote" (reach into one other machine over SSH every
        #time an action runs, using modules/remote.py). label is just a
        #friendly name shown in the GUI header and reports - it defaults to
        #the hostname (local) or host (remote) when left blank. auth_mode
        #is one of "agent_or_default" (let SSH's own agent or ~/.ssh keys
        #handle it - the normal case), "key_file" (a specific private key
        #file, picked in the wizard), or "password" (plain username +
        #password, for a box with no key-based login set up at all, such
        #as a practice/challenge VM). On purpose, there is NO password or
        #key-passphrase field here: whichever one is needed is typed into
        #the wizard each time Poltergeist starts and held in memory only
        #for that run - it is never written into this file, a log, or any
        #evidence Poltergeist produces.
        "target": {
            "mode": "local",
            "label": "",
            "host": "",
            "port": 22,
            "user": "",
            "remote_path": "poltergeist",
            "auth_mode": "agent_or_default",
            "key_path": "",
            #Which OS this target actually runs - "windows" or "linux",
            #set by the wizard straight from its own real probe of the
            #machine (never guessed). Empty until the wizard has actually
            #run once; the GUI's dynamic OS-aware taskbar icon (see
            #gui/icon.py) falls back to a plain ghost-only icon whenever
            #this is empty or not recognized.
            "os": "",
        },
    }


#Define load_config so every other file can get the current settings with
#one simple function call instead of re-reading and re-parsing JSON itself.
def load_config():
    #Check whether a config file already exists on disk.
    if not os.path.exists(CONFIG_PATH):
        #If it does not exist yet, return a safe set of defaults instead of
        #crashing, so the CLI can detect this and launch the wizard.
        return default_config()
    #Open the config file for reading using a "with" block so it is always
    #closed automatically even if something goes wrong while reading it.
    with open(CONFIG_PATH, "r") as config_file:
        #Parse the JSON text into a normal Python dictionary and store it.
        loaded = json.load(config_file)
    #Start from a fresh set of defaults so any keys missing from an older
    #config file (because we added a new setting later) still get a value.
    merged = default_config()
    #"target" is a nested dictionary, so work out its properly-merged form
    #BEFORE the general update below, so a config saved before some target
    #sub-key existed (or hand-edited to drop one) still gets that sub-key's
    #default instead of a flat dict.update() silently dropping it.
    merged_target = dict(merged["target"])
    if isinstance(loaded.get("target"), dict):
        #Let the saved sub-keys win over the defaults, same rule as below.
        merged_target.update(loaded["target"])
    #Overwrite the defaults with whatever the user actually saved, so their
    #real settings win but nothing is ever missing a key.
    merged.update(loaded)
    #Re-apply the properly-merged target LAST, since the line above would
    #otherwise have just replaced it wholesale with the raw saved version.
    merged["target"] = merged_target
    #Hand the completed, guaranteed-complete config back to the caller.
    return merged


#Define save_config so the wizard (and nothing else) can persist settings.
def save_config(config):
    #Make sure the evidence directory from this config actually exists on
    #disk before we finish saving, so later steps never crash on a missing
    #folder the very first time they try to write a finding to it.
    os.makedirs(config.get("evidence_dir", DEFAULT_EVIDENCE_DIR), exist_ok=True)
    #Open the config file for writing, creating it if this is the first run.
    with open(CONFIG_PATH, "w") as config_file:
        #Write the dictionary back out as nicely indented JSON so a human
        #can open the file later and actually read/edit it by hand.
        json.dump(config, config_file, indent=2)


#Define config_exists as a tiny helper so cli.py can decide whether to show
#the wizard automatically without duplicating the os.path.exists check.
def config_exists():
    #Return True only if the config file is actually sitting on disk.
    return os.path.exists(CONFIG_PATH)
