#DESCRIPTION: This module creates and watches "canary" files: files that
#             have no real reason to ever be opened by a legitimate user,
#             so the instant one is touched, it is a strong signal that
#             someone is poking around who should not be. This module only
#             ever DETECTS and ALERTS; it never kills a process or revokes
#             anyone's access automatically, because doing that to the
#             wrong process (a backup tool, a search indexer) could take
#             the whole box down ourselves. A human decides what to do
#             with a canary alert, the same as any other finding.
#
#             This is deliberately NOT the same thing as Tripwire
#             (modules/tripwire.py), even though both watch files and
#             both let the user pick a folder: Tripwire hashes REAL files
#             you already have and flags CONTENT CHANGE in them (did this
#             file get edited, added, or removed). Canary plants FAKE
#             bait files with tempting names and flags mere ACCESS (did
#               anyone so much as open one) - an early-warning honeytoken,
#             not an integrity check. Someone can edit a real config file
#             (Tripwire's job) without ever opening a fake flag.txt
#             (Canary's job), and vice versa - running both covers two
#             genuinely different kinds of intrusion signal.
#
#             Folder management here deliberately mirrors tripwire.py's
#             own add_path()/remove_path()/MAX_WATCHED_PATHS pattern
#             (same state-file shape, same cap, same GUI folder-browser
#             reuse) - bait files used to be hardcoded to only ever land
#             in config["evidence_dir"] itself, a location no real
#             attacker has any reason to browse, which made this feature
#             nearly useless as originally shipped. Letting the user pick
#             real, competition-specific locations (a web root, a shared
#             drive, wherever an attacker would actually look) is the
#             fix.

#import os so we can create files and read their last-access timestamps.
import os

#import glob only for the one case list_files helpers elsewhere in this
#project need it for - canary folders are never recursively walked (bait
#files are dropped directly into each chosen folder, not nested), so this
#module does not actually need it; kept out on purpose to keep this file
#as small as its job requires.

#import json so this module can save/load its own bait-folder list and
#planted-file manifest, the exact same pattern tripwire.py uses for its
#own watch list.
import json

#import platform and subprocess so the atime-reliability diagnostic below
#can tell Linux and Windows apart and run the one small OS command each
#needs to answer "will this filesystem even notice a file being opened".
import platform
import subprocess

#Store whether we are on Windows once for the whole module to reuse.
IS_WINDOWS = platform.system() == "Windows"

#Define MAX_CANARY_FOLDERS: the hard cap on how many real folders Canary
#will seed with bait files at once, for ONE running instance - the exact
#same reasoning, and the exact same number, as tripwire.py's own
#MAX_WATCHED_PATHS: a short, scannable list the GUI's own add/remove
#dialogs and the Dashboard's own display can show in full, not an
#unbounded one. Someone who genuinely needs more can open a separate
#instance of Poltergeist (see config.py's own per-instance isolation).
MAX_CANARY_FOLDERS = 3

#Define BAIT_NAMES, the short list of filenames that look valuable to an
#attacker but are completely harmless and fake - unchanged from before
#this round's folder-management rework.
BAIT_NAMES = ["flag.txt", "scoring_credentials.txt", "db_backup.sql", "ssh_keys_backup.zip"]


#Define state_file_path, a tiny helper so this module's own bait-folder
#list and planted-file manifest are always found at the same, predictable
#location - mirrors tripwire.py's own state_file_path() exactly.
def state_file_path(config):
    #Build the path inside the evidence directory.
    return os.path.join(config["evidence_dir"], "canary_state.json")


#Define load_state, which reads this module's own list of chosen bait
#folders and every path it has planted a canary into.
def load_state(config):
    #Build the path to our state file.
    path = state_file_path(config)
    #If no folders have ever been chosen, start from an empty structure.
    if not os.path.exists(path):
        #Return a fresh structure: the folders the user picked, plus the
        #flat list of every individual bait file path planted under them.
        return {"bait_folders": [], "planted_paths": []}
    #Try to read and parse the state file.
    try:
        #Open and parse the JSON content.
        with open(path) as state_file:
            #Return the parsed state.
            return json.load(state_file)
    #If the file is corrupted for any reason, start fresh rather than crash.
    except Exception:
        #Return a fresh, empty structure.
        return {"bait_folders": [], "planted_paths": []}


#Define save_state, which writes this module's updated bait-folder list
#and planted-file manifest back to disk.
def save_state(config, state):
    #Open the state file for writing, creating it on the very first use.
    with open(state_file_path(config), "w") as state_file:
        #Write the dictionary back out as JSON.
        json.dump(state, state_file, indent=1)


#Define run_command, a tiny helper identical in spirit to the one every
#other module in this project keeps a local copy of, used only by the
#atime-reliability check below.
def run_command(command):
    #Try to run the command and capture its output as text.
    try:
        #Give the command 10 seconds before giving up on it.
        result = subprocess.run(command, capture_output=True, text=True, timeout=10)
        #Return just the text that was printed to standard output.
        return result.stdout
    #If the command is missing or errors out, do not crash the caller.
    except Exception:
        #Return an empty string so the caller can treat it as "nothing".
        return ""


#Define atime_tracking_is_reliable, a best-effort honesty check for the
#one thing this whole module's detection depends on: the filesystem
#actually keeping a file's own last-ACCESS time (atime) up to date.
#check() below works by comparing a canary's atime against the moment it
#was planted - if the filesystem that folder lives on does not track
#atime at all, a canary could be opened, read, and copied by an
#attacker and this module would never know, with no error or warning
#anywhere. Two real-world cases this specifically catches:
#  - Linux: a filesystem mounted with "noatime" never updates atime at
#    all, ever. Very common on servers (it is a well-known performance
#    tweak). The much more common "relatime" (the modern Linux default)
#    is NOT flagged here - relatime still updates atime on a file's
#    FIRST real access after it was created (exactly the one access this
#    module needs to catch), it only skips updating it again on every
#    later read, which does not matter for a one-shot bait file.
#  - Windows: NTFS has disabled last-access-time tracking by default
#    since Vista (a registry/fsutil setting, "DisableLastAccess"), the
#    exact same silent gap.
#Returns (reliable: bool, reason: str or None) - reason is a short,
#plain-English explanation of what's wrong, filled in only when reliable
#is False, so plant_canaries() below can tell the user exactly what to
#fix (or just be aware of) for THIS specific folder, not a generic
#"might not work" shrug.
def atime_tracking_is_reliable(path):
    #Branch based on which operating system we are on.
    if IS_WINDOWS:
        #Ask Windows directly whether last-access tracking is disabled.
        output = run_command(["fsutil", "behavior", "query", "disablelastaccess"])
        #The command's own output contains a line like
        #"DisableLastAccess = 1" when tracking is OFF. A value of 0
        #(always enabled) or 2 (the modern "system managed" default,
        #which behaves as enabled on an ordinary fixed drive) both read
        #as reliable here - this is a best-effort check, not a perfect
        #one, and a false "reliable" costs far less than crying wolf on
        #every single Windows box using the modern default setting.
        if "disablelastaccess = 1" in output.lower():
            #Tracking is explicitly turned off system-wide.
            return False, ("this Windows machine has last-access-time tracking disabled "
                            "(the default since Windows Vista) - canary ACCESS may never be detected here. "
                            "Review with: fsutil behavior query disablelastaccess")
        #Either explicitly enabled, system-managed, or the command itself
        #was unavailable/failed - treat all of those as "no evidence of
        #a problem", which is the honest default.
        return True, None
    #On Linux/Unix, read /proc/mounts to find which real mount point this
    #path actually lives on, and what options it was mounted with.
    mounts_text = ""
    try:
        #/proc/mounts is a plain, always-readable text file on any real
        #Linux box; nothing here needs elevated permission to read it.
        with open("/proc/mounts") as mounts_file:
            #Read the whole thing - it is always tiny.
            mounts_text = mounts_file.read()
    #A missing /proc/mounts (not actually Linux, a minimal container
    #image, etc.) should never crash the plant - just skip the check.
    except Exception:
        #No evidence of a problem is available either way.
        return True, None
    #Resolve the real, absolute path (following any symlinks) so the
    #mount-point matching below compares like-for-like.
    real_path = os.path.realpath(path)
    #Track the best (longest, i.e. most specific) matching mount point
    #found so far, since /proc/mounts lists every mount, and a path can
    #sit under several of them at once (e.g. both "/" and "/home").
    best_match_len = -1
    best_match_options = ""
    #Walk every line of /proc/mounts.
    for line in mounts_text.splitlines():
        #Each line is: device mountpoint fstype options dump pass
        fields = line.split()
        #A malformed or unexpected line should never crash this check.
        if len(fields) < 4:
            #Skip this one line.
            continue
        mount_point, options = fields[1], fields[3]
        #Only consider this mount if the real path actually falls under
        #it (either an exact match, or the mount point plus a "/").
        if real_path == mount_point or real_path.startswith(mount_point.rstrip("/") + "/"):
            #Keep it only if it's a more specific (longer) match than
            #whatever we found so far.
            if len(mount_point) > best_match_len:
                #Remember this as the current best match.
                best_match_len = len(mount_point)
                best_match_options = options
    #Nothing matched at all (should not normally happen - "/" always
    #matches everything) - no evidence of a problem either way.
    if best_match_len == -1:
        #Treat this the same as "could not tell".
        return True, None
    #The one option that genuinely, always breaks this module's own
    #detection: noatime disables access-time updates completely.
    if "noatime" in best_match_options.split(","):
        #Tracking is confirmed off for this specific folder's filesystem.
        return False, ("the filesystem this folder lives on is mounted with \"noatime\" - "
                        "canary ACCESS will never be detected here. Review with: mount | grep noatime")
    #relatime (the modern Linux default) and everything else still
    #update atime on a bait file's first real access, which is the one
    #access this module actually needs - no warning needed.
    return True, None


#Define add_folder, called when the user asks to start seeding a new
#real folder with bait files - mirrors tripwire.py's own add_path()
#almost exactly: refuses a genuinely NEW folder once MAX_CANARY_FOLDERS
#is already reached, but always allows re-adding (re-seeding) a folder
#already on the list even at the cap, since the count does not grow.
def add_folder(config, folder):
    #Load the current bait-folder state.
    state = load_state(config)
    #Refuse a genuinely new folder once the cap is already reached.
    if folder not in state["bait_folders"] and len(state["bait_folders"]) >= MAX_CANARY_FOLDERS:
        #Hand back None, distinct from a real (possibly zero) planted
        #count, so the caller can tell "rejected" apart from "planted
        #into a folder Poltergeist could not actually write to" (0).
        return None
    #Only add this folder if it is not already on the list.
    if folder not in state["bait_folders"]:
        #Add it to the list of seeded folders.
        state["bait_folders"].append(folder)
    #Plant (or re-plant) bait files into just this one folder right now,
    #and check this folder's own atime reliability while we're at it.
    planted_here, reliable, reason = _plant_into_one_folder(folder)
    #Fold the newly planted paths into the flat manifest, without
    #duplicating any that were already recorded for this same folder
    #(a re-seed overwrites the files on disk, but the manifest entries
    #are already identical paths, so a plain union is correct).
    state["planted_paths"] = sorted(set(state["planted_paths"]) | set(planted_here))
    #Save the updated state back to disk.
    save_state(config, state)
    #Print the same honest, plain-English atime warning plant_canaries()
    #itself would print, so a solo "add one folder" click gets the exact
    #same heads-up a full re-plant would.
    if not reliable:
        print(f"  NOTE: {reason}")
    #Tell the caller how many bait files actually got planted here, for
    #a confirmation message.
    return len(planted_here)


#Define remove_folder, called when the user wants to stop seeding a
#folder. Unlike tripwire.py's remove_path() (which only ever stops
#WATCHING real files it never created), this also deletes the bait files
#THIS module itself planted in that folder - that is a deliberate,
#narrow exception to "never delete anything", the same spirit as the
#project's Shield MUTE / baseline-reset actions: it only ever removes
#synthetic files Poltergeist created for exactly this purpose, never
#anything that belongs to the monitored machine or an attacker, and only
#when the user explicitly asks to stop seeding this one folder.
def remove_folder(config, folder):
    #Load the current bait-folder state.
    state = load_state(config)
    #Remove this folder from the seeded list, if it was there.
    if folder in state["bait_folders"]:
        #Remove it from the list.
        state["bait_folders"].remove(folder)
    #Find every planted path that actually lives under this folder.
    normalized_folder = folder.rstrip("/\\")
    paths_here = [p for p in state["planted_paths"]
                  if p.startswith(normalized_folder + os.sep) or os.path.dirname(p) == normalized_folder]
    #Try to delete each bait file this module itself planted here.
    for bait_path in paths_here:
        #Wrap each delete separately so one missing/locked file never
        #stops the rest from being cleaned up.
        try:
            #Only ever remove a file that still exists.
            if os.path.isfile(bait_path):
                #Delete this one synthetic bait file.
                os.remove(bait_path)
        #A file already gone, or briefly locked, should never crash this.
        except Exception:
            #Nothing more to do for this one path.
            continue
    #Drop every entry for this folder from the flat manifest.
    state["planted_paths"] = [p for p in state["planted_paths"] if p not in paths_here]
    #Save the updated state back to disk.
    save_state(config, state)


#Define _plant_into_one_folder, the shared inner helper both
#plant_canaries() (every chosen folder) and add_folder() (just the one
#new folder) call - keeps the actual file-writing logic in exactly one
#place. Returns (planted_paths, atime_reliable, atime_reason) for this
#one folder.
def _plant_into_one_folder(folder):
    #Track every bait file path we successfully create in this folder.
    planted_paths = []
    #Loop over each fake filename we want to drop in this folder.
    for bait_name in BAIT_NAMES:
        #Build the full path for this one canary file.
        canary_path = os.path.join(folder, bait_name)
        #Try to write the fake file to disk.
        try:
            #Open the file for writing and put harmless filler text in
            #it so it looks plausible if someone opens it.
            with open(canary_path, "w") as canary_file:
                #Write an obviously fake but tempting-looking payload.
                canary_file.write("This file is monitored. Any access is logged.\n")
            #Remember this path as successfully planted.
            planted_paths.append(canary_path)
        #If we cannot write to this folder, just skip this one bait file -
        #a folder we cannot write to at all still gets caught below.
        except Exception:
            #Deliberately do nothing and move to the next bait file.
            continue
    #Check this one folder's own atime-tracking reliability, so the
    #caller can warn about it right alongside this specific location.
    reliable, reason = atime_tracking_is_reliable(folder)
    #Hand back everything the caller needs to report on this one folder.
    return planted_paths, reliable, reason


#Define plant_canaries, called to (re-)seed every currently chosen bait
#folder with a fresh set of fake files. If the user has never picked a
#folder yet (a brand new install, or someone who has not used the new
#"Canary: Choose a Bait Location" action), this safely falls back to
#config["evidence_dir"] alone - never nothing - so the action still does
#SOMETHING useful out of the box, exactly like it always has, while
#still making clear (via the printed note below) that this default
#location is not where a real attacker is likely to look.
def plant_canaries(config):
    #Load the current bait-folder state.
    state = load_state(config)
    #Fall back to evidence_dir alone if nothing has been chosen yet.
    bait_folders = state["bait_folders"] or [config["evidence_dir"]]
    #If we fell back to the default, say so plainly - this is exactly
    #the gap that made this feature nearly useless as originally
    #shipped: evidence_dir is Poltergeist's own working folder, not
    #anywhere a real attacker has a reason to browse.
    if not state["bait_folders"]:
        print("  NOTE: no bait locations chosen yet - planting into Poltergeist's own evidence "
              "folder only, which an attacker has no real reason to browse. Use "
              "\"Canary: Choose a Bait Location\" to seed a real spot instead (a web root, a "
              "shared drive, wherever someone poking around would actually look).")
    #Track every path planted across every folder, and collect which
    #folders (if any) turned out to have unreliable atime tracking.
    all_planted = []
    unreliable_notes = []
    #Loop over every folder we are seeding this time.
    for folder in bait_folders:
        #Plant into this one folder and check its own atime reliability.
        planted_here, reliable, reason = _plant_into_one_folder(folder)
        #Add this folder's planted paths to the running total.
        all_planted.extend(planted_here)
        #Remember this folder's own warning, if it has one.
        if not reliable:
            unreliable_notes.append(reason)
    #Persist the full, de-duplicated manifest of every planted path.
    #Deliberately does NOT write the evidence_dir fallback into
    #state["bait_folders"] when nothing has been chosen yet - that
    #fallback is only ever a one-time planting default, never something
    #that should start showing up as a "chosen" folder in the GUI's own
    #list or block a real folder from being added later.
    state["planted_paths"] = sorted(set(state["planted_paths"]) | set(all_planted))
    save_state(config, state)
    #Print one honest summary line, then every folder-specific atime
    #warning gathered above - exactly the "fails loudly and honestly"
    #standard this project's own Snapshot module already holds itself to.
    print(f"  Planted {len(all_planted)} canary file(s) across {len(bait_folders)} folder(s).")
    for note in unreliable_notes:
        #Each note already names which folder it's about.
        print(f"  NOTE: {note}")
    #Hand back the list of planted paths, same as before this round, in
    #case a caller wants it directly.
    return all_planted


#Define check, called from the live monitor loop to see whether any
#planted canary file has been read since we planted it.
def check(config, log):
    #Load the current bait-folder/manifest state - the canonical list of
    #what this module itself planted, replacing the old separate
    #canaries/manifest.txt text file this module used to keep (now
    #folded into the same canary_state.json folder management lives in).
    state = load_state(config)
    #If nothing has ever been planted, there is nothing to check yet.
    if not state["planted_paths"]:
        #Return immediately since this module has not been set up.
        return
    #Loop over every canary file we are currently watching.
    for canary_path in state["planted_paths"]:
        #Skip any canary that has been removed from disk entirely; that
        #is its own finding, reported separately by the integrity module.
        if not os.path.exists(canary_path):
            #Move on to the next canary in the list.
            continue
        #Read this file's last-access time from the filesystem.
        last_access_time = os.path.getatime(canary_path)
        #Read this file's creation/modification time as our planting time.
        planted_time = os.path.getmtime(canary_path)
        #If the file was accessed meaningfully after it was planted,
        #someone opened a file they had no legitimate reason to open.
        if last_access_time > planted_time + 2:
            #Report this at high severity; a human decides what to do next.
            #The suggestion points at recent logins and open files rather
            #than naming a process, since a file access alone does not
            #tell us which process touched it.
            fix = "review: who -a   (or Get-WinEvent -LogName Security -MaxEvents 50 on Windows) to see who was logged in when this was touched"
            log.add("deception", "high", f"canary:{canary_path}", f"Canary file was accessed: {canary_path}", suggested_fix=fix)
