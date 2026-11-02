#DESCRIPTION: This module is the "Tripwire" - a lighter-weight cousin of
#             Sentinel's integrity.py. integrity.py only watches the fixed
#             list of critical_paths from the setup wizard, and re-reading
#             it means waiting for a full baseline. Tripwire lets you add
#             ANY folder on the fly, mid-competition ("something looks
#             off in /var/www/uploads, watch it"), without touching the
#             main baseline at all. It hashes that folder right now as its
#             own starting point, then every future check compares against
#             that starting point and flags anything new, changed, or
#             removed. Because it reports through the same shared Log
#             object as every other module, a tripwire hit shows up on the
#             Dashboard exactly like any other finding - no extra wiring
#             needed to "pop an alert on the main page".

#import os and glob so we can walk a watched folder and find its files.
import os
import glob

#import json so this module can save/load its own watch list and hashes,
#the same pattern logging_health.py uses for its own size-tracking state.
import json

#import the sha256_of helper so tripwire hashes are computed exactly the
#same way as every other hash in this project.
from ..evidence import sha256_of

#Define MAX_WATCHED_PATHS: the hard cap on how many folders Tripwire will
#watch at once, for ONE running instance. This is a deliberate UX limit,
#not a technical one - a competitor juggling a dozen "quick watch this
#too" folders loses track of which ones actually matter, and the GUI's
#own add/remove buttons (see gui/app.py) need a small, fixed number
#anyway so the Dashboard's watched-path list and the "pick one to stop
#watching" dialog both stay a short, scannable list rather than growing
#without bound. Someone who genuinely needs more than this can always
#open a separate instance of Poltergeist (see config.py's own per-
#instance isolation) and watch more there instead.
MAX_WATCHED_PATHS = 3


#Define state_file_path, a tiny helper so this module's own watch-list
#file is always found at the same, predictable location.
def state_file_path(config):
    #Build the path inside the evidence directory.
    return os.path.join(config["evidence_dir"], "tripwire_state.json")


#Define load_state, which reads this module's own list of watched paths
#and their last-known file hashes.
def load_state(config):
    #Build the path to our state file.
    path = state_file_path(config)
    #If nothing has ever been watched, start from an empty structure.
    if not os.path.exists(path):
        #Return a fresh structure: a list of watched folders, plus a flat
        #dictionary of every individual file's last-known hash.
        return {"watched_paths": [], "file_hashes": {}}
    #Try to read and parse the state file.
    try:
        #Open and parse the JSON content.
        with open(path) as state_file:
            #Return the parsed state.
            return json.load(state_file)
    #If the file is corrupted for any reason, start fresh rather than crash.
    except Exception:
        #Return a fresh, empty structure.
        return {"watched_paths": [], "file_hashes": {}}


#Define save_state, which writes this module's updated watch list and
#hashes back to disk.
def save_state(config, state):
    #Open the state file for writing, creating it on the very first use.
    with open(state_file_path(config), "w") as state_file:
        #Write the dictionary back out as JSON.
        json.dump(state, state_file, indent=1)


#Define list_files_under, the same small helper pattern used in
#persistence.py and integrity.py, kept local so this module can be
#copy-pasted as a template for a future module without extra imports.
def list_files_under(path_or_pattern, cap=5000):
    #Start with an empty list of discovered file paths.
    found_files = []
    #Expand environment variables and "~" before globbing.
    expanded = os.path.expandvars(os.path.expanduser(path_or_pattern))
    #Match the pattern, falling back to the literal path if there is no
    #wildcard in it at all.
    matches = glob.glob(expanded) or [expanded]
    #Loop over every match the glob found.
    for matched_path in matches:
        #If the match is a folder, walk every file underneath it.
        if os.path.isdir(matched_path):
            #os.walk automatically recurses into every subfolder.
            for root, _, file_names in os.walk(matched_path):
                #Loop over every file name in this subfolder.
                for file_name in file_names:
                    #Record the full path to this one file.
                    found_files.append(os.path.join(root, file_name))
                    #Stop early once we hit the safety cap.
                    if len(found_files) >= cap:
                        #Return immediately to avoid hanging on a huge tree.
                        return found_files
        #If the match is a single file, record it directly.
        elif os.path.isfile(matched_path):
            #Add this one file path to the results.
            found_files.append(matched_path)
    #Hand back every file path discovered.
    return found_files


#Define add_path, called when the user asks to start watching a new
#folder. It hashes the folder RIGHT NOW and treats that as the clean
#starting point - it does not judge whether the folder is currently
#clean, so only add a tripwire to a folder you believe is okay right now.
def add_path(config, path):
    #Load the current watch state.
    state = load_state(config)
    #Refuse a genuinely NEW folder once MAX_WATCHED_PATHS is already
    #reached - re-adding a folder already being watched (re-baselining
    #it) is always allowed regardless of the cap, since the watch count
    #does not actually grow in that case.
    if path not in state["watched_paths"] and len(state["watched_paths"]) >= MAX_WATCHED_PATHS:
        #Hand back None, distinct from a real (possibly zero) file
        #count, so the caller can tell "rejected" apart from "watching
        #an empty/nonexistent folder" (which legitimately returns 0).
        return None
    #Only add this path if it is not already being watched.
    if path not in state["watched_paths"]:
        #Add it to the list of watched folders.
        state["watched_paths"].append(path)
    #Hash every file currently under this path as its starting point.
    files_found = list_files_under(path)
    #Loop over every file we found.
    for file_path in files_found:
        #Record its current hash as the "known good" starting value.
        state["file_hashes"][file_path] = sha256_of(file_path)
    #Save the updated watch state back to disk.
    save_state(config, state)
    #Tell the caller how many files were baselined, for a confirmation message.
    return len(files_found)


#Define remove_path, called when the user wants to stop watching a folder.
def remove_path(config, path):
    #Load the current watch state.
    state = load_state(config)
    #Remove this path from the watched list, if it was there.
    if path in state["watched_paths"]:
        #Remove it from the list.
        state["watched_paths"].remove(path)
    #Remove every individually hashed file that falls under this folder,
    #so stale entries do not linger forever in the state file.
    state["file_hashes"] = {f: h for f, h in state["file_hashes"].items() if not f.startswith(path)}
    #Save the updated watch state back to disk.
    save_state(config, state)


#Define check, the function modules/__init__.py registers for this
#module's LIVE_MODULES entry. Every watched folder gets re-hashed and
#compared against what was stored, every single check.
def check(config, log):
    #Load the current watch state.
    state = load_state(config)
    #If nothing is being watched, there is nothing to do.
    if not state["watched_paths"]:
        #Return immediately.
        return
    #Loop over every folder currently being watched.
    for watched_path in state["watched_paths"]:
        #Re-walk this folder to see what is there right now.
        current_files = list_files_under(watched_path)
        #Build a set of just this folder's previously known file paths,
        #so we can detect files that disappeared entirely.
        previously_known = {f for f in state["file_hashes"] if f.startswith(watched_path)}
        #Track which files we see this round, to compare against that set.
        seen_this_round = set()
        #Loop over every file currently under this watched folder.
        for file_path in current_files:
            #Remember that we saw this file this round.
            seen_this_round.add(file_path)
            #Compute its hash right now.
            current_hash = sha256_of(file_path)
            #Look up whether we have seen this exact file before.
            previous_hash = state["file_hashes"].get(file_path)
            #If we have never seen this file before, it is brand new.
            if previous_hash is None:
                #Report a new file at high severity.
                log.add("tripwire", "high", f"new:{file_path}", f"Tripwire ({watched_path}): NEW file {file_path}")
            #If we have seen it before but the hash changed, it was edited.
            elif previous_hash != current_hash:
                #Report a changed file at high severity.
                log.add("tripwire", "high", f"chg:{file_path}", f"Tripwire ({watched_path}): CHANGED file {file_path}")
            #Update the stored hash to the current one either way, so the
            #next check compares against this moment, not the original.
            state["file_hashes"][file_path] = current_hash
        #Any previously known file we did NOT see this round was removed.
        for missing_file in previously_known - seen_this_round:
            #Report the removal at medium severity.
            log.add("tripwire", "medium", f"del:{missing_file}", f"Tripwire ({watched_path}): file REMOVED: {missing_file}")
            #Drop it from the stored state so it is not reported again.
            del state["file_hashes"][missing_file]
    #Save the updated state so the next check compares against this round.
    save_state(config, state)
