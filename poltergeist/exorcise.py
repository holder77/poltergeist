#DESCRIPTION: This file holds the logic behind "poltergeist exorcise", the
#             command you run when something has clearly gone wrong and
#             you want to know exactly what changed since the clean
#             baseline. It never deletes or modifies anything on its own
#             unless auto_restore is turned on in the config, and even
#             then it ALWAYS saves a quarantine copy of the tampered file
#             before putting the clean version back, so nothing the red
#             team did is ever lost as evidence.

#import os and json so we can load the baseline.json file written by the
#baseline step and compare it against a fresh snapshot.
import os
import json

#import shutil so a restore can copy the clean baseline copy back over a
#tampered file, and so reset_baseline can move the old baseline aside
#instead of ever deleting it.
import shutil

#import datetime so reset_baseline can stamp the folder it moves the old
#baseline into with exactly when the reset happened.
from datetime import datetime, timezone

#import every state module through the registry in modules/__init__.py,
#so this file does not need to know the individual module names itself.
from .modules import STATE_MODULES

#import quarantine_file so a restore always preserves evidence first.
from .evidence import quarantine_file


#Define baseline_path, a tiny helper so the baseline file's location is
#computed the same way everywhere it is needed in this file.
def baseline_path(config):
    #Build the full path to baseline.json inside the evidence directory.
    return os.path.join(config["evidence_dir"], "baseline.json")


#Define baseline_files_dir, the folder holding each critical file's clean
#backup copy, so reset_baseline knows exactly what else to move aside
#alongside baseline.json itself.
def baseline_files_dir(config):
    #Build the full path to baseline_files/ inside the evidence directory.
    return os.path.join(config["evidence_dir"], "baseline_files")


#Define is_baseline_locked, the one check the unified action runner (see
#cli.py's run_action) uses to decide whether a "take a baseline" request
#is actually allowed to run right now. Once ANY baseline has been taken,
#this returns True, and stays True until reset_baseline() below is used -
#"Now once we hit that it's blocked to no longer use unless we accept a
#warning to reset it" is the whole reason this function exists, so taking
#a second baseline mid-competition can never accidentally happen with one
#careless click.
def is_baseline_locked(config):
    #A baseline exists the moment baseline.json has ever been written.
    return os.path.exists(baseline_path(config))


#Define reset_baseline, the ONLY way past the lock above. It never deletes
#the old baseline - consistent with every other part of this tool, which
#treats evidence/state as something to preserve, not discard - it moves
#baseline.json and baseline_files/ into a timestamped folder under
#evidence/baseline_history/ instead, so an old baseline is still sitting
#right there if anyone ever needs to look back at it. The caller (both
#front ends) is responsible for making the human actually confirm this
#first, the same typed-warning pattern already used for Shield: MUTE.
def reset_baseline(config):
    #If there is nothing to reset, say so rather than silently succeeding.
    if not is_baseline_locked(config):
        #Nothing to do; hand back None so the caller can tell the difference.
        return None
    #Build a sortable, filesystem-safe timestamp for this reset's folder.
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    #Build the destination folder this old baseline is moving into.
    history_dir = os.path.join(config["evidence_dir"], "baseline_history", stamp)
    #Make sure the parent baseline_history/ folder exists.
    os.makedirs(os.path.dirname(history_dir), exist_ok=True)
    #Move baseline.json itself into the new history folder.
    os.makedirs(history_dir, exist_ok=True)
    #Move the main baseline file, if it is actually there.
    old_baseline = baseline_path(config)
    if os.path.exists(old_baseline):
        #shutil.move, never a delete - the whole point of this function.
        shutil.move(old_baseline, os.path.join(history_dir, "baseline.json"))
    #Move the per-file clean-copy backups too, if any exist.
    old_backups = baseline_files_dir(config)
    if os.path.isdir(old_backups):
        #Move the whole folder in one step.
        shutil.move(old_backups, os.path.join(history_dir, "baseline_files"))
    #Hand back exactly where the old baseline now lives, so the caller can
    #tell the user precisely where to find it again if needed.
    return history_dir


#Define run_baseline, called once at the very start of a competition on a
#machine the team is confident is clean.
def run_baseline(config):
    #Make sure the folder for baseline file backups exists first.
    backup_dir = os.path.join(config["evidence_dir"], "baseline_files")
    #Create it now if this is the very first baseline ever taken.
    os.makedirs(backup_dir, exist_ok=True)
    #Start building the snapshot dictionary we will save to disk.
    snapshot = {"state": {}, "backups": {}}
    #Loop over every registered state module (persistence, users, integrity).
    for module_name, collect_function in STATE_MODULES.items():
        #Tell the person at the keyboard which module is being baselined.
        print(f"  baselining {module_name}...")
        #Call the module's collect function and store its result.
        snapshot["state"][module_name] = collect_function(config)
    #Loop over every file tracked specifically by the integrity module, so
    #we can keep a clean copy of each one to restore from later.
    for state_key in snapshot["state"].get("integrity", {}):
        #Pull the real file path back out of the "file:" prefixed key.
        file_path = state_key[len("file:"):]
        #Only back up files that actually exist on disk right now.
        if os.path.isfile(file_path):
            #Build a unique, flattened backup filename for this file.
            backup_name = os.path.basename(file_path) + "_" + str(abs(hash(file_path)))
            #Build the full destination path inside baseline_files/.
            backup_destination = os.path.join(backup_dir, backup_name)
            #Try to copy the clean file into the backup folder.
            try:
                #copy2 preserves file metadata along with the content.
                shutil.copy2(file_path, backup_destination)
                #Remember where this file's clean backup copy lives.
                snapshot["backups"][file_path] = backup_destination
            #If the copy fails for any reason, skip backing up this file.
            except Exception:
                #Deliberately do nothing and continue with the next file.
                pass
    #Save the completed snapshot to baseline.json.
    with open(baseline_path(config), "w") as baseline_file:
        #Write it as indented JSON so a human can inspect it if needed.
        json.dump(snapshot, baseline_file, indent=1)
    #Count how many total items were baselined across every module.
    total_items = sum(len(v) for v in snapshot["state"].values())
    #Tell the user the baseline is done and remind them of the one rule
    #this entire tool depends on: the box must actually be clean right now.
    print(f"  Baseline saved ({total_items} items). ASSUME THIS MACHINE IS CLEAN RIGHT NOW.")


#Define restore_file, which puts a tampered file back to its clean
#baseline version, but only after saving a quarantine copy of the
#tampered version first so nothing is ever lost.
def restore_file(config, file_path, snapshot):
    #Always quarantine whatever is currently on disk before touching it.
    quarantine_file(config, file_path)
    #Look up whether we actually have a clean backup copy of this file.
    backup_copy = snapshot["backups"].get(file_path)
    #Only attempt the restore if we truly have a clean copy saved.
    if backup_copy and os.path.isfile(backup_copy):
        #Copy the clean backup back over the tampered file.
        shutil.copy2(backup_copy, file_path)
        #Return True so the caller knows the restore actually happened.
        return True
    #If we have no clean copy to restore from, say so by returning False.
    return False


#Define run_exorcise, the function the "poltergeist exorcise" command
#actually calls. It diffs the current state against the saved baseline
#and reports (and optionally restores) every difference it finds.
def run_exorcise(config, log):
    #Confirm a baseline actually exists before trying to diff against it.
    if not os.path.exists(baseline_path(config)):
        #Tell the user clearly why nothing can be compared yet.
        print("  No baseline found. Run the baseline step first, on a clean box.")
        #Return early since there is nothing further this function can do.
        return
    #Load the saved baseline snapshot back into memory.
    with open(baseline_path(config)) as baseline_file:
        #Parse the JSON content into a normal Python dictionary.
        snapshot = json.load(baseline_file)
    #Loop over every registered state module the same way baseline did.
    for module_name, collect_function in STATE_MODULES.items():
        #Pull this module's saved baseline state, defaulting to empty.
        old_state = snapshot["state"].get(module_name, {})
        #Collect this module's current state fresh, right now.
        new_state = collect_function(config)
        #Find every key that exists now but did not exist at baseline time.
        for added_key in new_state.keys() - old_state.keys():
            #Report each newly appeared item as a high severity finding.
            log.add(module_name, "high", f"add:{added_key}", f"NEW since baseline: {added_key}")
        #Find every key that existed at baseline time but is gone now.
        for removed_key in old_state.keys() - new_state.keys():
            #Report each disappeared item as a medium severity finding.
            log.add(module_name, "medium", f"del:{removed_key}", f"REMOVED since baseline: {removed_key}")
        #Find every key that exists in both, but whose value has changed.
        for shared_key in old_state.keys() & new_state.keys():
            #Compare the old and new values for this one key.
            if old_state[shared_key] != new_state[shared_key]:
                #Report the change as a high severity finding.
                log.add(module_name, "high", f"chg:{shared_key}", f"CHANGED since baseline: {shared_key}")
                #Only attempt an automatic restore for the integrity module,
                #since persistence/users changes often need a human
                #decision (do we really want to delete that cron job?).
                if module_name == "integrity" and config.get("auto_restore") and shared_key.startswith("file:"):
                    #Pull the real file path back out of the state key.
                    file_path = shared_key[len("file:"):]
                    #Attempt the restore, which always quarantines first.
                    if restore_file(config, file_path, snapshot):
                        #Report the successful restore as its own finding.
                        log.add(module_name, "info", f"restored:{file_path}", f"Restored {file_path} from baseline (tampered copy saved in quarantine/)")
