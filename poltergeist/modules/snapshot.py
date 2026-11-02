#DESCRIPTION: This module is "the Medium" - the last-resort undo button.
#             It is NOT a replacement for the regular file backups
#             integrity.py and exorcise.py already keep; it is a bigger,
#             whole-volume safety net using the operating system's own
#             snapshot feature (Volume Shadow Copy on Windows, LVM on
#             Linux). It only works if the box was actually set up with
#             an LVM volume or VSS available BEFORE the competition
#             starts, which is not guaranteed on every competition image,
#             so every function here fails loudly and honestly instead of
#             pretending to have made a snapshot it could not actually take.
#
#             take_snapshot() below does REAL volume-group/logical-volume
#             discovery on Linux (no more hardcoded, made-up device names)
#             and REAL shadow-copy device lookup on Windows, and
#             revert_directory() is now actually implemented on both
#             OSes - it was previously just a TODO stub that printed "not
#             wired up yet" and returned False no matter what. Honesty
#             note, since this matters: the sandbox this was written in
#             has no real LVM volume group and no real Windows VSS
#             environment at all, so the discovery/mount/device-lookup
#             steps below could only be checked against their OWN honest
#             failure paths here ("lvm2 isn't installed", "root isn't on
#             LVM", etc - all genuinely true and tested in this sandbox).
#             The actual mount-the-snapshot-and-copy-files-back step
#             (_mirror_directory() below) is pure Python and WAS fully
#             tested end-to-end against real temp directories. Try this
#             for real, deliberately, on a throwaway LVM/VSS box before
#             trusting it on a real competition machine - the suggested-
#             command philosophy everywhere else in this project exists
#             for exactly this reason: a human should look before
#             anything touches real files, and this action is no
#             different just because a human clicked a confirm dialog
#             instead of pasting a suggested command into their own shell.

#import platform so we know whether to use VSS or LVM commands.
import platform

#import subprocess so we can actually run the snapshot commands.
import subprocess

#import os for path checks/joins and resolving real device paths (used to
#match a mount's reported source device against lvs' own listing).
import os

#import json for this module's own small state file (which volume/
#logical-volume/shadow-copy was actually captured by take_snapshot()),
#the exact same load_state()/save_state() shape tripwire.py and
#deception.py already use.
import json

#import re to pull the ShadowID/DeviceObject fields out of wmic's plain
#text output on Windows - wmic has no JSON mode, only this.
import re

#import shutil for copy2 (preserves timestamps) and rmtree, used by
#_mirror_directory() below to actually restore files from a snapshot.
import shutil

#import tempfile so revert_directory() on Linux can create (and always
#clean up) its own private mount point, rather than hardcoding one fixed
#path that could collide with something else already using it.
import tempfile

#import datetime so this module can stamp its own state file with a
#plain "when was this snapshot actually taken" timestamp.
import datetime

#Store whether we are on Windows once for the whole module to reuse.
IS_WINDOWS = platform.system() == "Windows"


#Define run_command, the same small wrapper pattern used in every other
#module, kept local so this module has no outside dependency beyond the
#standard library.
def run_command(command):
    #Try to run the command and capture both its output and any error
    #text, since snapshot failures are common and we want to show why.
    try:
        #Give the command up to 60 seconds; snapshots can take a while.
        result = subprocess.run(command, capture_output=True, text=True, timeout=60)
        #Return both the output and whether it actually succeeded.
        return result.stdout + result.stderr, result.returncode == 0
    #If the command itself is missing or errors out before running, treat
    #that the same as a failed command rather than crashing the tool -
    #this is also exactly how "lvm2 isn't even installed" (vgs/lvcreate
    #missing entirely) gets caught below: Python raises FileNotFoundError,
    #which lands right here.
    except Exception as error:
        #Return the exception text as the output, with success=False.
        return str(error), False


#Define _now_iso, a tiny shared helper so every timestamp this module
#writes to its own state file looks the same - plain, sortable, and
#explicitly UTC (same spirit as evidence.py's own now(), kept separate
#here rather than importing evidence.py, since this module has no other
#reason to depend on it and the project generally prefers a small local
#copy over a cross-module import for something this short).
def _now_iso():
    #Format the current UTC moment as a plain "YYYY-MM-DDTHH:MM:SSZ" string.
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


#Define state_file_path, a tiny helper so this module's own record of
#what was actually snapshotted (which volume, which logical volume or
#shadow copy) always lives at the same, predictable location - mirrors
#tripwire.py's/deception.py's own state_file_path() exactly.
def state_file_path(config):
    #Build the path inside the evidence directory.
    return os.path.join(config["evidence_dir"], "snapshot_state.json")


#Define load_state, which reads back whatever take_snapshot() last
#recorded about the current snapshot, so revert_directory() can find it
#again without re-discovering the whole LVM/VSS layout from scratch.
def load_state(config):
    #Build the path to our state file.
    path = state_file_path(config)
    #If no snapshot has ever been taken, there is nothing to load.
    if not os.path.exists(path):
        #Return an empty dict - callers check "if not state:" either way.
        return {}
    #Try to read and parse the state file.
    try:
        #Open and parse the JSON content.
        with open(path) as state_file:
            #Return the parsed state.
            return json.load(state_file)
    #If the file is corrupted for any reason, treat it the same as "no
    #snapshot recorded" rather than crashing.
    except Exception:
        #Return an empty dict.
        return {}


#Define save_state, which writes take_snapshot()'s own record of what it
#just captured back to disk, for revert_directory() to read later.
def save_state(config, state):
    #Open the state file for writing, creating it on the very first use.
    with open(state_file_path(config), "w") as state_file:
        #Write the dictionary back out as JSON.
        json.dump(state, state_file, indent=1)


#Define _linux_find_root_logical_volume, which answers one specific
#question honestly: "is the root filesystem ('/') actually sitting on an
#LVM logical volume on THIS box, and if so, which one?" Returns
#(found, info_or_reason) - info_or_reason is a dict with "vg_name",
#"lv_name", "lv_path" when found is True, or a plain human-readable
#explanation string when it is False. Deliberately split into separate
#steps (rather than one combined check) so the reason given is always the
#TRUE reason - "lvm2 isn't installed" is a very different situation from
#"lvm2 is installed, but this particular box's root isn't on an LVM
#volume at all", and a user deciding whether to even bother setting this
#up needs to know which one they are looking at.
def _linux_find_root_logical_volume():
    #Step 1: does this box even have the lvm2 tools, and do they work at
    #all? "vgs" with no arguments lists every volume group - the single
    #cheapest command that tells us both "is this installed" and "does
    #anything exist" at once.
    vgs_output, vgs_ok = run_command(["vgs", "--noheadings", "-o", "vg_name"])
    if not vgs_ok:
        #Either lvm2 genuinely isn't installed (the usual case - Python
        #raises FileNotFoundError, caught by run_command above, and its
        #text ends up right here), or it's installed but something about
        #running it failed for another reason - either way, say so.
        return False, f"lvm2 does not appear to be usable on this box (running 'vgs' failed: {vgs_output.strip()[:150]})"
    if not vgs_output.strip():
        #lvm2 itself works fine, there's just nothing defined with it.
        return False, "lvm2 is installed and working, but this box has no LVM volume groups defined at all"
    #Step 2: which actual device is "/" mounted from right now?
    root_device, findmnt_ok = run_command(["findmnt", "-n", "-o", "SOURCE", "--target", "/"])
    root_device = root_device.strip()
    if not findmnt_ok or not root_device:
        #This should essentially never happen (every running Linux box
        #has SOME device mounted as "/"), but never assume it.
        return False, 'could not determine which device the root filesystem ("/") is actually mounted from'
    #Step 3: is THAT device an LVM logical volume, or plain partitioning
    #(a regular partition, a bare disk, software RAID, etc)? "lsblk"'s
    #own TYPE column says "lvm" only for an actual logical volume device.
    device_type, lsblk_ok = run_command(["lsblk", "-no", "TYPE", root_device])
    if not lsblk_ok or device_type.strip() != "lvm":
        #The honest, common case on a box that was never set up with LVM
        #at all - no amount of retrying fixes this; the partitioning
        #itself would have to change before this feature could work here.
        return False, (f'the root filesystem ("/") is on {root_device}, which is NOT an LVM logical '
                        "volume on this box - it's on plain partitioning, so this kind of snapshot "
                        "isn't possible here")
    #Step 4: now that we know root IS on some logical volume, match that
    #exact device against "lvs"' own listing to learn its real volume-
    #group and logical-volume names (needed to build the lvcreate command
    #below) - resolving both sides through os.path.realpath() first,
    #since the same device is often reachable through more than one path
    #(a /dev/mapper/... symlink and a /dev/<vg>/<lv> path both point at
    #the same real block device).
    lvs_output, lvs_ok = run_command(["lvs", "--noheadings", "-o", "vg_name,lv_name,lv_path"])
    if not lvs_ok:
        return False, f"'lvs' failed while looking up volume names: {lvs_output.strip()[:150]}"
    root_device_real = os.path.realpath(root_device)
    for line in lvs_output.splitlines():
        #Each line is "  vgname   lvname   /dev/vgname/lvname" - split on
        #whitespace rather than assuming fixed column widths.
        parts = line.split()
        if len(parts) != 3:
            #Not a line in the shape we expect; skip rather than guess.
            continue
        vg_name, lv_name, lv_path = parts
        if os.path.realpath(lv_path) == root_device_real:
            #Found the match - this is the logical volume root actually
            #lives on.
            return True, {"vg_name": vg_name, "lv_name": lv_name, "lv_path": lv_path}
    #lsblk said root IS an lvm-type device, but lvs' own listing never
    #matched it - an unusual, inconsistent state worth reporting plainly
    #rather than guessing at a volume name.
    return False, f"could not match {root_device} to any logical volume 'lvs' listed - this box's LVM layout is unusual"


#Define _mirror_directory, the one piece of this module that IS fully,
#end-to-end testable without any real LVM/VSS environment at all, since
#it is pure Python working against two plain directories on disk - one
#being whatever this OS's snapshot technology exposes as a read-only
#view of the past (a mounted LVM snapshot's own folder on Linux, or a
#VSS shadow copy's device path on Windows), the other being the live
#folder to restore. Makes dest_dir end up an EXACT mirror of source_dir:
#copies every file so dest matches what the snapshot held, AND removes
#anything from dest_dir that the snapshot does NOT have - a revert that
#only ever added files back would leave anything an attacker (or an
#innocent mistake) ADDED since the snapshot still sitting there, which
#defeats the point of "roll this back to what it looked like before".
#Returns (ok, message).
def _mirror_directory(source_dir, dest_dir):
    #The snapshot might simply not contain this folder at all - it may
    #not have existed yet when the snapshot was taken, or the path might
    #be mistyped. Either way, say so plainly rather than silently wiping
    #dest_dir's contents based on an empty/missing source.
    if not os.path.isdir(source_dir):
        return False, f"the snapshot does not contain this folder ({source_dir} not found inside it) - it may not have existed yet when the snapshot was taken"
    try:
        #Pass 1: remove anything already in dest_dir that the snapshot
        #does NOT have, walking bottom-up (topdown=False) so a directory
        #being removed is already empty of its own now-removed children
        #by the time shutil.rmtree() would otherwise need to recurse.
        for root, dirs, files in os.walk(dest_dir, topdown=False):
            #Work out where this same spot would be inside source_dir.
            relative = os.path.relpath(root, dest_dir)
            source_root = source_dir if relative == "." else os.path.join(source_dir, relative)
            #Remove any file dest has that source does not.
            for name in files:
                if not os.path.exists(os.path.join(source_root, name)):
                    os.remove(os.path.join(root, name))
            #Remove any subfolder dest has that source does not.
            for name in dirs:
                if not os.path.exists(os.path.join(source_root, name)):
                    shutil.rmtree(os.path.join(root, name))
        #Pass 2: copy everything FROM the snapshot ONTO dest_dir, creating
        #folders as needed and overwriting any file already there so it
        #matches the snapshot's own version exactly.
        for root, dirs, files in os.walk(source_dir):
            relative = os.path.relpath(root, source_dir)
            dest_root = dest_dir if relative == "." else os.path.join(dest_dir, relative)
            os.makedirs(dest_root, exist_ok=True)
            for name in files:
                #copy2 (not plain copy) also carries over the snapshot's
                #own modified time, so a file untouched since the
                #snapshot looks genuinely untouched afterward too.
                shutil.copy2(os.path.join(root, name), os.path.join(dest_root, name))
        return True, f"{dest_dir} now matches the snapshot exactly"
    #Catch anything at all that goes wrong partway through (a permissions
    #error, a file vanishing mid-walk) and report it plainly rather than
    #leaving the caller to guess whether the revert actually finished.
    except Exception as exc:
        return False, f"error while copying from the snapshot: {exc}"


#Define take_snapshot, called once at the start of a competition (right
#after the clean baseline) if the user wants this extra layer of safety.
def take_snapshot(config, log):
    #Branch based on which operating system we are on - each OS's own
    #implementation is split into its own function below, since the two
    #have essentially nothing in common beyond "try, and report honestly".
    if IS_WINDOWS:
        return _take_snapshot_windows(config, log)
    return _take_snapshot_linux(config, log)


#Define _take_snapshot_linux, the real (no longer hardcoded/placeholder)
#Linux half of take_snapshot(). Discovers the box's own actual LVM
#layout with _linux_find_root_logical_volume() above, then creates a
#real LVM snapshot of whatever logical volume root is really on.
def _take_snapshot_linux(config, log):
    #Work out exactly which logical volume root is really on - or the
    #honest reason we can't, which becomes the finding's own message.
    found, info = _linux_find_root_logical_volume()
    if not found:
        #info is the plain-English reason string in this branch.
        log.add("snapshot", "medium", "failed", f"Snapshot could NOT be taken (this box may not support it): {info}", quiet_dupes=False)
        return False
    #info is the {"vg_name", "lv_name", "lv_path"} dict in this branch.
    vg_name, lv_path = info["vg_name"], info["lv_path"]
    #This box only ever keeps ONE Poltergeist snapshot at a time, under
    #this fixed, predictable name.
    snapshot_lv_path = f"/dev/{vg_name}/poltergeist_snap"
    #If a Poltergeist snapshot from an EARLIER run already exists, reuse
    #it rather than silently failing - or, worse, auto-removing it to
    #make room for a fresh one. Deleting it would need its own separate,
    #explicit, user-invoked action (the same reasoning deception.py's
    #own remove_folder() documents for why that ONE delete is allowed at
    #all) - take_snapshot() itself never deletes anything.
    existing_output, existing_ok = run_command(["lvs", "--noheadings", "-o", "lv_name", vg_name])
    if existing_ok and "poltergeist_snap" in existing_output:
        save_state(config, {
            "platform": "linux", "vg_name": vg_name, "lv_name": info["lv_name"],
            "origin_lv_path": lv_path, "snapshot_lv_path": snapshot_lv_path, "taken_at": _now_iso(),
        })
        log.add("snapshot", "medium", "reused_existing",
                f"A Poltergeist snapshot already existed from an earlier run ({snapshot_lv_path}) - "
                "this box only keeps one at a time, so nothing NEW was taken. If you want a fresh one, "
                f"remove the old one yourself first (suggested: lvremove {snapshot_lv_path}) and run "
                "this again.", quiet_dupes=False)
        #Still True - a usable (if stale) snapshot genuinely does exist.
        return True
    #Create a real snapshot, sized at 20% of the origin volume's own
    #size ("--extents 20%ORIGIN") rather than a hardcoded, possibly-too-
    #small-or-too-large fixed byte count - lvcreate itself works out the
    #real number from the origin volume's actual size, and fails loudly
    #(caught and reported below, not silently) if the volume group
    #simply doesn't have that much free space to spare.
    output, ok = run_command(["lvcreate", "--snapshot", "--name", "poltergeist_snap", "--extents", "20%ORIGIN", lv_path])
    if ok:
        save_state(config, {
            "platform": "linux", "vg_name": vg_name, "lv_name": info["lv_name"],
            "origin_lv_path": lv_path, "snapshot_lv_path": snapshot_lv_path, "taken_at": _now_iso(),
        })
        log.add("snapshot", "info", "taken",
                f"Snapshot taken of the root filesystem's logical volume ({lv_path}) as "
                f"{snapshot_lv_path} (sized at 20% of the origin volume, via LVM)", quiet_dupes=False)
        return True
    #lvcreate itself failed (not enough free space in the volume group is
    #the most likely real-world reason) - report its own output honestly.
    log.add("snapshot", "medium", "failed", f"Snapshot could NOT be taken (this box may not support it): {output.strip()[:200]}", quiet_dupes=False)
    return False


#Define _take_snapshot_windows, the real (no longer silently-missing-its-
#own-ID) Windows half of take_snapshot(). Creates a VSS shadow copy
#exactly as before, but now also parses its own ShadowID and looks up
#the matching device path right away - without that device path,
#revert_directory() below would have no way to ever find this snapshot
#again, no matter how successfully it was created.
def _take_snapshot_windows(config, log):
    #Ask VSS to create a new shadow copy of the C: drive.
    create_output, create_ok = run_command(["wmic", "shadowcopy", "call", "create", "Volume=C:\\"])
    if not create_ok:
        #Could not even run the creation command - "wmic" missing
        #entirely (recent Windows builds have started removing it) is
        #one real possibility worth naming plainly, alongside the more
        #generic "this box may not support it".
        log.add("snapshot", "medium", "failed",
                "Snapshot could NOT be taken (this box may not support it, or 'wmic' isn't available - "
                f"some newer Windows builds have removed it): {create_output.strip()[:200]}", quiet_dupes=False)
        return False
    #wmic's own "call create" output includes a line like:
    #    ShadowID = "{GUID-LOOKING-STRING}";
    #Pull that GUID out so the next lookup can ask about THIS specific
    #new shadow copy, not just "whichever one is newest" (which could be
    #wrong if something else on the box is also taking shadow copies).
    shadow_id_match = re.search(r'ShadowID\s*=\s*"(\{[0-9A-Fa-f-]+\})"', create_output)
    if not shadow_id_match:
        #Creation reported success, but its own output didn't look the
        #way this code expects - say so rather than guessing at an ID.
        log.add("snapshot", "medium", "unparseable",
                "wmic reported success, but this module could not find the new shadow copy's own ID "
                f"in its output - revert will not be possible until this is fixed. Raw output: {create_output.strip()[:200]}",
                quiet_dupes=False)
        return False
    shadow_id = shadow_id_match.group(1)
    #Now look up THIS shadow copy's own device path - the thing
    #revert_directory() below actually needs to read files back out of
    #it later.
    lookup_output, lookup_ok = run_command(["wmic", "shadowcopy", "where", f"ID='{shadow_id}'", "get", "DeviceObject", "/value"])
    device_match = re.search(r"DeviceObject=(.+)", lookup_output)
    if not lookup_ok or not device_match:
        log.add("snapshot", "medium", "unparseable",
                f"Snapshot {shadow_id} was created, but this module could not look up its own device "
                "path afterward - revert will not be possible until this is fixed.", quiet_dupes=False)
        return False
    #Strip any trailing whitespace/carriage return wmic's text output
    #tends to leave on a /value field.
    device_object = device_match.group(1).strip()
    save_state(config, {"platform": "windows", "volume": "C:", "shadow_id": shadow_id, "device_object": device_object, "taken_at": _now_iso()})
    log.add("snapshot", "info", "taken", f"Snapshot taken of C:\\ via Volume Shadow Copy (id {shadow_id})", quiet_dupes=False)
    return True


#Define revert_directory, called when the user wants to roll one specific
#folder back to the snapshot taken at the start of the competition. This
#is deliberately scoped to one folder at a time rather than the whole
#disk, so a bad revert cannot undo more than the operator asked for. This
#OVERWRITES live files in target_path to match the snapshot - the one
#deliberate, user-invoked, typed-confirmation-gated exception to this
#project's "never touch real files" rule (see cli.py's/menu_actions.py's
#own RESTORE confirmation gate; this function itself assumes that
#confirmation already happened, exactly like lockdown.mute() assumes
#Shield's own MUTE confirmation already happened before IT is called).
def revert_directory(config, log, target_path):
    #Load whatever take_snapshot() last recorded. Nothing recorded at all
    #means nothing has ever been snapshotted on this box - there is
    #simply nothing to revert FROM yet.
    state = load_state(config)
    if not state:
        print('  No snapshot has been taken yet on this box - run "Medium: Take Snapshot" first. Nothing was reverted.')
        return False
    #Confirm the target is a real, existing folder on THIS machine before
    #doing anything else - a typo'd path should fail here, plainly,
    #rather than partway through a mount/copy sequence.
    if not os.path.isdir(target_path):
        print(f"  {target_path} is not a real, existing folder on this machine - nothing was reverted.")
        return False
    #Branch based on which operating system we are on, same split as
    #take_snapshot() above.
    if IS_WINDOWS:
        return _revert_directory_windows(log, state, target_path)
    return _revert_directory_linux(log, state, target_path)


#Define _revert_directory_linux, the real (no longer a TODO stub) Linux
#half of revert_directory(). Mounts the LVM snapshot read-only to a
#throwaway temporary mount point, mirrors the one requested folder back
#from inside it, then always unmounts and cleans up afterward - even if
#the mirror step itself fails partway through.
def _revert_directory_linux(log, state, target_path):
    #The saved state has to actually BE a Linux LVM snapshot - a stale
    #state file left over from a different OS (copied in from a Windows
    #target's own evidence, say) must never be acted on as if it were.
    if state.get("platform") != "linux":
        print("  The saved snapshot state here is not a Linux LVM snapshot - nothing was reverted.")
        return False
    #Confirm target_path is actually ON the same logical volume that got
    #snapshotted - a folder living on a SEPARATE mount point (a different
    #LVM volume, a different disk entirely) was never captured by this
    #particular snapshot at all, and reverting it from the wrong
    #snapshot would silently restore the wrong data rather than failing
    #loudly, which is far worse than just refusing.
    target_device, findmnt_ok = run_command(["findmnt", "-n", "-o", "SOURCE", "--target", target_path])
    if not findmnt_ok or os.path.realpath(target_device.strip()) != os.path.realpath(state["origin_lv_path"]):
        print(f"  {target_path} is not on the volume that was snapshotted ({state['origin_lv_path']}) - nothing was reverted.")
        return False
    #Create a fresh, private mount point just for this one revert - never
    #a fixed shared path, so this can never collide with anything else
    #(another instance, a leftover mount from a previous failed run)
    #already using that same path.
    mount_point = tempfile.mkdtemp(prefix="poltergeist_snap_mount_")
    mount_output, mount_ok = run_command(["mount", "-o", "ro", state["snapshot_lv_path"], mount_point])
    if not mount_ok:
        print(f"  Could not mount the snapshot ({mount_output.strip()[:200]}) - nothing was reverted.")
        #Nothing was actually mounted, so just clean up the empty folder.
        try:
            os.rmdir(mount_point)
        except OSError:
            pass
        return False
    try:
        #The snapshot is a point-in-time copy of the WHOLE root
        #filesystem, so the requested folder lives inside it at the same
        #absolute path, just rooted under mount_point instead of "/".
        source_inside_snapshot = os.path.join(mount_point, target_path.lstrip("/"))
        ok, message = _mirror_directory(source_inside_snapshot, target_path)
    #Always unmount and remove the temporary mount point afterward, even
    #if _mirror_directory() raised or returned a failure - leaving a
    #snapshot mounted (or a stray empty folder sitting under /tmp)
    #forever would be its own small mess left behind by this "undo".
    finally:
        run_command(["umount", mount_point])
        try:
            os.rmdir(mount_point)
        except OSError:
            pass
    if ok:
        log.add("snapshot", "info", f"reverted:{target_path}",
                f"Reverted {target_path} back to the state captured by the last snapshot ({state['taken_at']})",
                quiet_dupes=False)
        print(f"  Reverted. {message}")
    else:
        print(f"  Revert failed: {message}")
    return ok


#Define _revert_directory_windows, the real (no longer a TODO stub)
#Windows half of revert_directory(). A VSS shadow copy's device path is
#directly readable like any other path once you know it (the classic
#backup-tool trick, no extra driver or tool required), so this needs no
#separate "mount" step the way Linux's LVM snapshot does - it goes
#straight to _mirror_directory() once the right sub-path is worked out.
def _revert_directory_windows(log, state, target_path):
    #The saved state has to actually BE a Windows VSS snapshot.
    if state.get("platform") != "windows":
        print("  The saved snapshot state here is not a Windows VSS snapshot - nothing was reverted.")
        return False
    #Confirm target_path is on the SAME drive the snapshot covers - this
    #module only ever snapshots C:\, so a folder on a different drive
    #letter was never captured by it at all.
    drive, path_without_drive = os.path.splitdrive(target_path)
    if drive.rstrip("\\").upper() != state["volume"].rstrip("\\").upper():
        print(f"  {target_path} is on a different drive than the one snapshotted ({state['volume']}) - nothing was reverted.")
        return False
    #Build the matching path INSIDE the shadow copy: the same device
    #object wmic handed back when the snapshot was taken, plus whatever
    #comes after the drive letter in the live path.
    source_inside_snapshot = state["device_object"] + path_without_drive
    ok, message = _mirror_directory(source_inside_snapshot, target_path)
    if ok:
        log.add("snapshot", "info", f"reverted:{target_path}",
                f"Reverted {target_path} back to the state captured by the last snapshot ({state['taken_at']})",
                quiet_dupes=False)
        print(f"  Reverted. {message}")
    else:
        print(f"  Revert failed: {message}")
    return ok
