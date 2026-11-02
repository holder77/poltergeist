#DESCRIPTION: This file is Poltergeist's evidence locker. Every module that
#             finds something suspicious reports it through the Log class
#             defined here, which prints it to the screen AND writes it to
#             findings.jsonl on disk. This file also holds the helper
#             functions that copy a suspicious process's details and binary
#             somewhere safe, and the quarantine helper that saves a
#             tampered file before anything restores it. Nothing in this
#             program is ever allowed to delete evidence; this file exists
#             to make that rule easy to follow everywhere else.

#import os so we can build paths and create folders for evidence storage.
import os

#import json so findings and process snapshots are saved in a format that
#is both human-readable and easy to re-load for a report later.
import json

#import shutil so we can copy files (binaries, tampered configs) without
#ever touching the original file's permissions or deleting anything.
import shutil

#import hashlib so every copied file can be named by its own hash, which
#makes it easy to prove later that a copy was never altered after capture.
import hashlib

#import datetime so every finding and every captured file gets a precise,
#sortable timestamp for the incident report.
import datetime

#import colorize so every printed finding is color-coded by severity.
from .color import colorize

#import ntp_sync so every timestamp this file stamps is corrected
#against a real NTP time source (when one is reachable) instead of
#blindly trusting whichever machine's own system clock happened to be
#running - the direct fix for "timestamps need to match" when findings
#from more than one machine (the analyst's own, and a remote target,
#each with its own clock) end up in the same report. See ntp_sync.py's
#own top comment for the full reasoning, including why this never slows
#down or breaks a scan even on a network that blocks NTP outright, and
#for why this file lives at the top level of the package rather than
#inside modules/ (importing it from inside modules/ would recreate a
#circular import with this very file).
from . import ntp_sync


#Define a small helper function that returns the current time as a
#plain, sortable text string, so every other function in this file
#stamps events the exact same way instead of each writing its own
#timestamp format. Returns an explicit, unambiguous UTC timestamp (with
#a trailing "Z", ISO 8601's own marker for "this is UTC, not some
#unstated local time") rather than the old bare local-clock reading -
#a timestamp with no timezone attached is exactly what made findings
#logged on two different machines (or two different machines set to two
#different timezones) impossible to line up correctly in one report.
#Every caller downstream (report.py especially) converts this back into
#whichever timezone it wants to actually DISPLAY, but what gets stored
#on disk is always this same, unambiguous instant.
def now():
    #ntp_sync.corrected_utcnow() already falls back to this machine's
    #own uncorrected system clock (offset 0.0) if NTP could not be
    #reached at all, so this always returns a real, usable timestamp -
    #never raises, never blocks noticeably (the NTP query itself is
    #cached and timeout-bounded - see ntp_sync.py), and is only ever as
    #good as this machine's own clock in the worst case, never worse.
    corrected_now = ntp_sync.corrected_utcnow()
    #Format down to the second, with an explicit "Z" (UTC) suffix -
    #isoformat() on a timezone-aware UTC datetime already appends
    #"+00:00"; swap that for the shorter, equally standard "Z" so every
    #timestamp this project writes reads the same way a judge or a log-
    #analysis tool would expect "this is Zulu time" to look.
    return corrected_now.isoformat(timespec="seconds").replace("+00:00", "Z")


#Define format_ts_for_display, the one shared function every place that
#actually SHOWS a finding's own stored "ts" value to a person - the web
#Dashboard (dashboard.py), the GUI's live findings table
#(gui/findings_view.py), and the incident report (report.py, which adds
#its own fuller "(UTC-07:00)"-style wording on top of this same idea) -
#calls to turn that stored, unambiguous UTC instant into whatever
#timezone THIS machine (wherever the Dashboard/GUI/report is actually
#being looked at from) is currently set to. Before this existed, every
#one of those three places printed the raw "...Z" string verbatim - correct,
#but easy to misread as "stale" when it's really just UTC sitting next
#to a wall clock that's reading Mountain/Pacific/whatever time instead.
#A timestamp recorded before this round's NTP/explicit-UTC fix (no
#trailing "Z" at all) is handed back completely unchanged, since there
#is no way to know after the fact which timezone it was actually
#written in - guessing would be worse than leaving it as-is.
def format_ts_for_display(ts_string):
    if not ts_string.endswith("Z"):
        #Pre-existing, naive timestamp from before this fix - nothing
        #safe to convert.
        return ts_string
    try:
        #Parse the stored "...Z" string back into a timezone-aware UTC
        #datetime, then let astimezone() (with no argument) ask the
        #operating system what timezone THIS machine is currently set
        #to, DST included - the same zero-hardcoded-location approach
        #report.py's own _format_local() already uses.
        utc_dt = datetime.datetime.strptime(ts_string, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)
        local_dt = utc_dt.astimezone()
        return local_dt.strftime("%Y-%m-%d %H:%M:%S %Z")
    #A genuinely malformed timestamp should never break a findings
    #table or a web page over one bad row - fall back to the raw text.
    except ValueError:
        return ts_string


#Define load_findings_file, the one canonical copy of the small helper
#that reads one findings.jsonl-shaped file into a plain list of dicts.
#dashboard.py, gui/findings_view.py, and gui/live_dashboard.py each used
#to keep their own near-identical copy of this; it moved here once
#latest_state() below (which all three also need) became load-bearing
#for correctness, not just a formatting nicety - three independent copies
#of logic that findings actually disappearing from the Dashboard depends
#on is exactly the kind of thing that quietly drifts out of sync.
def load_findings_file(path):
    #If the file doesn't exist yet, there's nothing to load.
    if not os.path.exists(path):
        #Return an empty list rather than crash on a missing file.
        return []
    #Open the file and parse every non-blank line as one JSON finding.
    with open(path) as findings_file:
        #Return every parsed finding found in the file.
        return [json.loads(line) for line in findings_file if line.strip()]


#Define latest_state, which collapses a flat list of findings down to
#just the single most recent record for each distinct (module, key)
#pair. findings.jsonl is an APPEND-only log - Log.add() below only
#de-dupes identical repeats WITHIN one scan pass (do_check() builds a
#fresh Log every single cycle - see cli.py - so even that in-pass dedup
#starts over each time) - so an ongoing, unchanged condition legitimately
#gets re-logged on every single scan. Collapsing down to "the newest
#record per (module, key)" is what turns that growing history into "here
#is the current state of each distinct thing being tracked", which is
#what every live-updating view (the web Dashboard, the GUI findings
#table, the GUI's own Dashboard tab) actually wants to show. This alone
#does NOT make a genuinely resolved finding disappear or go green - if a
#key is never asserted again at all (the thing it was tracking is simply
#gone), the last record logged for it stays "the newest one" forever.
#That second half of the problem is resolve_stale()'s job, just below.
def latest_state(findings):
    #Map each (module, key) pair to the single newest finding seen for
    #it so far. findings is expected in the same append order
    #load_findings_file() reads it in - i.e. already chronological, since
    #findings.jsonl is only ever appended to - which matters for the tie-
    #break just below: timestamps are only stored to whole-second
    #precision (see now()'s own comment in this file), so two findings
    #from two back-to-back scan passes (an original flag, then
    #resolve_stale()'s own "resolved" line a moment later) can land in
    #the exact same second. On a tie, keep whichever one was seen LATER
    #in that chronological order (">=", not ">"), not whichever happened
    #to be seen first - otherwise a finding resolved within the same
    #second it was first flagged could still show as the stale original.
    latest_by_identity = {}
    #Walk every finding exactly once, in order.
    for finding in findings:
        #Build this finding's dedup identity.
        identity = (finding.get("module"), finding.get("key"))
        #Keep whichever one has the later-or-equal timestamp, preferring
        #the one seen later in iteration order on an exact tie.
        existing = latest_by_identity.get(identity)
        if existing is None or finding.get("ts", "") >= existing.get("ts", ""):
            #This is the newest version of this (module, key) seen so far.
            latest_by_identity[identity] = finding
    #Hand back just the values, newest first.
    return sorted(latest_by_identity.values(), key=lambda f: f.get("ts", ""), reverse=True)


#Define resolve_stale, the other half of "findings should reflect what's
#actually true right now, not just what was ever true once" - the direct
#fix for a finding (a flagged process, a dropped file) staying on every
#Dashboard forever even after the process was killed or the file deleted
#by hand, simply because nothing ever told the Dashboard the condition
#went away.
#
#A live-check module (processes.py's check(), persistence.py's
#check_foothold_directories()) calls this once, at the end of its own
#pass, handing back the full set of keys it found to still be true THIS
#scan - current_keys. This function loads the set of keys that were true
#as of the PREVIOUS scan (persisted to a small JSON file under
#evidence_dir/live_state/, since do_check() builds a brand new Log, with
#no memory of earlier cycles, every single time - see cli.py), and for
#any key that was true before but is missing from current_keys now, logs
#ONE new low-severity finding under that SAME (module, key) - so
#latest_state() above naturally picks it up as the newest record for
#that identity, flipping what the Dashboard shows for it from a
#stale, already-handled high/medium-severity alert to a plain
#"no longer detected" note, without ever deleting the original evidence
#of what was found (findings.jsonl is still append-only; this only ever
#adds a new line, same as every other finding).
#
#state_name is a separate label from module on purpose: "persistence"
#and "integrity" are both module names that more than one different
#check function reports findings under (persistence.py's own baseline-
#diff collect(), its live check()'s several different sub-checks, and
#integrity.py's own baseline-diff collect() all share one of those two
#module names) - state_name scopes this function's own "what was true
#last cycle" memory to just the one specific check that called it,
#so two unrelated checks that happen to log under the same module name
#never stomp on each other's resolve-tracking state.
def resolve_stale(config, log, module, state_name, current_keys):
    #Build the small per-check state file's path, creating the folder it
    #lives in the first time this is ever called.
    state_dir = os.path.join(config["evidence_dir"], "live_state")
    os.makedirs(state_dir, exist_ok=True)
    state_path = os.path.join(state_dir, f"{state_name}.json")
    #Load what was true as of the previous scan pass, tolerating a first-
    #ever run (no file yet) or a corrupted/partial file the same way
    #every other small state file in this project does.
    try:
        with open(state_path) as f:
            previously_active = set(json.load(f))
    except (FileNotFoundError, json.JSONDecodeError):
        #Nothing recorded yet - treat this as "nothing was active before".
        previously_active = set()
    #Anything that was active before but is not in the fresh set this
    #check just reported has, by definition, stopped being true.
    newly_resolved = previously_active - current_keys
    #Report each one as its own low-severity "resolved" finding, in a
    #stable sorted order so test output and real runs are both
    #deterministic rather than depending on set iteration order.
    for key in sorted(newly_resolved):
        #quiet_dupes=False because this exact key was deliberately never
        #in this cycle's fresh Log's own "seen" set - there is nothing to
        #de-dupe against, and this should always get its own new line.
        log.add(module, "info", key,
                "Previously flagged - no longer detected as of this scan (resolved). "
                "The original finding above is kept as evidence, not deleted.",
                quiet_dupes=False)
    #Persist this cycle's active set as the new "last cycle" baseline for
    #next time, whether or not anything actually resolved just now.
    with open(state_path, "w") as f:
        json.dump(sorted(current_keys), f)


#Define sha256_of so any file's integrity hash can be computed the same
#way everywhere in the project, whether for baselining or for evidence.
def sha256_of(path):
    #Try to open and hash the file, since the file might disappear or be
    #permission-locked between the moment we see it and the moment we hash it.
    try:
        #Create an empty SHA-256 hash object to feed the file into.
        hasher = hashlib.sha256()
        #Open the target file in binary mode so text-encoding never matters.
        with open(path, "rb") as f:
            #Read the file in 1 megabyte chunks instead of all at once, so
            #hashing a huge log file does not blow up memory usage.
            for chunk in iter(lambda: f.read(1 << 20), b""):
                #Feed each chunk into the running hash calculation.
                hasher.update(chunk)
        #Return the finished hash as a readable hex string.
        return hasher.hexdigest()
    #Catch any failure (file deleted, permission denied, etc).
    except Exception:
        #Return a clear marker instead of crashing the whole scan.
        return "UNREADABLE"


#Define safe_filename so we never try to write a file using a path that
#contains slashes or illegal characters, by turning any path into one
#short, flat, collision-resistant filename.
def safe_filename(original_path):
    #Hash the full original path so two files with the same base name in
    #different folders never collide when we flatten them into one folder.
    path_hash = hashlib.sha1(original_path.encode()).hexdigest()[:16]
    #Grab just the last 40 characters of the real filename so the result
    #stays readable to a human looking through the evidence folder.
    short_name = os.path.basename(original_path)[:40]
    #Glue the hash and the short name together with an underscore.
    return f"{path_hash}_{short_name}"


#Define the Log class, which every check module uses to report a finding.
#Using a class (instead of a bare function) lets us remember which findings
#we have already printed, so a monitor loop does not spam the same warning
#every 15 seconds forever.
class Log:
    #Define the constructor, which runs once when a Log object is created.
    def __init__(self, config):
        #Save the evidence directory path from the config so every method
        #below knows where findings.jsonl should live.
        self.evidence_dir = config["evidence_dir"]
        #Make sure the evidence directory actually exists before we try to
        #write into it, in case this is the very first run.
        os.makedirs(self.evidence_dir, exist_ok=True)
        #Build the full path to the append-only findings log file.
        self.path = os.path.join(self.evidence_dir, "findings.jsonl")
        #Create an empty set to remember (module, key) pairs we have
        #already reported, so repeat scans do not re-print the same thing.
        self.seen = set()

    #Define add, the one method every module calls to report a finding.
    #suggested_fix is optional, plain-English/command text telling the
    #human what to type to look closer or to safely pause something -
    #this tool NEVER runs that command itself, it only ever suggests it.
    def add(self, module, severity, key, message, quiet_dupes=True, suggested_fix=None):
        #Check whether we should skip this finding because we already
        #reported the exact same (module, key) combination before.
        if quiet_dupes and (module, key) in self.seen:
            #Return False so the caller knows nothing new was logged.
            return False
        #Remember this (module, key) pair so we do not repeat it later.
        self.seen.add((module, key))
        #Build a dictionary holding everything about this one finding.
        record = {
            #Stamp exactly when the finding happened.
            "ts": now(),
            #Record which module raised the finding (processes, network...).
            "module": module,
            #Record how serious the finding is (info, medium, high).
            "severity": severity,
            #Record the unique key used for de-duplication.
            "key": key,
            #Record the human-readable explanation of what happened.
            "message": message,
            #Record the suggested next command, or None if there isn't one.
            "fix": suggested_fix,
        }
        #Open findings.jsonl in append mode so nothing already written is
        #ever overwritten or lost, only ever added to.
        with open(self.path, "a") as f:
            #Write this one finding as a single line of JSON text.
            f.write(json.dumps(record) + "\n")
        #Print the finding to the screen right away so whoever is sitting
        #at the keyboard during the competition sees it immediately. The
        #severity word is colorized (high=red, medium=yellow, info=cyan)
        #so the most important findings are visible at a glance; color.py
        #automatically falls back to plain text when color is not safe.
        severity_label = colorize(f"[{severity.upper():6}]", severity)
        print(f"{severity_label} {module:11} {message}")
        #If a suggested fix was given, print it on its own indented line
        #right under the finding, clearly labeled as a suggestion only.
        if suggested_fix:
            #The arrow makes it visually obvious this is a follow-up action,
            #not part of the finding itself. Dimmed so it reads as a
            #secondary line under the main, colored finding above it.
            print(colorize(f"           -> suggested: {suggested_fix}", "dim"))
        #Return True so the caller knows this was a brand new finding.
        return True


#Define capture_process so any module can save full forensic detail about
#one suspicious process without having to repeat this logic itself.
def capture_process(config, process, reason):
    #Wrap everything in a try block because the process we are inspecting
    #can legitimately exit at any moment while we are looking at it.
    try:
        #Pull the basic identifying fields off the psutil process object.
        info = process.as_dict(attrs=["pid", "name", "exe", "cmdline", "username", "create_time", "ppid"])
        #Record why this process was flagged, so the report explains itself.
        info["why"] = reason
        #Build the folder where individual process snapshots get stored.
        process_dir = os.path.join(config["evidence_dir"], "processes")
        #Create that folder if this is the first process we have captured.
        os.makedirs(process_dir, exist_ok=True)
        #Build a unique filename from the timestamp and process ID so no
        #two captures ever overwrite each other.
        file_name = f"{now().replace(':', '-')}_{info['pid']}.json"
        #Open the new evidence file for writing.
        with open(os.path.join(process_dir, file_name), "w") as f:
            #Write the process details as readable, indented JSON.
            json.dump(info, f, indent=2, default=str)
        #Pull the executable path so we can also grab a copy of the binary.
        exe_path = info.get("exe")
        #Only copy the binary if it exists on disk and is not absurdly
        #large, so one huge file cannot fill up the evidence drive.
        if exe_path and os.path.isfile(exe_path) and os.path.getsize(exe_path) < 50 * 1024 * 1024:
            #Build the folder where suspicious binaries get stored.
            sample_dir = os.path.join(config["evidence_dir"], "samples")
            #Create that folder if this is the first sample we have saved.
            os.makedirs(sample_dir, exist_ok=True)
            #Name the copy using its own hash so tampering is detectable.
            dest_name = sha256_of(exe_path)[:16] + "_" + os.path.basename(exe_path)
            #Copy the binary (copy2 preserves metadata like timestamps).
            shutil.copy2(exe_path, os.path.join(sample_dir, dest_name))
    #If anything above fails, swallow the error rather than crashing the
    #whole scan over one process we could not fully inspect.
    except Exception:
        #Deliberately do nothing; a partial capture failure should never
        #stop the rest of the audit from running.
        pass


#Define quarantine_file so anything that touches a tampered file always
#saves a copy of the tampered version before it gets restored or removed.
def quarantine_file(config, path):
    #Build the folder where quarantined (tampered) copies get stored.
    quarantine_dir = os.path.join(config["evidence_dir"], "quarantine")
    #Create that folder if this is the first file we have quarantined.
    os.makedirs(quarantine_dir, exist_ok=True)
    #Only attempt to copy the file if it still actually exists on disk.
    if os.path.isfile(path):
        #Build a timestamped, collision-safe destination filename.
        dest_name = now().replace(":", "-") + "_" + safe_filename(path)
        #Copy the tampered file into quarantine before anyone touches it.
        shutil.copy2(path, os.path.join(quarantine_dir, dest_name))
