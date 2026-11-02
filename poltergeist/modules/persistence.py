#DESCRIPTION: This module answers one question: "what has been set up to
#             run automatically, either on a schedule or at startup?"
#             That is the single most common place a red team hides their
#             way back in, so this module's collect() function is called
#             once to build the clean baseline, then called again on every
#             check to see what changed. collect() itself does not judge
#             anything; cli.py's diff logic decides what counts as
#             suspicious there, purely from "is this new/changed/gone".
#
#             check() below is a SEPARATE, additional LIVE check over the
#             exact same set of startup locations, registered in
#             modules/__init__.py's LIVE_MODULES under the SAME "persistence"
#             module name (so its findings land in the Dashboard's one
#             "EVASIVE PERSISTENCE" section alongside the baseline-diff
#             ones, not a second section of their own). Unlike collect(),
#             it DOES judge something directly, on every single scan, with
#             no baseline required first: it looks at what each startup
#             file's content actually DOES, flagging the handful of
#             patterns that are themselves evasive persistence red flags
#             regardless of whether this exact file existed yesterday -
#             a brand new box someone just handed Poltergeist (already
#             possibly compromised, with no "clean" baseline to compare
#             against yet) still gets a useful first look.

#import os and glob so we can find and list files in the various startup
#and scheduler locations on both operating systems.
import os
import glob

#import platform so this module can tell which operating system it is on
#and read the right locations (Task Scheduler vs cron) for that OS.
import platform

#import subprocess so we can run the OS commands that list scheduled
#tasks, services, and systemd timers.
import subprocess

#import csv and io so Windows's own schtasks output (requested as CSV)
#can be parsed properly - a task's own "Task To Run" command can easily
#contain commas and quotes, which a hand-rolled split(",") would mangle.
import csv
import io

#import re so the registry-value parser below can split "reg query"'s
#own column-padded output on runs of whitespace without a hand-rolled
#loop, and json so the Windows services check below can parse
#PowerShell's own Get-CimInstance ... | ConvertTo-Json output safely
#(a service's own path can contain commas/quotes a text parser would
#mangle, the exact same reasoning schtasks's CSV output gets csv.py).
import re
import json

#import hashlib so a scheduled task's own definition can be hashed into
#a short, stable string for the baseline-diff state dictionary, the same
#spirit as sha256_of() for a real file, just for data that only exists
#as command output, not a file on disk.
import hashlib

#import the sha256_of helper from evidence.py so every file we track here
#is hashed using the exact same method as the rest of the project.
#import resolve_stale too - every live check in this file (foothold
#files, hidden autostart files, evasive content, systemd units, Windows
#scheduled tasks/registry run keys/services) answers "is this true RIGHT
#NOW", so a key it logs can legitimately stop being true the moment a
#file is deleted, a task is removed, or a registry value is cleared.
#Without this, that finding would sit on every Dashboard looking
#permanently active forever - see resolve_stale's own comment in
#evidence.py for the full reasoning.
from ..evidence import sha256_of, resolve_stale

#Store whether we are on Windows once, so collect() does not need to call
#platform.system() more than one time.
IS_WINDOWS = platform.system() == "Windows"


#Define run_command, a tiny helper identical in spirit to the one in
#discovery.py, kept local here so this module has no import cycle back
#into a shared "utils" file that does not otherwise need to exist yet.
def run_command(command):
    #Try to run the command and capture its output as text.
    try:
        #Give the command 15 seconds before giving up on it.
        result = subprocess.run(command, capture_output=True, text=True, timeout=15, shell=isinstance(command, str))
        #Return just the text that was printed to standard output.
        return result.stdout
    #If the command is missing or errors out, do not crash the scan.
    except Exception:
        #Return an empty string so the caller can treat it as "nothing".
        return ""


#Define list_files_under, a helper that walks a folder (or matches a glob
#pattern like "C:\\Users\\*\\...") and returns every file found inside it.
def list_files_under(path_or_pattern, cap=3000):
    #Start with an empty list of discovered file paths.
    found_files = []
    #Expand environment variables and "~" first, then run the glob match.
    expanded = os.path.expandvars(os.path.expanduser(path_or_pattern))
    #Get every path that matches the pattern, or just the literal path if
    #no wildcard characters were present in it.
    matches = glob.glob(expanded) or [expanded]
    #Loop over every match the glob found.
    for matched_path in matches:
        #If this match is a folder, walk every file underneath it.
        if os.path.isdir(matched_path):
            #os.walk visits every subfolder automatically.
            for root, _, file_names in os.walk(matched_path):
                #Loop over every file name found in this subfolder.
                for file_name in file_names:
                    #Record the full path to this one file.
                    found_files.append(os.path.join(root, file_name))
                    #Stop early if we have hit the safety cap on file count.
                    if len(found_files) >= cap:
                        #Return immediately so one huge folder cannot hang
                        #the whole baseline step.
                        return found_files
        #If this match is itself a single file, just record it directly.
        elif os.path.isfile(matched_path):
            #Add this one file path to the results.
            found_files.append(matched_path)
    #Hand back every file path we found.
    return found_files


#Define list_scheduled_tasks_windows, which runs "schtasks /query /fo CSV
#/v" (verbose CSV - every column, including the actual command each task
#runs) and parses it into a list of plain dictionaries, one per task, so
#both collect() and check_scheduled_tasks_windows() below can share one
#single real invocation of the actual OS command instead of each running
#their own slightly-different query. CSV (not the default table format)
#specifically because a task's own "Task To Run" command can easily
#contain commas, and only a real CSV parser (not a hand-rolled split on
#commas) handles that correctly.
def list_scheduled_tasks_windows():
    #Run the real Windows command. /v adds the extra columns this check
    #actually needs (Task To Run, Author, Run As User) that the default,
    #non-verbose query does not include at all.
    output = run_command(["schtasks", "/query", "/fo", "CSV", "/v"])
    #Nothing came back at all - either this is not actually Windows, the
    #command is missing, or something else went wrong; either way, there
    #is nothing to parse.
    if not output.strip():
        #Hand back an empty list rather than crash the caller.
        return []
    #Try to parse it as CSV. csv.DictReader uses the first row as the
    #column headers automatically, which is exactly schtasks's own CSV
    #output shape.
    try:
        #io.StringIO lets csv.reader work on an in-memory string exactly
        #like it would on a real file object.
        rows = list(csv.DictReader(io.StringIO(output)))
    #A genuinely malformed CSV (or any other parsing hiccup) should never
    #crash the whole scan over one broken query.
    except Exception:
        #Nothing usable came back.
        return []
    #schtasks always includes a literal header-repeat row for the special
    #built-in "root" folder task; filter out any row with no real TaskName
    #at all, which is the one reliable sign of a junk/malformed row.
    return [row for row in rows if (row.get("TaskName") or "").strip()]


#Define EVASIVE_COMMAND_PATTERNS_WINDOWS, the Windows equivalent of
#EVASIVE_CONTENT_PATTERNS above - the handful of classic, well-known
#command-line idioms a dropped scheduled task's own "Task To Run" command
#uses to fetch or run something covertly. Same deliberately short,
#explainable-in-one-sentence philosophy as every other pattern list in
#this file - not an attempt at a general malware signature database.
EVASIVE_COMMAND_PATTERNS_WINDOWS = [
    ("-enc ", "runs PowerShell with a base64-encoded command (-enc/-EncodedCommand)"),
    ("-encodedcommand", "runs PowerShell with a base64-encoded command (-enc/-EncodedCommand)"),
    ("downloadstring", "downloads and likely runs a remote script (.DownloadString)"),
    ("downloadfile", "downloads a file from a remote address (.DownloadFile)"),
    ("invoke-webrequest", "fetches something over the network (Invoke-WebRequest)"),
    ("iex ", "pipes something straight into Invoke-Expression (IEX)"),
    ("mshta ", "runs mshta.exe - a common living-off-the-land script-execution trick"),
    ("certutil -decode", "abuses certutil to decode a payload (a well-known certutil misuse)"),
    ("certutil -urlcache", "abuses certutil to download a file (a well-known certutil misuse)"),
    ("bitsadmin /transfer", "uses BITS to covertly download a file (bitsadmin /transfer)"),
    ("regsvr32 /i:http", "uses regsvr32 to run a remote script (the \"Squiblydoo\" technique)"),
]


#Define check_scheduled_tasks_windows, the Windows equivalent of
#check_systemd_units() above - a SEPARATE live check (same "no baseline
#needed, judges name/content directly" spirit) over every real Windows
#Task Scheduler entry. A task is flagged when either its own NAME matches
#a known malicious-tooling keyword (SUSPICIOUS_NAME_KEYWORDS - the same
#keyword-only treatment check_systemd_units() gives *.service files,
#since Windows ships thousands of legitimate task names and there is no
#practical allowlist), OR its own "Task To Run" COMMAND matches one of
#the classic evasive idioms just above - whichever of the two actually
#applies, a task can be flagged for either reason independently.
#Returns the set of "persistence"-module keys this pass found still
#true, so check() below can fold it into its own combined set and hand
#the whole thing to resolve_stale() once at the end.
def check_scheduled_tasks_windows(config, log):
    #Track every key this pass finds still true.
    current_keys = set()
    #Skip entirely off Windows - nothing here applies anywhere else.
    if not IS_WINDOWS:
        #Nothing to do on this OS - hand back an empty set either way.
        return current_keys
    #Pull every real scheduled task this machine currently has.
    for task in list_scheduled_tasks_windows():
        #Pull out the two fields this check actually judges, with a safe
        #fallback for a column schtasks happened not to include.
        task_name = (task.get("TaskName") or "").strip()
        command = (task.get("Task To Run") or "").strip()
        #Skip a row with no real name at all - should already be filtered
        #out by list_scheduled_tasks_windows(), but check again here too.
        if not task_name:
            #Nothing to judge on this row.
            continue
        #The suggested review command is the same regardless of which
        #reason below triggered - inspect, don't touch, exactly like
        #every other suggested_fix in this project.
        quoted_name = task_name.strip("\\")
        fix = f'review: schtasks /query /tn "{quoted_name}" /fo LIST /v'
        #Check 1: does the task's own NAME match a known-bad keyword?
        lowered_name = task_name.lower()
        matched_keyword = next((k for k in SUSPICIOUS_NAME_KEYWORDS if k in lowered_name), None)
        if matched_keyword:
            #This key is true right now - remember it for resolve_stale().
            current_keys.add(f"schtask_name:{task_name}")
            #Report at high severity - the name itself is a red flag,
            #same bar check_systemd_units() uses for a *.service name.
            log.add("persistence", "high", f"schtask_name:{task_name}",
                    f"Scheduled task name matches a known malicious-tooling pattern "
                    f"('{matched_keyword}'): {task_name} (runs: {command or 'unknown'}) - "
                    "worth confirming what it actually runs", suggested_fix=fix)
        #Check 2: does the task's own COMMAND match a known evasive idiom?
        #Independent of the name check above - a task can be flagged for
        #either reason, or both, without one suppressing the other.
        if command:
            #Work out the lowercase command text for the pattern match.
            lowered_command = command.lower()
            #Check every known evasive command pattern against it.
            for pattern, description in EVASIVE_COMMAND_PATTERNS_WINDOWS:
                #A simple substring search, same philosophy as every
                #other pattern list in this file - cheap, explainable
                #tripwires, not a general-purpose malware scanner.
                if pattern in lowered_command:
                    #This key is true right now - remember it for resolve_stale().
                    current_keys.add(f"schtask_cmd:{task_name}:{pattern.strip()}")
                    #Report at high severity - these are all patterns a
                    #legitimate scheduled task essentially never needs.
                    log.add("persistence", "high", f"schtask_cmd:{task_name}:{pattern.strip()}",
                            f"Scheduled task {task_name} {description}: {command}",
                            suggested_fix=fix)
    #Hand back every key this pass found still true.
    return current_keys


#Define hash_scheduled_task_windows, a small helper for collect() below:
#builds one short, stable hash out of the handful of fields that actually
#matter for "did this task change" (its command, who runs it, and who
#authored it) - NOT the whole raw CSV row, which includes constantly-
#churning fields (Next Run Time, Last Run Time, Last Result) that would
#make every single task look "changed" on literally every single scan.
def hash_scheduled_task_windows(task):
    #Build one combined string from just the fields that matter.
    stable_text = "|".join([
        task.get("Task To Run") or "",
        task.get("Run As User") or "",
        task.get("Author") or "",
        task.get("Scheduled Task State") or "",
    ])
    #Hash it the same way sha256_of() hashes a real file's bytes.
    return hashlib.sha256(stable_text.encode("utf-8", errors="replace")).hexdigest()


#Define REGISTRY_RUN_KEY_PATHS: the four classic Windows "run on every
#login" registry locations - one entry per (hive label as reg.exe spells
#it, the full key path, a short label distinguishing Run from RunOnce).
#RunOnce keys are exactly as real a persistence spot as Run keys - the
#only difference is Windows deletes a RunOnce entry itself after it
#fires once, which does not stop an attacker from simply re-adding it on
#every reboot through another mechanism.
REGISTRY_RUN_KEY_PATHS = [
    ("HKLM", r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run", "Run"),
    ("HKLM", r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce", "RunOnce"),
    ("HKCU", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "Run"),
    ("HKCU", r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce", "RunOnce"),
]


#Define list_registry_run_keys_windows, which runs "reg query" against
#each of the four locations above and parses every VALUE found under
#them into a list of plain dictionaries - the registry equivalent of
#list_scheduled_tasks_windows() above, so collect(), the live keyword
#check below, and anything else that needs this data all share one
#single real invocation of "reg query" per key rather than each running
#their own slightly different query.
def list_registry_run_keys_windows():
    #Start with an empty list of discovered entries.
    entries = []
    #Loop over all four Run/RunOnce locations (both hives).
    for hive, full_path, run_key_label in REGISTRY_RUN_KEY_PATHS:
        #Run the real "reg query" command against this one key.
        output = run_command(["reg", "query", full_path])
        #Nothing came back - either this key does not exist on this
        #machine (very common; not every box has RunOnce entries), the
        #command is missing, or something else went wrong. Either way,
        #there is nothing to parse, and that is not itself suspicious.
        if not output.strip():
            #Move on to the next key.
            continue
        #Loop over every line reg query printed for this key.
        for line in output.splitlines():
            #The first line just repeats the key's own path - skip it,
            #along with any other line that is not actually indented
            #(every real VALUE line reg query prints starts with
            #whitespace; the key path header line does not).
            if not line.startswith(" ") and not line.startswith("\t"):
                #Not a value line - skip it.
                continue
            #Strip the leading whitespace now that we know this is one.
            stripped = line.strip()
            if not stripped:
                #A genuinely blank line - nothing to parse.
                continue
            #reg query pads its three columns (name, type, data) with
            #multiple spaces - a real value's data can itself contain
            #single spaces (a path with arguments), so only split on
            #RUNS of two or more spaces, and only into three pieces at
            #most, so the data column is never itself split apart.
            columns = re.split(r"\s{2,}", stripped, maxsplit=2)
            #A malformed or unexpected line should never crash the scan.
            if len(columns) < 3:
                #Not enough columns to make sense of - skip this line.
                continue
            #Record this one value as its own entry.
            entries.append({
                "hive": hive,
                "run_key": run_key_label,
                "name": columns[0],
                "type": columns[1],
                "value": columns[2],
            })
    #Hand back every entry found across all four locations.
    return entries


#Define hash_registry_run_entry, a small helper for collect() below:
#hashes just this entry's own command/value text - the one field that
#actually matters for "did this autorun entry change". A Run/RunOnce
#value has no other churning metadata the way a scheduled task's "Next
#Run Time" does, so this is simpler than hash_scheduled_task_windows().
def hash_registry_run_entry(entry):
    #Hash the value text the exact same way every other hash in this
    #project works.
    return hashlib.sha256((entry.get("value") or "").encode("utf-8", errors="replace")).hexdigest()


#Define check_registry_run_keys_windows, the Run/RunOnce-key equivalent
#of check_scheduled_tasks_windows() above - a SEPARATE live check (same
#"no baseline needed" spirit) that flags an entry whose NAME matches a
#known malicious-tooling keyword, or whose VALUE (the command Windows
#actually runs) matches one of the classic evasive idioms - exactly the
#same two independent checks run against scheduled tasks above.
#Returns the set of "persistence"-module keys this pass found still
#true, the same way check_scheduled_tasks_windows() above does.
def check_registry_run_keys_windows(config, log):
    #Track every key this pass finds still true.
    current_keys = set()
    #Skip entirely off Windows - nothing here applies anywhere else.
    if not IS_WINDOWS:
        #Nothing to do on this OS - hand back an empty set either way.
        return current_keys
    #Pull every real Run/RunOnce entry this machine currently has.
    for entry in list_registry_run_keys_windows():
        #Pull out the fields this check actually judges.
        hive, run_key_label = entry["hive"], entry["run_key"]
        name, value = entry["name"], entry["value"]
        #The suggested review command is the same regardless of which
        #reason below triggered - inspect, don't touch, exactly like
        #every other suggested_fix in this project.
        key_path = next(p for h, p, r in REGISTRY_RUN_KEY_PATHS if h == hive and r == run_key_label)
        fix = f'review: reg query "{key_path}" /v "{name}"'
        #Check 1: does the entry's own NAME match a known-bad keyword?
        lowered_name = name.lower()
        matched_keyword = next((k for k in SUSPICIOUS_NAME_KEYWORDS if k in lowered_name), None)
        if matched_keyword:
            #This key is true right now - remember it for resolve_stale().
            current_keys.add(f"regrun_name:{hive}:{run_key_label}:{name}")
            #Report at high severity - same bar every other name-keyword
            #match in this file uses.
            log.add("persistence", "high", f"regrun_name:{hive}:{run_key_label}:{name}",
                    f"{hive} {run_key_label} entry name matches a known malicious-tooling pattern "
                    f"('{matched_keyword}'): {name} (runs: {value}) - worth confirming what it actually runs",
                    suggested_fix=fix)
        #Check 2: does the entry's own VALUE match a known evasive idiom?
        #Independent of the name check above - an entry can be flagged
        #for either reason, or both, without one suppressing the other.
        lowered_value = value.lower()
        for pattern, description in EVASIVE_COMMAND_PATTERNS_WINDOWS:
            #A simple substring search, same philosophy as everywhere else.
            if pattern in lowered_value:
                #This key is true right now - remember it for resolve_stale().
                current_keys.add(f"regrun_cmd:{hive}:{run_key_label}:{name}:{pattern.strip()}")
                #Report at high severity - these are all patterns a
                #legitimate Run/RunOnce entry essentially never needs.
                log.add("persistence", "high", f"regrun_cmd:{hive}:{run_key_label}:{name}:{pattern.strip()}",
                        f"{hive} {run_key_label} entry {name} {description}: {value}",
                        suggested_fix=fix)
    #Hand back every key this pass found still true.
    return current_keys


#Define list_services_windows, which runs Get-CimInstance Win32_Service
#through PowerShell and parses its JSON into a list of plain
#dictionaries - JSON (not the default table text) specifically because a
#service's own path can contain commas and quotes a hand-rolled text
#parser would mangle, the exact same reasoning list_scheduled_tasks_
#windows() above uses CSV for schtasks.
def list_services_windows():
    #Ask PowerShell for just the four fields this check actually needs,
    #as JSON. ConvertTo-Json on a SINGLE result returns one bare object
    #rather than a one-item array, which is normalized back out below.
    command = ("Get-CimInstance Win32_Service | "
               "Select-Object Name,StartMode,PathName,State | ConvertTo-Json")
    output = run_command(["powershell", "-NoProfile", "-NonInteractive", "-Command", command])
    #Nothing came back - either this is not actually Windows, PowerShell
    #is missing, or something else went wrong.
    if not output.strip():
        #Hand back an empty list rather than crash the caller.
        return []
    #Try to parse the JSON PowerShell printed.
    try:
        parsed = json.loads(output)
    #A genuinely malformed/truncated JSON blob should never crash the
    #whole scan over one broken query.
    except Exception:
        #Nothing usable came back.
        return []
    #A single service comes back as one bare JSON object rather than a
    #one-item array - normalize both shapes into a plain Python list.
    if isinstance(parsed, dict):
        #Wrap the single object in a list.
        parsed = [parsed]
    #Anything other than a list at this point is not usable.
    if not isinstance(parsed, list):
        #Nothing usable came back.
        return []
    #Filter out any entry with no real Name at all.
    return [row for row in parsed if isinstance(row, dict) and (row.get("Name") or "").strip()]


#Define hash_service_windows, a small helper for collect() below: hashes
#just the two fields that actually matter for "did this service change
#in a way worth noticing" - its start mode (so a service quietly flipped
#from Manual to Automatic is caught, the exact scenario this check
#exists for) and its own executable path/command line. Deliberately NOT
#the service's current running State, which churns on every normal
#start/stop and would make every service look "changed" constantly.
def hash_service_windows(service):
    #Build one combined string from just the fields that matter.
    stable_text = "|".join([
        service.get("StartMode") or "",
        service.get("PathName") or "",
    ])
    #Hash it the same way every other hash in this project works.
    return hashlib.sha256(stable_text.encode("utf-8", errors="replace")).hexdigest()


#Define check_services_windows, the services equivalent of
#check_scheduled_tasks_windows() above - a SEPARATE live check flagging
#a service whose own NAME matches a known malicious-tooling keyword, or
#whose own PathName (the command it actually runs) matches one of the
#classic evasive idioms. The Manual-to-Automatic flip this whole feature
#was added for is a BASELINE-DIFF concern, not a live one (there is
#nothing wrong with a service simply being SET to Automatic by itself,
#only with one quietly CHANGING to it), so that case is covered by
#hash_service_windows()/collect() below instead, not here.
#Returns the set of "persistence"-module keys this pass found still
#true, the same way the other Windows-only live checks above do.
def check_services_windows(config, log):
    #Track every key this pass finds still true.
    current_keys = set()
    #Skip entirely off Windows - nothing here applies anywhere else.
    if not IS_WINDOWS:
        #Nothing to do on this OS - hand back an empty set either way.
        return current_keys
    #Pull every real Windows service this machine currently has.
    for service in list_services_windows():
        #Pull out the fields this check actually judges.
        name = (service.get("Name") or "").strip()
        path_name = (service.get("PathName") or "").strip()
        #Skip a row with no real name at all.
        if not name:
            #Nothing to judge on this row.
            continue
        #The suggested review command is the same regardless of which
        #reason below triggered - inspect, don't touch.
        fix = f'review: Get-CimInstance Win32_Service -Filter "Name=\'{name}\'" | Format-List *'
        #Check 1: does the service's own NAME match a known-bad keyword?
        lowered_name = name.lower()
        matched_keyword = next((k for k in SUSPICIOUS_NAME_KEYWORDS if k in lowered_name), None)
        if matched_keyword:
            #This key is true right now - remember it for resolve_stale().
            current_keys.add(f"service_name:{name}")
            #Report at high severity - same bar every other name check
            #in this file uses.
            log.add("persistence", "high", f"service_name:{name}",
                    f"Windows service name matches a known malicious-tooling pattern "
                    f"('{matched_keyword}'): {name} (runs: {path_name or 'unknown'}) - "
                    "worth confirming what it actually runs", suggested_fix=fix)
        #Check 2: does the service's own PathName match a known evasive
        #idiom? Independent of the name check above.
        if path_name:
            #Work out the lowercase path/command for the pattern match.
            lowered_path = path_name.lower()
            for pattern, description in EVASIVE_COMMAND_PATTERNS_WINDOWS:
                #A simple substring search, same philosophy as everywhere else.
                if pattern in lowered_path:
                    #This key is true right now - remember it for resolve_stale().
                    current_keys.add(f"service_cmd:{name}:{pattern.strip()}")
                    #Report at high severity.
                    log.add("persistence", "high", f"service_cmd:{name}:{pattern.strip()}",
                            f"Windows service {name} {description}: {path_name}", suggested_fix=fix)
    #Hand back every key this pass found still true.
    return current_keys


#Define list_systemd_timers_linux, which runs "systemctl list-timers
#--all --no-legend --no-pager" and parses it into a list of plain
#dictionaries - the Linux equivalent of list_scheduled_tasks_windows()
#above. "--all" includes inactive/disabled timers too, not just the
#ones currently counting down, since a disabled-but-still-present timer
#is just as worth tracking in the baseline. The leading date/countdown
#columns are intentionally NOT parsed out individually - they constantly
#change on every single scan (NEXT/LEFT/LAST/PASSED) and systemd does
#not pad them to a fixed width, so the only reliable way to find the
#UNIT and ACTIVATES columns is that a unit name itself never contains
#whitespace, which means the two of them are always the LAST two tokens
#on the line.
def list_systemd_timers_linux():
    #Run the real systemd command. --no-legend drops the header row,
    #--no-pager guarantees the full output comes back in one piece
    #rather than being handed to a pager this non-interactive call could
    #never interact with.
    output = run_command(["systemctl", "list-timers", "--all", "--no-legend", "--no-pager"])
    #Nothing came back - either this machine is not actually running
    #systemd, the command is missing, or something else went wrong.
    if not output.strip():
        #Hand back an empty list rather than crash the caller.
        return []
    #Start with an empty list of discovered timers.
    timers = []
    #Loop over every line this command printed.
    for line in output.splitlines():
        #Split on any whitespace - the unit name and what it activates
        #are always the last two tokens, for the reason explained above.
        tokens = line.split()
        #A genuinely blank or malformed line should never crash the scan.
        if len(tokens) < 2:
            #Not enough tokens to make sense of - skip this line.
            continue
        #The last token is what this timer activates (almost always the
        #same name with .service instead of .timer); the second-to-last
        #is the timer unit's own name.
        activates, unit_name = tokens[-1], tokens[-2]
        #A real timer unit name always ends in ".timer" - the one
        #reliable sanity check that the split above actually landed on
        #the right two columns rather than, say, a stray "n/a" field.
        if not unit_name.endswith(".timer"):
            #Something about this line did not parse as expected - skip
            #it rather than record something wrong.
            continue
        #Record this one timer as its own entry.
        timers.append({"unit": unit_name, "activates": activates})
    #Hand back every timer found.
    return timers


#Define hash_systemd_timer, a small helper for collect() below: hashes
#just what this timer ACTIVATES (the service it actually fires) - the
#one field from list_systemd_timers_linux() worth tracking for change,
#since the timer's own NAME is already the dictionary key it is stored
#under, and the countdown/last-run columns deliberately are not kept at
#all (see list_systemd_timers_linux()'s own comment on why).
def hash_systemd_timer(timer):
    #Hash the "activates" text the exact same way every other hash in
    #this project works.
    return hashlib.sha256((timer.get("activates") or "").encode("utf-8", errors="replace")).hexdigest()


#Define get_startup_locations, the exact OS-branching list collect()
#used to build inline - pulled out into its own function so check()
#below can walk the SAME set of locations without duplicating this
#list, and so a location added for one is automatically covered by
#the other too.
def get_startup_locations():
    #Branch based on which operating system we are auditing.
    if IS_WINDOWS:
        #Scheduled tasks are NOT handled here any more - unlike every
        #other location in this function, a task has no single file on
        #disk this list_files_under()-based approach could hash (the real
        #definition lives in the Task Scheduler's own internal store,
        #queried through "schtasks", not a plain file path). See
        #list_scheduled_tasks_windows()/hash_scheduled_task_windows()
        #above, wired into collect() directly below instead, plus
        #check_scheduled_tasks_windows() (the LIVE, no-baseline-needed
        #keyword/content check - the Windows equivalent of
        #check_systemd_units() below).
        #Registry Run/RunOnce keys and Windows services are ALSO not
        #handled here for the exact same reason - neither has a single
        #file on disk this list_files_under()-based approach could ever
        #hash. See list_registry_run_keys_windows()/hash_registry_run_
        #entry() and list_services_windows()/hash_service_windows()
        #above, wired into collect() directly below instead, plus
        #check_registry_run_keys_windows() and check_services_windows()
        #(the LIVE, no-baseline-needed keyword/content checks for each).
        #Collect every file sitting in the common startup folders, since a
        #dropped .lnk or .bat file there runs on every login.
        startup_locations = [
            r"C:\Windows\System32\Tasks",
            r"%ProgramData%\Microsoft\Windows\Start Menu\Programs\StartUp",
            r"C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup",
        ]
    else:
        #List every Linux location where a cron job, timer, or shell
        #profile could be used to run something automatically.
        startup_locations = [
            "/etc/crontab", "/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily",
            "/etc/cron.weekly", "/etc/cron.monthly", "/var/spool/cron",
            "/etc/systemd/system", "/lib/systemd/system", "/etc/rc.local",
            "/etc/profile", "/etc/profile.d", "/etc/bash.bashrc", "/etc/ld.so.preload",
            "/etc/init.d",
        ]
        #Add every user's shell profile and authorized_keys file too, since
        #those are just as common a persistence spot as the system files.
        for home_dir in glob.glob("/home/*") + ["/root"]:
            #Add the four most commonly abused per-user files.
            startup_locations += [
                f"{home_dir}/.bashrc", f"{home_dir}/.profile",
                f"{home_dir}/.bash_profile", f"{home_dir}/.ssh/authorized_keys",
            ]
        #Systemd TIMERS (as opposed to the *.timer unit FILES check_
        #systemd_units() below already scans for) are ALSO not handled
        #here, for the same reason - "systemctl list-timers" is a live
        #query of systemd's own loaded state, not a file on disk, and
        #it also catches a timer loaded from /lib/systemd/system (stock
        #OS packages) that check_systemd_units()'s /etc/systemd/system-
        #only file scan would never see. See list_systemd_timers_linux()/
        #hash_systemd_timer() above, wired into collect() directly below.
    #Hand back the finished list of locations for this OS.
    return startup_locations


#Define collect, the one function modules/__init__.py registers under
#STATE_MODULES. It returns a dictionary mapping a unique string key to a
#value (usually a file hash) representing the current state of
#persistence mechanisms on this machine.
def collect(config):
    #Start with an empty dictionary to fill in below.
    state = {}
    #Loop over every location we decided to check for this OS.
    for location in get_startup_locations():
        #Expand that location into every actual file sitting under it.
        for file_path in list_files_under(location):
            #Record this file's hash under a "file:" prefixed key so the
            #diff logic in cli.py can tell at a glance what kind of item
            #changed just by reading the key.
            state[f"file:{file_path}"] = sha256_of(file_path)
    #On Windows, also record one state entry per real scheduled task -
    #see list_scheduled_tasks_windows()/hash_scheduled_task_windows()
    #above for why this needs its own, non-file-based path (a task has
    #no single file on disk list_files_under() above could ever hash).
    #Keyed by task name alone (not also by its hash) so a RENAMED task
    #shows up as one addition + one removal in the diff, same as a
    #renamed file anywhere else in this project's baseline logic.
    if IS_WINDOWS:
        #Loop over every real scheduled task this machine currently has.
        for task in list_scheduled_tasks_windows():
            #Pull out this task's own name, skipping a row with none.
            task_name = (task.get("TaskName") or "").strip()
            if not task_name:
                #Nothing to key this entry by.
                continue
            #Record this task's stable hash under a "task:" prefixed key.
            state[f"task:{task_name}"] = hash_scheduled_task_windows(task)
        #Also record one state entry per Run/RunOnce registry value -
        #see list_registry_run_keys_windows()/hash_registry_run_entry()
        #above for why this needs its own, non-file-based path too.
        #Keyed by hive+key+name together (not also by its own hash) so
        #a renamed entry shows up as one addition + one removal, the
        #same convention the scheduled-task keys above use.
        for entry in list_registry_run_keys_windows():
            #Build this entry's own unique key out of which hive/key it
            #lives under plus its own value name.
            entry_key = f"regrun:{entry['hive']}:{entry['run_key']}:{entry['name']}"
            #Record this entry's stable hash under that key.
            state[entry_key] = hash_registry_run_entry(entry)
        #Also record one state entry per Windows service - see
        #list_services_windows()/hash_service_windows() above. This is
        #the actual baseline-diff piece that catches a service quietly
        #flipping from Manual to Automatic start mode, since that flip
        #changes hash_service_windows()'s own hash for that service.
        for service in list_services_windows():
            #Pull out this service's own name, skipping a row with none.
            service_name = (service.get("Name") or "").strip()
            if not service_name:
                #Nothing to key this entry by.
                continue
            #Record this service's stable hash under a "service:" key.
            state[f"service:{service_name}"] = hash_service_windows(service)
    else:
        #Off Windows, record one state entry per real systemd timer -
        #see list_systemd_timers_linux()/hash_systemd_timer() above for
        #why this needs its own, non-file-based path too (a timer loaded
        #from a stock OS package under /lib/systemd/system has no file
        #sitting in /etc/systemd/system for list_files_under() to ever
        #walk into). Keyed by the timer's own unit name alone, same
        #"rename = one addition + one removal" convention as above.
        for timer in list_systemd_timers_linux():
            #Record this timer's stable hash under a "systemd_timer:" key.
            state[f"systemd_timer:{timer['unit']}"] = hash_systemd_timer(timer)
    #Hand back the completed state dictionary.
    return state


#Define EVASIVE_CONTENT_PATTERNS, the small set of plain-text substrings
#this file's own check() below scans every startup file's CONTENT for -
#each one is a well-known shorthand real attackers actually use to make
#a persistence mechanism harder to notice or to re-fetch a payload
#rather than storing it in plain sight. This is deliberately a short,
#explainable list (a few classic droppers/reverse-shell idioms), not an
#attempt at a general malware signature database - that is a much
#bigger, constantly-moving target this project does not try to chase.
#Each entry is (the literal substring to search for, a short label used
#in the finding's own message).
EVASIVE_CONTENT_PATTERNS = [
    ("curl ", "downloads something with curl"),
    ("wget ", "downloads something with wget"),
    ("| bash", "pipes a download straight into bash"),
    ("| sh", "pipes a download straight into a shell"),
    ("/dev/tcp/", "opens a raw /dev/tcp/ socket (classic bash reverse shell)"),
    ("base64 -d", "decodes a base64 blob before running it"),
    ("base64 --decode", "decodes a base64 blob before running it"),
    ("nc -e", "launches netcat with -e (classic reverse-shell one-liner)"),
    ("bash -i", "launches an interactive bash shell (classic reverse-shell one-liner)"),
    ("chattr +i", "makes a file immutable - a common anti-tamper trick on a dropped persistence file"),
]

#Define SUSPICIOUS_EXEC_DIRECTORIES, the folders a persistence mechanism
#should almost never actually point its own ExecStart/command AT - these
#are all world-writable or temporary-by-design locations where nothing
#legitimate is normally installed to run from.
SUSPICIOUS_EXEC_DIRECTORIES = ["/tmp/", "/var/tmp/", "/dev/shm/", "/dev/.", "/.cache/"]

#Define SUSPICIOUS_NAME_KEYWORDS, a short, explainable list of substrings
#that show up constantly in real dropper/implant/wiper tooling names - the
#same spirit as EVASIVE_CONTENT_PATTERNS above, just matched against a
#FILE or UNIT's own name/path instead of its content. Kept intentionally
#short and plain-English-explainable, same reasoning as that list: this is
#not an attempt at a malware-name signature database, just the handful of
#words that are themselves an immediate red flag wherever they show up.
SUSPICIOUS_NAME_KEYWORDS = [
    "wipe", "shadow", "miner", "backdoor", "implant", "beacon", "payload",
    "dropper", "rootkit", "respawn", "reverse", "exfil", "keylog",
    #"guard" is a generic enough word that a legitimate tool could use it
    #too, but it is kept in anyway: it is the literal word that let the
    #reference tool this was compared against catch logrotate-guard.timer/
    #.service on the exact VM this whole investigation started from, and
    #a false positive here costs a 30-second "yeah that's fine" glance -
    #missing a real one costs the finding entirely.
    "guard",
]

#Define FOOTHOLD_DIRECTORIES_ALWAYS_SCAN: locations a stock/minimal Linux
#install almost never has anything running from at all, so EVERY file
#found there is worth at least a mention - mirrors the exact directories
#the user's own Shadow Watch/Harbinger tool scrubs for "dormant payloads
#on disk" (its own ACTIVE ROOT DIRECTORY SCRUB), since this check exists
#specifically because Poltergeist was missing coverage Harbinger already
#had here.
FOOTHOLD_DIRECTORIES_ALWAYS_SCAN = ["/usr/local/sbin", "/opt", "/srv"]

#Define FOOTHOLD_DIRECTORIES_KEYWORD_ONLY: locations that LEGITIMATELY see
#constant, harmless file churn (temp files, build artifacts), so flagging
#every single file there would flood the Dashboard with noise - these are
#only reported when a file's own name also matches SUSPICIOUS_NAME_KEYWORDS
#above, the same distinction Harbinger's own scrub draws.
FOOTHOLD_DIRECTORIES_KEYWORD_ONLY = ["/tmp", "/dev/shm", "/var/tmp"]


#Define check_foothold_directories, a SEPARATE live check (same "no
#baseline needed, judges content/location directly" spirit as check()
#above) that looks for dropped files sitting in the handful of locations
#real intrusions use as a staging/persistence foothold far more often than
#anything legitimate does.
#
#Reports under the "integrity" module, NOT "persistence" - this is
#deliberate, matching the Dashboard layout the user's own Shadow
#Watch/Harbinger tool uses, which this project's Dashboard mirrors:
#these are "ACTIVE ROOT DIRECTORY SCRUB" findings (a live, no-baseline-
#needed sweep of a few specific suspicious directories), which belong in
#the Dashboard's "FILE INTEGRITY / ROOT DIRECTORY SCRUB" section right
#alongside the baseline-diff integrity findings modules/integrity.py's
#own collect() produces - not in "POTENTIAL EVASIVE PERSISTENCE", which
#is reserved for the hidden-file/timer/service/evasive-shell-content
#checks below in this same file. "integrity" already exists as a real
#module name (see modules/__init__.py's STATE_MODULES) and the Dashboard
#already has a section wired to it - this just means it was never fed
#anything for the LIVE (no-baseline) case before now.
#Returns the set of "integrity"-module keys this pass actually found
#still true, so check() below can hand that to resolve_stale() and clear
#a finding the instant the dropped file is deleted - exactly the gap
#behind a removed file's "Unexpected file in ..." alert sitting on the
#Dashboard forever even after it's gone from disk.
def check_foothold_directories(config, log):
    #Track every key this pass finds still true - mirrors every key
    #string log.add() is called with anywhere below in this function.
    current_keys = set()
    #Skip this on Windows - these are all Linux-specific paths; Windows
    #has its own separate TODO items above for its own equivalent spots.
    if IS_WINDOWS:
        #Nothing to do on this OS - hand back an empty set either way.
        return current_keys
    #Walk every "always scan" directory, reporting literally everything
    #found there - mirrors Harbinger's own unconditional SUSPICIOUS tag
    #for any file under these same three directories.
    for directory in FOOTHOLD_DIRECTORIES_ALWAYS_SCAN:
        #Skip a directory that does not exist on this machine at all.
        if not os.path.isdir(directory):
            #Nothing to scan here.
            continue
        #List every file found anywhere under this directory.
        for file_path in list_files_under(directory):
            #Work out the lowercase file name for the keyword match below.
            lowered_name = os.path.basename(file_path).lower()
            #A name match bumps this to high severity and a sharper
            #message - the same CRITICAL-vs-SUSPICIOUS split Harbinger
            #draws between a keyword hit and mere presence in the dir.
            matched_keyword = next((k for k in SUSPICIOUS_NAME_KEYWORDS if k in lowered_name), None)
            if matched_keyword:
                #This key is true right now - remember it for resolve_stale().
                current_keys.add(f"foothold_name:{file_path}")
                #Report at high severity - the name itself is a red flag.
                log.add("integrity", "high", f"foothold_name:{file_path}",
                        f"File in {directory} (a location almost nothing legitimate installs to) "
                        f"has a name matching a known malicious-tooling pattern ('{matched_keyword}'): {file_path}",
                        suggested_fix=f"review: ls -la {file_path}; file {file_path}; sha256sum {file_path}")
            else:
                #This key is true right now - remember it for resolve_stale().
                current_keys.add(f"foothold:{file_path}")
                #Report at medium severity - just "worth a look", since
                #real (if unusual) admin tooling does occasionally live
                #in these spots too.
                log.add("integrity", "medium", f"foothold:{file_path}",
                        f"Unexpected file in {directory} - a location rarely used for anything "
                        f"on a stock/minimal install, worth a manual look: {file_path}",
                        suggested_fix=f"review: ls -la {file_path}; file {file_path}; sha256sum {file_path}")
    #Walk every "keyword only" directory, but ONLY report a name match -
    #ordinary temp-file churn here is expected and not worth a finding.
    for directory in FOOTHOLD_DIRECTORIES_KEYWORD_ONLY:
        #Skip a directory that does not exist on this machine at all.
        if not os.path.isdir(directory):
            #Nothing to scan here.
            continue
        #List every file found anywhere under this directory.
        for file_path in list_files_under(directory):
            #Work out the lowercase file name for the keyword match.
            lowered_name = os.path.basename(file_path).lower()
            #Only report this one if its name itself is a red flag.
            matched_keyword = next((k for k in SUSPICIOUS_NAME_KEYWORDS if k in lowered_name), None)
            if matched_keyword:
                #This key is true right now - remember it for resolve_stale().
                current_keys.add(f"foothold_name:{file_path}")
                #Report at high severity - same reasoning as above.
                log.add("integrity", "high", f"foothold_name:{file_path}",
                        f"File in {directory} has a name matching a known malicious-tooling "
                        f"pattern ('{matched_keyword}'): {file_path}",
                        suggested_fix=f"review: ls -la {file_path}; file {file_path}; sha256sum {file_path}")
    #Hand back every key this pass found still true, so check() below can
    #resolve anything that dropped out since the previous scan.
    return current_keys


#Define KNOWN_BENIGN_TIMER_NAMES, the set of systemd timer unit file names
#that ship stock on an ordinary Debian/Ubuntu-family box - directly
#carried over from the user's own Shadow Watch/Harbinger tool's own
#"safe_timers" allowlist, since it is an accurate, battle-tested list of
#real stock names, plus a few more common ones from other distro families.
#A real timer's EXACT basename is almost always one of these; anything
#else is worth a look, even if it turns out to be legitimate third-party
#software - better to ask a human to glance at one unfamiliar timer than
#to silently miss a planted one.
KNOWN_BENIGN_TIMER_NAMES = {
    "apt-daily-upgrade.timer", "apt-daily.timer", "dpkg-db-backup.timer",
    "e2scrub_all.timer", "fstrim.timer", "fwupd-refresh.timer",
    "logrotate.timer", "man-db.timer", "motd-news.timer",
    "systemd-tmpfiles-clean.timer", "update-notifier-download.timer",
    "update-notifier-motd.timer", "phpsessionclean.timer",
    "apport-autoreport.timer", "snapd.snap-repair.timer",
    "ua-timer.timer", "snapd.aa-prompt-listener.timer",
    "systemd-tmpfiles-clean.timer", "unattended-upgrades.timer",
    "certbot.timer", "logwatch.timer", "shadow.timer",
}

#Define SYSTEMD_UNIT_DIRECTORY as its own module-level constant (rather
#than a literal buried inside check_systemd_units below) for the same
#reason FOOTHOLD_DIRECTORIES_ALWAYS_SCAN/KEYWORD_ONLY above are: so a test
#can monkeypatch it to point at an isolated scratch folder instead of the
#real machine's /etc/systemd/system.
SYSTEMD_UNIT_DIRECTORY = "/etc/systemd/system"


#Define check_systemd_units, a SEPARATE live check that looks at every
#*.timer and *.service unit file dropped directly in SYSTEMD_UNIT_DIRECTORY
#(the modern equivalent of a cron job, and the exact mechanism Harbinger's
#own "ANOMALOUS TIMER FILE"/"ANOMALOUS SERVICE FILE" findings look for) -
#*.timer files are flagged simply for not being a name this tool
#recognizes as stock, *.service files only when their own name also
#matches SUSPICIOUS_NAME_KEYWORDS (there are far too many legitimate
#service names to allowlist, so this one stays keyword-only to avoid
#flooding the Dashboard with every ordinary daemon on the box).
#Returns the set of "persistence"-module keys this pass found still
#true, the same way every other live check function in this file does.
def check_systemd_units(config, log):
    #Track every key this pass finds still true.
    current_keys = set()
    #Skip this on Windows - systemd is Linux-only.
    if IS_WINDOWS:
        #Nothing to do on this OS - hand back an empty set either way.
        return current_keys
    #Nothing to do if this machine has no systemd unit directory at all.
    unit_directory = SYSTEMD_UNIT_DIRECTORY
    if not os.path.isdir(unit_directory):
        #Nothing to scan here.
        return current_keys
    #Look only at files sitting DIRECTLY in this folder - a real systemd
    #unit always does, and this avoids wandering into the (sometimes
    #large) per-service ".wants"/".requires" symlink subfolders that also
    #live here.
    try:
        #List just this one folder's own direct entries.
        entries = os.listdir(unit_directory)
    #A permission problem or anything else here should not crash the scan.
    except Exception:
        #Nothing more can be done.
        return current_keys
    #Loop over every direct entry in the unit directory.
    for entry_name in entries:
        #Build the full path to this entry.
        full_path = os.path.join(unit_directory, entry_name)
        #Skip anything that is not an actual regular file (a directory,
        #broken symlink, socket, etc.).
        if not os.path.isfile(full_path):
            #Move on to the next entry.
            continue
        #Flag a .timer file whose exact name is not one this tool
        #recognizes as a stock OS-shipped timer.
        if entry_name.endswith(".timer") and entry_name not in KNOWN_BENIGN_TIMER_NAMES:
            #This key is true right now - remember it for resolve_stale().
            current_keys.add(f"timer:{full_path}")
            #Report at medium severity - an unrecognized name alone is
            #not proof of anything, just genuinely worth a human glance.
            log.add("persistence", "medium", f"timer:{full_path}",
                    f"Timer unit not on this tool's list of standard OS-shipped timers: "
                    f"{full_path} - worth confirming what it actually runs",
                    suggested_fix=f"review: systemctl cat {entry_name}; systemctl status {entry_name}")
        #Flag a .service file only when its own name matches a known
        #malicious-tooling keyword - too many legitimate service names
        #exist to allowlist them all the way the timer list above does.
        elif entry_name.endswith(".service"):
            #Work out the lowercase name for the keyword match.
            lowered_name = entry_name.lower()
            #Check for a keyword match.
            matched_keyword = next((k for k in SUSPICIOUS_NAME_KEYWORDS if k in lowered_name), None)
            if matched_keyword:
                #This key is true right now - remember it for resolve_stale().
                current_keys.add(f"service:{full_path}")
                #Report at high severity - the name itself is a red flag.
                log.add("persistence", "high", f"service:{full_path}",
                        f"Service unit name matches a known malicious-tooling pattern "
                        f"('{matched_keyword}'): {full_path} - worth confirming what it actually runs",
                        suggested_fix=f"review: systemctl cat {entry_name}; systemctl status {entry_name}")
    #Hand back every key this pass found still true.
    return current_keys


#Define read_text_snippet, a small helper reading at most the first few
#KB of a file as text, tolerating anything that is not valid UTF-8 (a
#binary payload dropped into one of these locations is itself worth
#flagging, but this function's own job is just "give me text to search,
#or nothing") - persistence files are almost always small shell
#scripts/unit files/crontab lines, so a few KB is always enough; capping
#it means this never has to worry about a huge file slowing the scan.
def read_text_snippet(file_path, cap_bytes=8192):
    #Wrap the whole read, since a persistence "file" can turn out to be
    #a socket, a broken symlink, or something else os.walk still listed.
    try:
        #Open in binary mode first so a snippet can be capped by bytes,
        #not by (potentially very long) decoded characters.
        with open(file_path, "rb") as f:
            #Read only the first cap_bytes bytes.
            raw = f.read(cap_bytes)
        #Decode tolerantly - a stray non-UTF-8 byte should never crash
        #this check, it should just show up as a replacement character.
        return raw.decode("utf-8", errors="replace")
    #Anything else (permission denied, file vanished mid-scan, etc.)
    #just means there is nothing to search in this one file.
    except Exception:
        #Return an empty string so the caller's "nothing matched" path
        #is taken naturally.
        return ""


#Define check, the LIVE companion to collect() above - registered under
#the SAME "persistence" module name in LIVE_MODULES (see modules/
#__init__.py) so every finding it reports lands in the exact same
#"EVASIVE PERSISTENCE" bucket collect()'s own baseline-diff findings do,
#on the Dashboard. Unlike collect(), this runs every single scan, with
#no baseline needed, and looks at file CONTENT and hidden-naming, not
#just "did this file's hash change since yesterday".
def check(config, log):
    #Track every "persistence"-module key THIS function's own inline loop
    #finds still true, so it can be combined below with the key sets the
    #four sub-check functions each hand back, then resolved together in
    #one shot at the very end. Mirrors every "persistence" key string
    #log.add() is called with anywhere in this function's own loop below.
    current_keys = set()
    #Walk the exact same set of startup locations collect() hashes.
    for location in get_startup_locations():
        #Work out, up front, whether THIS location is itself a single,
        #individually-named file (like ".bashrc" or "authorized_keys")
        #rather than a directory to walk - get_startup_locations() names
        #a user's own dotfiles directly for exactly this reason, and
        #every single one of them is, by Unix shell convention, ALWAYS
        #dot-prefixed. The hidden-file check just below is looking for a
        #file that snuck INTO a normally-visible directory while blending
        #in - it was never meant to flag one of this project's own,
        #deliberately-named per-user dotfiles for simply existing and
        #being named what it is always named. Expanding the same way
        #list_files_under() does (environment variables, "~", and glob
        #patterns) is needed here too, since a raw, unexpanded location
        #string would never match a real path on disk.
        expanded_location = os.path.expandvars(os.path.expanduser(location))
        location_is_single_file = os.path.isfile(expanded_location)
        #Expand this location into every actual file sitting under it.
        for file_path in list_files_under(location):
            #Flag a dot-prefixed ("hidden") file sitting directly inside
            #one of these normally-visible autostart DIRECTORIES - this
            #is a classic "blend in, but not quite" trick: a legitimate
            #cron.d drop-in or systemd unit is never itself named with a
            #leading dot, so one that is deserves a second look. Skipped
            #entirely when this location is one of the individually-
            #named per-user dotfiles itself (see the comment just above) -
            #those are supposed to be dot-prefixed, every single time.
            base_name = os.path.basename(file_path)
            if base_name.startswith(".") and not location_is_single_file:
                #This key is true right now - remember it for resolve_stale().
                current_keys.add(f"hidden:{file_path}")
                #Report it - medium severity, since a hidden file alone
                #is suspicious but not proof of anything by itself.
                log.add("persistence", "medium", f"hidden:{file_path}",
                        f"Hidden file in an autostart location: {file_path} - a legitimate "
                        "startup entry is not normally dot-prefixed")
            #Read a text snippet of this file's own content, and search
            #it for any of the known evasive-persistence idioms above.
            content = read_text_snippet(file_path)
            #Skip the content checks entirely for a file we could not
            #read any text from at all (binary, empty, unreadable).
            if content:
                #Check every known pattern against this one file's content.
                for pattern, description in EVASIVE_CONTENT_PATTERNS:
                    #A simple substring search is enough here - these are
                    #all meant to be cheap, explainable tripwires, not a
                    #general-purpose malware scanner.
                    if pattern in content:
                        #This key is true right now - remember it for resolve_stale().
                        current_keys.add(f"evasive:{file_path}:{pattern.strip()}")
                        #Report it at high severity - these are all
                        #patterns a legitimate startup file essentially
                        #never contains.
                        log.add("persistence", "high", f"evasive:{file_path}:{pattern.strip()}",
                                f"Autostart file {file_path} {description}")
                #Check whether this file's content points its own
                #execution at a suspicious, world-writable directory.
                for suspicious_dir in SUSPICIOUS_EXEC_DIRECTORIES:
                    #Another plain substring search, same reasoning.
                    if suspicious_dir in content:
                        #This key is true right now - remember it for resolve_stale().
                        current_keys.add(f"evasive_exec:{file_path}:{suspicious_dir}")
                        #Report it at high severity.
                        log.add("persistence", "high", f"evasive_exec:{file_path}:{suspicious_dir}",
                                f"Autostart file {file_path} references an executable under "
                                f"{suspicious_dir} - not a normal install location")
    #Run the additional live checks defined above - kept as their own
    #functions (rather than folded inline into the loop above) because
    #they walk a DIFFERENT set of locations than get_startup_locations()
    #covers (dropped files outside any autostart mechanism, systemd unit
    #names specifically, and real Windows scheduled tasks/registry run
    #keys/services specifically), but still report into this exact same
    #"persistence" module name so every finding lands together in the
    #Dashboard's one EVASIVE PERSISTENCE section. Every one of these
    #no-ops on the "wrong" OS on its own (see each function's own first
    #line), so all of them are always called unconditionally here rather
    #than branching on IS_WINDOWS - only the ones that actually apply to
    #this machine's OS do anything.
    #check_foothold_directories() reports under the SEPARATE "integrity"
    #module name (see its own comment above for why) - keep its returned
    #keys apart from this function's own "persistence"-module current_keys
    #so each gets resolved against the right module/state file below.
    integrity_current_keys = check_foothold_directories(config, log)
    #The other four sub-checks all report under "persistence", the same
    #module this function's own inline loop above does - fold every key
    #they found still true into the one combined set.
    current_keys |= check_systemd_units(config, log)
    current_keys |= check_scheduled_tasks_windows(config, log)
    current_keys |= check_registry_run_keys_windows(config, log)
    current_keys |= check_services_windows(config, log)
    #Resolve anything that was flagged as of the previous scan pass but
    #has since gone away (a dropped file deleted, a task removed, a
    #registry value cleared, a service uninstalled) in one shot for each
    #of the two module names this function (and its sub-checks) report
    #under. state_name ("persistence_live"/"integrity_live") deliberately
    #does not match either module name exactly - see resolve_stale's own
    #comment in evidence.py for why that matters: integrity.py's own
    #SEPARATE baseline-diff collect() also logs under "integrity", and
    #must never share this function's own "what was true last cycle"
    #memory.
    resolve_stale(config, log, "persistence", "persistence_live", current_keys)
    resolve_stale(config, log, "integrity", "integrity_live", integrity_current_keys)
