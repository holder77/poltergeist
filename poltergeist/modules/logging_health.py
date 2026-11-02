#DESCRIPTION: This module answers two related questions: "is the system's
#             own logging still turned on?" and "did a log file just get
#             smaller, which usually means someone cleared it to cover
#             their tracks?" A red team's very first move after getting a
#             foothold is often to stop the logging daemon or truncate
#             auth.log / the Windows Security log, so catching that is as
#             important as catching the intrusion itself. This is a LIVE
#             module (no baseline needed for the service-status half), but
#             the log-shrink half needs to remember each log file's size
#             from the PREVIOUS check, so it keeps its own tiny state file
#             inside the evidence directory rather than using the single
#             fixed STATE_MODULES baseline (which only compares against
#             the one snapshot taken at the very start).

#import os so we can check file sizes and build paths.
import os

#import json so this module can save/load its own small size-tracking
#state file between one check and the next.
import json

#import platform so we check the right logging service names per OS.
import platform

#import subprocess so we can query service status.
import subprocess

#Store whether we are on Windows once for the whole module to reuse.
IS_WINDOWS = platform.system() == "Windows"

#Windows-only fix for a real bug report: check_logging_service() below
#shells out to "sc query eventlog" on every single scan (this module is
#a registered LIVE_MODULE) - without this, that's a visible console
#window flashing open and closed once per scan. See modules/users.py's
#own copy of this exact fix for the full explanation; the short version
#is CREATE_NO_WINDOW tells Windows not to allocate a console for the
#child process at all, and the ternary keeps this safe to import on
#Linux too.
_HIDE_CONSOLE_KWARGS = {"creationflags": subprocess.CREATE_NO_WINDOW} if IS_WINDOWS else {}

#List the log files worth watching for a sudden size decrease. These are
#the most commonly cleared logs on each OS; the user can add more to
#their own copy by editing this list.
WATCHED_LOG_FILES_LINUX = [
    "/var/log/auth.log", "/var/log/secure", "/var/log/syslog",
    "/var/log/messages", "/var/log/audit/audit.log",
]


#Define run_command, the same small wrapper pattern used in every other
#module, kept local so this module stays self-contained. Unlike most of
#the other modules' versions, this one also tells the caller whether the
#command actually ran at all, because for THIS module "I could not check"
#and "I checked and it's fine" must never be treated as the same thing -
#silently saying nothing when systemctl itself is unavailable (a minimal
#container, a non-systemd distro) would hide a real logging outage.
def run_command(command):
    #Try to run the command and capture its output.
    try:
        #Give the command 10 seconds before giving up.
        #**_HIDE_CONSOLE_KWARGS suppresses the flashing console window
        #this would otherwise pop open on Windows (see that constant's
        #own comment above).
        result = subprocess.run(command, capture_output=True, text=True, timeout=10, **_HIDE_CONSOLE_KWARGS)
        #Return the output text and whether the command itself succeeded.
        return result.stdout, result.returncode == 0
    #If the command fails or is missing, do not crash the scan.
    except Exception:
        #Return an empty string and False, meaning "could not even run this".
        return "", False


#Define state_file_path, a tiny helper so this module's own size-tracking
#file is always found at the same, predictable location.
def state_file_path(config):
    #Build the path inside the evidence directory, clearly named so it is
    #obvious what this file is for if a human stumbles across it.
    return os.path.join(config["evidence_dir"], "log_size_tracking.json")


#Define load_previous_sizes, which reads this module's own memory of the
#last size seen for each watched log file.
def load_previous_sizes(config):
    #Build the path to our tracking file.
    path = state_file_path(config)
    #If we have never tracked anything before, start from an empty dict.
    if not os.path.exists(path):
        #Return an empty dictionary, treated as "no history yet".
        return {}
    #Try to read and parse the tracking file.
    try:
        #Open and parse the JSON content.
        with open(path) as tracking_file:
            #Return the parsed dictionary of {path: last_known_size}.
            return json.load(tracking_file)
    #If the file is corrupted for any reason, start fresh rather than crash.
    except Exception:
        #Return an empty dictionary.
        return {}


#Define save_current_sizes, which writes this module's updated memory of
#every watched log file's current size, ready for the next check to
#compare against.
def save_current_sizes(config, sizes):
    #Open the tracking file for writing, creating it on the first run.
    with open(state_file_path(config), "w") as tracking_file:
        #Write the dictionary back out as JSON.
        json.dump(sizes, tracking_file)


#Define check_logging_service, which verifies the OS's own logging
#daemon/service is actually still running.
def check_logging_service(config, log):
    #Branch based on which operating system we are on.
    if IS_WINDOWS:
        #Query the Windows Event Log service's current status.
        output, ran_ok = run_command(["sc", "query", "eventlog"])
        #Only draw a conclusion if the query command actually ran.
        if ran_ok and "RUNNING" not in output:
            #Report this at high severity; a stopped Event Log service
            #means Windows itself has largely stopped recording history.
            log.add("logging", "high", "eventlog", "Windows Event Log service is not running", suggested_fix="review: sc query eventlog; to restart: sc start eventlog")
        #If the query command itself could not run, say so rather than
        #silently implying everything is fine.
        elif not ran_ok:
            #Report at informational severity: this is a visibility gap,
            #not evidence of tampering by itself.
            log.add("logging", "info", "eventlog_unknown", "Could not query the Windows Event Log service status", quiet_dupes=False)
    else:
        #Track whether at least one of the systemd checks actually ran,
        #so we can tell "all healthy" apart from "systemd isn't even here".
        any_check_ran = False
        #Check each common Linux logging daemon in turn.
        for service_name in ("rsyslog", "systemd-journald", "auditd"):
            #Ask systemd whether this particular service is active.
            output, ran_ok = run_command(["systemctl", "is-active", service_name])
            #Only treat this as a real answer if the command actually ran.
            if ran_ok:
                #Remember that at least one systemd check succeeded.
                any_check_ran = True
                #A stopped or failed logging daemon is a high severity finding.
                status = output.strip()
                if status in ("inactive", "failed"):
                    #Report it with a safe, read-only review/restart suggestion.
                    log.add("logging", "high", f"svc:{service_name}", f"{service_name} is {status}", suggested_fix=f"review: systemctl status {service_name}; to restart: systemctl start {service_name}")
        #If systemd could not answer for ANY of the three services (this
        #box may not use systemd at all, e.g. a minimal container or an
        #older init system), say so plainly instead of staying silent.
        if not any_check_ran:
            #Report at informational severity, once, not per service.
            log.add("logging", "info", "systemd_unavailable", "Could not query systemd service status on this box (it may not use systemd) - logging health here is unverified", quiet_dupes=False)


#Define check_log_shrinkage, which compares every watched log file's
#current size against what we saw last check, and flags any file that
#got SMALLER, since legitimate logs only ever grow (or get rotated into
#a new file, which this module treats separately, not as a shrink).
def check_log_shrinkage(config, log):
    #Linux-only for now; Windows Event Logs are binary and rotate through
    #the Event Log service itself rather than as flat files on disk.
    #TODO: add a Windows equivalent using Get-WinEvent record counts.
    if IS_WINDOWS:
        #Return immediately; nothing to check on this OS yet.
        return
    #Load what we remembered from the previous check.
    previous_sizes = load_previous_sizes(config)
    #Start building this check's fresh size readings.
    current_sizes = {}
    #Loop over every log file we are watching.
    for log_path in WATCHED_LOG_FILES_LINUX:
        #Skip any log file that does not exist on this particular box.
        if not os.path.isfile(log_path):
            #Move on to the next watched path.
            continue
        #Read this file's current size in bytes.
        current_size = os.path.getsize(log_path)
        #Record it for next time, regardless of what we find below.
        current_sizes[log_path] = current_size
        #Look up what size we saw for this file last check.
        previous_size = previous_sizes.get(log_path)
        #Only compare if we actually have a previous reading to compare
        #against; the very first check has nothing to compare yet.
        if previous_size is not None and current_size < previous_size:
            #A log file getting smaller is a strong sign it was cleared.
            log.add("logging", "high", f"shrink:{log_path}", f"{log_path} shrank from {previous_size} to {current_size} bytes - possible log clearing", suggested_fix=f"review: stat {log_path}; ls -la {os.path.dirname(log_path)}  (check for a .1 rotated copy before assuming malice)")
    #Save this check's readings so the NEXT check can compare against them.
    save_current_sizes(config, current_sizes)


#Define check, the function modules/__init__.py registers for this
#module's LIVE_MODULES entry.
def check(config, log):
    #Run the logging-service-is-alive check first.
    check_logging_service(config, log)
    #Then run the log-file-shrank check.
    check_log_shrinkage(config, log)
