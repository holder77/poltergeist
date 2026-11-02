#DESCRIPTION: This module answers "is anything running right now that
#             looks like malware or a reverse shell?" Unlike persistence,
#             users, and integrity, this is a LIVE module: it has no
#             baseline, it just looks at this one moment in time every
#             time it runs. It never kills or touches a flagged process;
#             it only reports it and, through evidence.capture_process,
#             saves a forensic snapshot of it.

#import psutil so we can list every running process on either OS the exact
#same way, including its executable path, parent, CPU, and memory use.
import psutil

#import platform so Windows-only checks (like masquerading as svchost.exe)
#only ever run on Windows.
import platform

#import capture_process from evidence.py so a flagged process's full
#detail and binary get saved the same way every other module would do it.
#import resolve_stale too - this module's whole job is "what does the
#process list look like RIGHT NOW", so every key it ever logs (a PID
#that matched a keyword, ran from a bad directory, etc.) can legitimately
#stop being true the instant that process is killed or exits on its own.
#Without this, a killed process's finding would sit on every Dashboard
#looking permanently active forever, simply because nothing ever told it
#otherwise - see resolve_stale's own comment in evidence.py.
from ..evidence import capture_process, resolve_stale

#Store whether we are on Windows once for the whole module to reuse.
IS_WINDOWS = platform.system() == "Windows"


#Define suggest_fix_for, which builds a safe, NON-destructive command the
#human can choose to run themselves. On Linux we suggest SIGSTOP, which
#freezes a process in place without killing it or losing any evidence;
#Windows has no exact equivalent built in, so we point at PowerShell's
#Suspend-Process where available, and otherwise just the review command.
#Poltergeist never runs either of these commands itself.
def suggest_fix_for(pid):
    #Branch based on which operating system we are on.
    if IS_WINDOWS:
        #Suggest reviewing it first, then a non-destructive PowerShell
        #suspend if the person decides it is actually malicious.
        return f"review: Get-Process -Id {pid} | Format-List *; to pause (not kill): Get-Process -Id {pid} | Suspend-Process"
    #On Linux/Unix, SIGSTOP pauses the process without killing it; it can
    #be resumed later with "kill -CONT <pid>" once it has been reviewed.
    return f"review: ps -p {pid} -o pid,ppid,user,args; to pause (not kill): kill -STOP {pid}  (resume later with kill -CONT {pid})"

#Define the list of directory fragments that are almost always writable by
#any user and are extremely common places for a dropped malicious binary
#to be launched from - running from one of these is itself high severity,
#no keyword match needed.
SUSPICIOUS_DIRECTORIES = [
    "/tmp/", "/dev/shm/", "/var/tmp/", "/windows/temp/", "/users/public/", "/appdata/local/temp/",
]

#Define UNUSUAL_INSTALL_DIRECTORIES: locations a STOCK/minimal install
#almost never runs anything from at all - added by comparing against the
#user's own Shadow Watch/Harbinger tool, which flags a process by its exe
#path landing in any of these spots (the real gap that let PID 34's
#python3 /usr/local/sbin/shadow_agent.py go unnoticed). Kept SEPARATE
#from SUSPICIOUS_DIRECTORIES above, at a lower default severity, because
#unlike /tmp or /dev/shm, real (if less common) legitimate software does
#sometimes live in /opt or /usr/local/sbin on an ordinary general-purpose
#machine - this sandbox's own Poltergeist dev environment is a case in
#point (its own CLI tooling and a couple of real utilities live under
#/opt). A name/cmdline keyword match (PROCESS_NAME_KEYWORDS below) still
#gets reported as its own separate high severity finding regardless of
#which directory it is in, so a genuinely suspicious one is never diluted
#by this directory check alone running at only medium severity.
UNUSUAL_INSTALL_DIRECTORIES = ["/usr/local/sbin/", "/opt/", "/srv/"]

#Define PROCESS_NAME_KEYWORDS, the exact same short, explainable
#malicious-tooling word list persistence.py's SUSPICIOUS_NAME_KEYWORDS
#uses, checked here against a RUNNING process's own name/command line
#instead of a file on disk - this is what actually catches something like
#a process named "shadow_agent.py" even when it is NOT (yet) running from
#one of the directories above.
PROCESS_NAME_KEYWORDS = [
    "wipe", "shadow", "miner", "backdoor", "implant", "beacon", "payload",
    "dropper", "rootkit", "respawn", "reverse", "exfil", "keylog", "guard",
]

#Define the set of process names that are normal to see running a web
#server or database, used to catch one of them spawning a shell.
SERVER_PROCESS_NAMES = {
    "nginx", "apache2", "httpd", "php-fpm", "mysqld", "postgres", "sqlservr.exe", "w3wp.exe", "java", "java.exe", "tomcat",
}

#Define the set of process names that count as a command shell, used
#together with SERVER_PROCESS_NAMES to catch a server spawning a shell.
SHELL_PROCESS_NAMES = {
    "sh", "bash", "dash", "zsh", "cmd.exe", "powershell.exe", "pwsh.exe", "nc", "ncat", "netcat",
}

#Define the set of core Windows system process names that should only
#ever be found running from inside the real System32 folder.
WINDOWS_SYSTEM_PROCESS_NAMES = {
    "svchost.exe", "lsass.exe", "csrss.exe", "services.exe", "winlogon.exe", "smss.exe",
}


#Define check, the function modules/__init__.py registers for this
#module's LIVE_MODULES entry. It takes the current config and the shared
#Log object, and reports findings directly rather than returning a value.
def check(config, log):
    #Track every key this pass actually finds to still be true, so the
    #resolve_stale() call at the very end of this function can tell which
    #previously-flagged processes have since been killed or exited and
    #report those as resolved instead of leaving them looking permanently
    #active. Must mirror, exactly, every key string log.add() is called
    #with anywhere below.
    current_keys = set()
    #Loop over every currently running process on the machine. cmdline is
    #requested here (not just name/exe) so the keyword check below can
    #catch a suspicious name that only shows up in the full command line,
    #e.g. a generic interpreter ("python3") running a suspiciously-named
    #script as its argument.
    for process in psutil.process_iter(["pid", "name", "exe", "ppid", "cmdline"]):
        #Wrap each process in its own try block so one process that exits
        #mid-check never crashes the scan of every other process.
        try:
            #Pull the lowercase process name for easy, case-safe comparison.
            name = (process.info["name"] or "").lower()
            #Pull the full executable path, defaulting to an empty string.
            exe_path = process.info["exe"] or ""
            #Pull the full command line as one joined, lowercase string -
            #cmdline is a list of args, so join it with spaces first.
            cmdline_text = " ".join(process.info.get("cmdline") or []).lower()
            #Build a lowercase, forward-slash version of the path for the
            #suspicious-directory check, so Windows backslashes still match.
            normalized_path = exe_path.lower().replace("\\", "/")
            #Pull the process ID for use in log messages.
            pid = process.info["pid"]

            #Check whether this process is running out of a classic,
            #world-writable staging directory - high severity, no keyword
            #needed, since legitimate software essentially never runs
            #from /tmp or /dev/shm.
            if exe_path and any(d in normalized_path for d in SUSPICIOUS_DIRECTORIES):
                #This key is true right now - remember it for resolve_stale().
                current_keys.add(f"dir:{exe_path}")
                #Report this as a high severity finding.
                if log.add("process", "high", f"dir:{exe_path}", f"{name} (PID {pid}) runs from writable dir: {exe_path}", suggested_fix=suggest_fix_for(pid)):
                    #Capture full forensic detail since this is brand new.
                    capture_process(config, process, "writable directory")

            #Check whether this process is running out of a location a
            #STOCK/minimal install rarely populates at all - medium
            #severity only, since (unlike the writable-dir check above)
            #real software does sometimes legitimately live here; see
            #UNUSUAL_INSTALL_DIRECTORIES' own comment for why this is
            #deliberately softer than the writable-dir finding above.
            elif exe_path and any(d in normalized_path for d in UNUSUAL_INSTALL_DIRECTORIES):
                #This key is true right now - remember it for resolve_stale().
                current_keys.add(f"dir:{exe_path}")
                #Report this at medium severity - worth a look, not proof.
                log.add("process", "medium", f"dir:{exe_path}", f"{name} (PID {pid}) runs from a location a stock install rarely uses: {exe_path}", suggested_fix=suggest_fix_for(pid))

            #Check whether this process's own name or command line
            #matches a known malicious-tooling keyword - catches something
            #like a process literally named "shadow_agent.py" even before
            #it has moved anywhere near a SUSPICIOUS_DIRECTORIES location.
            matched_keyword = next((k for k in PROCESS_NAME_KEYWORDS if k in name or k in cmdline_text), None)
            if matched_keyword:
                #This key is true right now - remember it for resolve_stale().
                current_keys.add(f"keyword:{pid}")
                #Report this as a high severity finding.
                if log.add("process", "high", f"keyword:{pid}", f"{name} (PID {pid}) matches a known malicious-tooling pattern ('{matched_keyword}'): {cmdline_text[:160] or exe_path}", suggested_fix=suggest_fix_for(pid)):
                    #Capture full forensic detail since this is brand new.
                    capture_process(config, process, f"name/cmdline matches '{matched_keyword}'")

            #Check whether the executable file itself has been deleted
            #from disk while the process is still running, a classic sign
            #of a process trying to hide its own binary.
            if exe_path.endswith("(deleted)"):
                #This key is true right now - remember it for resolve_stale().
                current_keys.add(f"del:{pid}")
                #Report this as a high severity finding.
                if log.add("process", "high", f"del:{pid}", f"{name} (PID {pid}) binary was deleted from disk", suggested_fix=suggest_fix_for(pid)):
                    #Capture full forensic detail since this is brand new.
                    capture_process(config, process, "deleted binary")

            #On Windows only, check whether a core system process name is
            #running from somewhere other than the real System32 folder.
            if IS_WINDOWS and name in WINDOWS_SYSTEM_PROCESS_NAMES and exe_path and "/windows/system32/" not in normalized_path:
                #This key is true right now - remember it for resolve_stale().
                current_keys.add(f"masq:{pid}")
                #Report this as a high severity finding.
                if log.add("process", "high", f"masq:{pid}", f"{name} (PID {pid}) outside System32: {exe_path}", suggested_fix=suggest_fix_for(pid)):
                    #Capture full forensic detail since this is brand new.
                    capture_process(config, process, "masquerading system process")

            #Look up this process's parent so we can catch a web server or
            #database spawning a command shell, a common web-shell pattern.
            parent = process.parent()
            #Check whether the parent is a known server and this process
            #is a known shell.
            if parent and parent.name().lower() in SERVER_PROCESS_NAMES and name in SHELL_PROCESS_NAMES:
                #This key is true right now - remember it for resolve_stale().
                current_keys.add(f"spawn:{pid}")
                #Report this as a high severity finding.
                if log.add("process", "high", f"spawn:{pid}", f"{parent.name()} spawned {name} (PID {pid}), possible web shell", suggested_fix=suggest_fix_for(pid)):
                    #Capture full forensic detail since this is brand new.
                    capture_process(config, process, "server spawned shell")

            #Read this process's current CPU and memory usage.
            cpu_percent = process.cpu_percent(interval=None)
            memory_percent = process.memory_percent()
            #Check whether either usage crosses the configured thresholds,
            #which could indicate a crypto miner or a denial-of-service
            #attempt running on the box.
            if cpu_percent > config["cpu_threshold"] or memory_percent > config["mem_threshold"]:
                #This key is true right now - remember it for resolve_stale().
                #Keyed by name alone (not PID), so it only resolves once NO
                #process with this name is still over either threshold.
                current_keys.add(f"res:{name}")
                #Report this at medium severity since high usage alone is
                #not proof of malice, just something worth a human look.
                log.add("process", "medium", f"res:{name}", f"{name} (PID {pid}) using CPU {cpu_percent:.0f}% / MEM {memory_percent:.0f}%")
        #Catch the normal "process already gone" and "no permission" cases
        #that happen constantly while scanning a live process list.
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            #Simply move on to the next process in the loop.
            continue

    #Every PID/name this pass actually saw as still matching something is
    #now in current_keys - compare that against what was flagged as of
    #the previous scan pass, and report anything that dropped out (killed,
    #exited, or simply no longer over a threshold) as resolved instead of
    #leaving it looking permanently active on every Dashboard. See
    #resolve_stale's own comment in evidence.py for the full reasoning.
    resolve_stale(config, log, "process", "process", current_keys)
