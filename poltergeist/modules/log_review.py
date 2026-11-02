#DESCRIPTION: This module is "look through logs of current machine",
#             now covering BOTH operating systems for real (not just a
#             Linux auth.log, and not just "Windows isn't supported
#             yet") and, on Linux, "all the logs a distro would have,
#             not just auth.log" - direct answers to this round's
#             feedback. Built on two small, testable cores:
#               - analyze_lines() - OpenSSH-style plain-text log lines
#                 (Linux: auth.log/secure, syslog, and everything else
#                 list_linux_log_files() finds, plus a journalctl
#                 fallback on journald-only distros with no flat file).
#               - analyze_windows_event_blocks() - wevtutil's own
#                 "/f:text" event-block format (Windows: a LIVE read of
#                 the real Security log via wevtutil itself, or an
#                 uploaded text/CSV export of one).
#             Both feed the SAME shared brute-force tally
#             (_tally_brute_force), so "5+ failures from one source,
#             especially followed by a success" means the same thing
#             and is reported the same way regardless of which OS or
#             which path (live vs. uploaded) found it.
#
#             Three public entry points: (1) check(), the LIVE module
#             (registered in modules/__init__.py's LIVE_MODULES under
#             module name "logs") that reads the monitored machine's
#             own real logs on every scan; (2) analyze_uploaded_text(),
#             called by the GUI's "Upload Log" button for a plain-text
#             log (Linux-style lines OR a wevtutil text export) from the
#             analyst's own machine; (3) a binary Windows .evtx upload
#             is handled by the separate evtx_review.py module (see its
#             own top comment for why that one stays intentionally
#             basic), which app.py's upload handler reaches for only
#             when the uploaded bytes start with the EVTX file magic.

#import os so check() can find and read the real log files on this
#machine.
import os

#import re for every line/text pattern this file looks for.
import re

#import platform so check() branches cleanly between the Linux
#plain-text-log approach and the Windows Event Log approach - the two
#are genuinely different log systems, not the same thing read two ways.
import platform

#import subprocess for journalctl (Linux, used only as a fallback when
#no flat log file exists at all - see list_linux_log_files()) and
#wevtutil (Windows, the standard built-in command-line way to read the
#Event Log - no new dependency, exactly like modules/snapshot.py and
#modules/lockdown.py already shell out to OS-native tools for things
#Python has no portable library for).
import subprocess

#import glob so list_linux_log_files() can pick up *.log files this
#module's own fixed name list doesn't happen to know about, instead of
#only ever reading exactly the files it was told about in advance.
import glob

#Store whether we are on Windows once for the whole module to reuse.
IS_WINDOWS = platform.system() == "Windows"

#Windows-only fix for a real bug report: read_windows_eventlog_tail()
#below shells out to "wevtutil" on every single scan (this module is a
#registered LIVE_MODULE) - without this, that's a visible console window
#flashing open and closed once per scan. See modules/users.py's own copy
#of this exact fix for the full explanation; the short version is
#CREATE_NO_WINDOW tells Windows not to allocate a console for the child
#process at all, and the ternary keeps this safe to import on Linux too
#(where it's never actually needed, since journalctl - the Linux
#equivalent just below - never pops a console window in the first place).
_HIDE_CONSOLE_KWARGS = {"creationflags": subprocess.CREATE_NO_WINDOW} if IS_WINDOWS else {}

#The two SSH-specific auth log paths, kept as their own named constant
#since they are what "the" auth log actually is on the two main Linux
#families (Debian/Ubuntu use auth.log, RHEL/CentOS/Fedora use secure) -
#still read first, and still what most blue-team SSH-brute-force
#questions are really asking about, but no longer the ONLY logs read.
LINUX_AUTH_LOG_PATHS = ["/var/log/auth.log", "/var/log/secure"]

#The directory every other known/discovered Linux log file below is
#found under - by far the standard location across every mainstream
#distribution.
LINUX_LOG_DIRECTORY = "/var/log"

#A deliberately BROAD list of well-known Linux system log filenames -
#the "I mean everything" ask, not just auth.log. Every one of these is
#only ever actually read if it exists on THIS particular distribution;
#nothing here assumes any one of them is present. Covers general system
#activity (syslog/messages), the kernel ring buffer as logged to disk,
#background services, scheduled tasks, mail, boot, and the two major
#package managers' own install/upgrade history - exactly the kind of
#thing a blue-team competitor digs through by hand otherwise.
LINUX_KNOWN_LOG_FILENAMES = [
    "auth.log", "secure",                      # authentication (see LINUX_AUTH_LOG_PATHS above)
    "syslog", "messages",                       # general system log
    "kern.log", "kernel.log",                   # kernel messages
    "daemon.log",                                # background service messages
    "cron", "cron.log",                          # scheduled task log
    "maillog", "mail.log",                       # mail subsystem
    "boot.log",                                  # boot-time messages
    "dpkg.log", "alternatives.log",              # Debian/Ubuntu package management
    "yum.log", "dnf.log", "dnf.rpm.log",         # RHEL/Fedora package management
    "ufw.log",                                    # Ubuntu's firewall front-end
]

#Filenames under LINUX_LOG_DIRECTORY that are NOT plain text - these are
#fixed-record BINARY formats (login/logout session records, failed-
#login counters), and reading them as text would show nothing but
#garbage. Excluded from both the known-filename list above and from the
#*.log glob below, so "read every log" never means "read every log AS
#IF it were text".
LINUX_BINARY_LOG_FILENAMES = {"wtmp", "btmp", "lastlog", "faillog"}

#How many of a log file's own most recent lines to actually read and
#analyze - capped so a multi-gigabyte, years-old log file never turns
#one scan into a multi-minute read. 4000 lines comfortably covers many
#hours of even a busy box's activity.
MAX_LOG_LINES = 4000

#How many journalctl lines to pull on a journald-only distro with no
#flat log file at all (see list_linux_log_files()'s own fallback note).
MAX_JOURNALCTL_LINES = 4000

#How many failed login attempts from the same source IP, within the
#lines/events actually read, count as "enough to call this a
#brute-force attempt" rather than just an ordinary mistyped password or
#two. Shared by both the Linux line-based path and the Windows
#event-based path.
BRUTE_FORCE_THRESHOLD = 5

#The two line shapes the Linux path looks for - OpenSSH's own, very
#consistent log wording for a failed vs. a successful login, covering
#both a valid-but-wrong-password username and an outright invalid one
#(sshd logs both the exact same way except for the phrase "invalid
#user"). Capturing the source IP, not the username, since the SAME IP
#trying many different usernames (or the same one repeatedly) is the
#actual brute-force signal either way.
FAILED_LOGIN_PATTERN = re.compile(r"Failed password for (?:invalid user )?\S+ from (\d{1,3}(?:\.\d{1,3}){3})")
ACCEPTED_LOGIN_PATTERN = re.compile(r"Accepted (?:password|publickey) for (\S+) from (\d{1,3}(?:\.\d{1,3}){3})")

#The three standard Windows Event Log channels worth reading live -
#Security carries the actual logon events this module cares most about
#(see WINDOWS_FAILED_LOGON_EVENT_ID below), System and Application are
#read too since "look through logs" was not scoped to logons only.
WINDOWS_EVENT_LOGS = ["Security", "System", "Application"]

#How many of a Windows Event Log channel's own most recent events to
#pull per scan/view - same reasoning as MAX_LOG_LINES above, just
#counted in events instead of lines (a single event's /f:text block is
#several lines long).
MAX_WINDOWS_EVENTS = 1000

#The two Windows Security-log Event IDs this module actually interprets
#- 4625 (An account failed to log on) and 4624 (An account was
#successfully logged on) are the Windows equivalents of OpenSSH's own
#"Failed password"/"Accepted password" lines, logged by the built-in
#Microsoft-Windows-Security-Auditing provider on every Windows box with
#logon auditing enabled (the default on a domain-joined machine; a
#standalone box may need it turned on by hand - this module has no way
#to turn that on itself, only to read what's already being logged).
WINDOWS_FAILED_LOGON_EVENT_ID = "4625"
WINDOWS_ACCEPTED_LOGON_EVENT_ID = "4624"


#Define read_tail_lines, reading at most the last max_lines lines of a
#text file - tolerant of anything that is not valid UTF-8, same
#reasoning persistence.py's own read_text_snippet() uses: a log line
#with a stray bad byte in it should never crash this check.
def read_tail_lines(path, max_lines=MAX_LOG_LINES):
    #Wrap the whole read, since the file could vanish, be a special
    #device file, or be unreadable without elevated privileges.
    try:
        #Open in text mode with tolerant decoding.
        with open(path, "r", errors="replace") as log_file:
            #Read every line - for a file small enough to be a sane
            #thing to tail at all, this is simpler and plenty fast
            #enough than seeking backward from the end byte by byte.
            all_lines = log_file.readlines()
        #Hand back just the most recent max_lines of them.
        return all_lines[-max_lines:]
    #Anything else (permission denied, file does not exist, etc.) just
    #means there is nothing to analyze from this one file.
    except Exception:
        #Return an empty list so the caller's "nothing found" path is
        #taken naturally.
        return []


#Define list_linux_log_files, returning every readable, plain-text log
#file this machine actually has - the "everything", not just auth.log.
#Combines the fixed LINUX_KNOWN_LOG_FILENAMES list (so a file with an
#uncommon name but a common PURPOSE still gets read) with a glob for
#anything ending in ".log" this module's own list doesn't happen to
#know about (so a distro- or app-specific log this list never
#anticipated still gets picked up), explicitly excluding the binary
#formats in LINUX_BINARY_LOG_FILENAMES either way. Returns full paths,
#sorted, with LINUX_AUTH_LOG_PATHS' own two files pinned first (if
#present) since those are the ones most worth seeing at the top.
def list_linux_log_files():
    #Start from the fixed list of known filenames, turned into full paths.
    candidate_paths = {os.path.join(LINUX_LOG_DIRECTORY, name) for name in LINUX_KNOWN_LOG_FILENAMES}
    #Add anything else ending in .log this machine actually has, caught
    #by the glob rather than this module's own fixed list of names.
    try:
        candidate_paths.update(glob.glob(os.path.join(LINUX_LOG_DIRECTORY, "*.log")))
    #A glob can fail if LINUX_LOG_DIRECTORY itself doesn't exist at all
    #(a very unusual machine, or a test's own scratch directory) - treat
    #that the same as "nothing extra found", not a crash.
    except Exception:
        pass
    #Keep only the ones that actually exist, are regular readable files,
    #and are not one of the known-binary formats.
    existing_paths = []
    for path in candidate_paths:
        if os.path.basename(path) in LINUX_BINARY_LOG_FILENAMES:
            #A binary record format, not a text log - skip it outright.
            continue
        if os.path.isfile(path) and os.access(path, os.R_OK):
            #A real, readable, plain-text-ish log file.
            existing_paths.append(path)
    #Put the two dedicated auth-log paths first (if they're in the
    #set at all), then everything else alphabetically, so the most
    #security-relevant file is always the first thing shown/scanned.
    def sort_key(path):
        return (0, path) if path in LINUX_AUTH_LOG_PATHS else (1, path)
    return sorted(existing_paths, key=sort_key)


#Define read_journalctl_tail, a fallback for a journald-only distro
#(nothing in LINUX_LOG_DIRECTORY at all - increasingly common: this
#project's own development sandbox is one example) where there is no
#flat log FILE to read in the first place. journalctl is the standard,
#always-present command on any systemd-based Linux box; this is run
#read-only and bounded, exactly like the Windows side's wevtutil call
#below.
def read_journalctl_tail(max_lines=MAX_JOURNALCTL_LINES):
    try:
        #"-n <N>" caps how many of the most recent lines are returned;
        #"--no-pager" stops it from trying to launch an interactive
        #pager, which would otherwise hang this call forever since
        #nothing here can respond to a pager prompt.
        result = subprocess.run(
            ["journalctl", "-n", str(max_lines), "--no-pager"],
            capture_output=True, text=True, errors="replace", timeout=30,
        )
        #A non-zero exit (journalctl not usable, no permission to read
        #the system journal, etc.) means there's nothing usable here.
        if result.returncode != 0:
            return []
        return result.stdout.splitlines(keepends=True)
    #journalctl not installed at all, timed out, or anything else that
    #went wrong - treat it the same as "nothing available", never crash.
    except Exception:
        return []


#Define _tally_brute_force, the shared core BOTH the Linux line-based
#path and the Windows event-based path below feed into once they've
#each reduced their own very different raw input down to the same
#plain shape: "this IP failed N times" and "this IP succeeded at least
#once". Kept as its own function so the brute-force THRESHOLD and
#MESSAGE WORDING live in exactly one place, not duplicated between an
#OpenSSH-flavored and a Windows-flavored copy that could quietly drift
#apart from each other over time.
def _tally_brute_force(failed_counts, succeeded_ips):
    results = []
    #Walk every source IP that had ANY failed attempts.
    for source_ip, fail_count in failed_counts.items():
        #Below the threshold - not enough to call this a real pattern,
        #same reasoning network.py's own beacon check uses for its own
        #minimum-sample requirement.
        if fail_count < BRUTE_FORCE_THRESHOLD:
            #Nothing to report for this IP.
            continue
        #Report the brute-force attempt itself.
        results.append((
            "high", f"bruteforce:{source_ip}",
            f"{fail_count} failed login attempts from {source_ip} - possible brute-force attempt",
        ))
        #If that SAME IP also succeeded at some point, this is a much
        #more urgent signal: a brute-force that appears to have worked.
        if source_ip in succeeded_ips:
            #Report it as its own, separately-keyed, even more urgent
            #finding - never silently folded into the line above, since
            #a human scanning the Dashboard should see this one first.
            results.append((
                "high", f"bruteforce_success:{source_ip}",
                f"{source_ip} logged in successfully AFTER {fail_count} failed attempts - "
                "possible SUCCESSFUL brute-force; review this account's recent activity now",
            ))
    #Hand back the finished list.
    return results


#Define analyze_lines, the pure, testable core of the LINUX half of this
#file: given a plain list of text lines (from a live system log OR an
#uploaded file - this function has no idea which), return a plain list
#of (severity, key, message) tuples for every brute-force or
#successful-login-after-brute-force pattern found. Nothing here touches
#Tkinter, the filesystem, or the shared Log object directly, so this one
#function can be - and is, see log_review_test.py - tested completely on
#its own.
def analyze_lines(lines):
    #Count failed attempts per source IP, and remember whether any
    #successful login was ALSO seen from that same IP.
    failed_counts = {}
    succeeded_ips = set()
    #Walk every line exactly once.
    for line in lines:
        #Check this line against the failed-login pattern first.
        failed_match = FAILED_LOGIN_PATTERN.search(line)
        if failed_match:
            #Pull out the source IP and bump its running count.
            source_ip = failed_match.group(1)
            failed_counts[source_ip] = failed_counts.get(source_ip, 0) + 1
            #A line cannot be both a failure and a success - move on.
            continue
        #Check this line against the successful-login pattern.
        accepted_match = ACCEPTED_LOGIN_PATTERN.search(line)
        if accepted_match:
            #Remember that this source IP successfully logged in at
            #some point within the lines we are looking at.
            succeeded_ips.add(accepted_match.group(2))
    #Hand the counted-up tallies to the shared core.
    return _tally_brute_force(failed_counts, succeeded_ips)


#Define split_wevtutil_text_events, breaking wevtutil's own "/f:text"
#output (one long block of text covering many events) into a list of
#per-event text chunks - each one starts with a line shaped like
#"Event[12]:". Kept separate from parse_windows_event_block() below so
#each piece can be tested (and reasoned about) on its own, the same
#split this file already uses between read_tail_lines()/analyze_lines().
WEVTUTIL_EVENT_START_PATTERN = re.compile(r"^Event\[\d+\]:", re.MULTILINE)


def split_wevtutil_text_events(text):
    #Find the start position of every "Event[N]:" line.
    starts = [match.start() for match in WEVTUTIL_EVENT_START_PATTERN.finditer(text)]
    #Nothing matched at all - this text doesn't look like wevtutil's
    #own text format in the first place.
    if not starts:
        return []
    #Slice the text into one chunk per event, from each start up to the
    #next one (or the end of the text for the last one).
    blocks = []
    for index, start in enumerate(starts):
        end = starts[index + 1] if index + 1 < len(starts) else len(text)
        blocks.append(text[start:end])
    return blocks


#The field patterns parse_windows_event_block() looks for within ONE
#event's own text block. "Account Name:" and "Source Network Address:"
#can each appear MORE THAN ONCE in a real 4624/4625 block (once under
#"Subject:"/blank placeholder fields, again under the section that
#actually names the logon attempt itself) - re.findall() plus taking
#the LAST match is a deliberate, documented heuristic for picking the
#one that actually describes the logon attempt, not an accident; see
#parse_windows_event_block()'s own comment for why.
WEVTUTIL_EVENT_ID_PATTERN = re.compile(r"Event ID:\s*(\d+)")
WEVTUTIL_ACCOUNT_NAME_PATTERN = re.compile(r"Account Name:\s*(\S+)")
WEVTUTIL_SOURCE_ADDRESS_PATTERN = re.compile(r"Source Network Address:\s*(\S+)")


#Define parse_windows_event_block, pulling the event ID, source IP, and
#account name out of ONE wevtutil-formatted event block, for whichever
#of the two logon event IDs this module actually interprets. Returns
#None for any event this module doesn't care about (every OTHER event
#ID, or a 4624/4625 missing the fields needed), so the caller can
#simply skip it.
#
#HONEST LIMITATION: wevtutil's own text format is not formally
#specified and can vary slightly by Windows version/locale - this is a
#best-effort match against the standard English-language layout
#(verified against real wevtutil output at the time this was written),
#not a guaranteed-correct structured parse. A source address of "-"
#(a local/console logon, which has no network address at all) is
#treated as "no usable IP" and the event is skipped for brute-force
#tallying purposes, same as a line with no match at all.
def parse_windows_event_block(block):
    event_id_match = WEVTUTIL_EVENT_ID_PATTERN.search(block)
    if not event_id_match:
        #Not even a recognizable event block - nothing to parse.
        return None
    event_id = event_id_match.group(1)
    if event_id not in (WINDOWS_FAILED_LOGON_EVENT_ID, WINDOWS_ACCEPTED_LOGON_EVENT_ID):
        #Some other event ID this module has no opinion about.
        return None
    #Take the LAST "Source Network Address:"/"Account Name:" match in
    #the block - see this function's own docstring above for why.
    address_matches = WEVTUTIL_SOURCE_ADDRESS_PATTERN.findall(block)
    account_matches = WEVTUTIL_ACCOUNT_NAME_PATTERN.findall(block)
    source_ip = address_matches[-1] if address_matches else None
    account_name = account_matches[-1] if account_matches else None
    #A dash (or nothing at all) means no real network address was
    #recorded for this logon (most commonly: a local console logon) -
    #there is no IP to tally against, so treat it as unusable.
    if not source_ip or source_ip == "-" or not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", source_ip):
        return None
    return {"event_id": event_id, "source_ip": source_ip, "account_name": account_name or "?"}


#Define analyze_windows_event_blocks, the pure, testable core of the
#WINDOWS half of this file - the exact same role analyze_lines() plays
#for Linux, just fed wevtutil's own per-event text blocks instead of
#plain log lines. Used by BOTH check()'s own live wevtutil read and by
#an uploaded text/CSV export of the Security log.
def analyze_windows_event_blocks(blocks):
    failed_counts = {}
    succeeded_ips = set()
    for block in blocks:
        parsed = parse_windows_event_block(block)
        if parsed is None:
            #Not a 4624/4625 event with a usable source IP.
            continue
        if parsed["event_id"] == WINDOWS_FAILED_LOGON_EVENT_ID:
            failed_counts[parsed["source_ip"]] = failed_counts.get(parsed["source_ip"], 0) + 1
        else:
            succeeded_ips.add(parsed["source_ip"])
    #Hand the counted-up tallies to the exact same shared core the
    #Linux path uses - same threshold, same message wording.
    return _tally_brute_force(failed_counts, succeeded_ips)


#Define read_windows_eventlog_tail, pulling the most recent events from
#one real Windows Event Log channel on THIS machine via wevtutil - the
#standard, always-present, built-in Windows command-line tool for this
#(no new dependency, same approach modules/snapshot.py and
#modules/lockdown.py already take for things Python has no portable
#library for). Returns the raw text/f:text output, or "" if it could
#not be read (wrong OS, insufficient privilege, channel doesn't exist).
def read_windows_eventlog_tail(log_name, max_events=MAX_WINDOWS_EVENTS):
    try:
        #"/rd:true" reads newest-first, so "/c:<N>" naturally caps to
        #the N MOST RECENT events rather than the N oldest ones.
        #**_HIDE_CONSOLE_KWARGS suppresses the flashing console window
        #this would otherwise pop open on Windows (see that constant's
        #own comment above).
        result = subprocess.run(
            ["wevtutil", "qe", log_name, f"/c:{max_events}", "/rd:true", "/f:text"],
            capture_output=True, text=True, errors="replace", timeout=30,
            **_HIDE_CONSOLE_KWARGS,
        )
        if result.returncode != 0:
            return ""
        return result.stdout
    #wevtutil missing (should never happen on real Windows, but this
    #function must never crash the scan if it somehow is), access
    #denied (Security log needs an elevated prompt on some setups), or
    #a timeout - all treated the same as "nothing available".
    except Exception:
        return ""


#Define check, the LIVE module registered in modules/__init__.py's
#LIVE_MODULES under module name "logs". Branches on the real OS this
#code is actually running on (local target: this literally running
#machine; remote target: the SAME code runs on the monitored machine
#itself, since quickscan.run() - which calls every LIVE_MODULES entry -
#is what gets deployed and invoked there, see modules/remote.py's own
#dispatch() for how "run quickscan.py over there" actually works).
def check(config, log):
    if IS_WINDOWS:
        #Read the Security channel live via wevtutil and run the
        #Windows-side brute-force analysis against it.
        raw_text = read_windows_eventlog_tail("Security")
        if not raw_text:
            #wevtutil itself failed (no privilege, channel unavailable,
            #etc.) - say so plainly rather than silently reporting
            #nothing and leaving a human to wonder why.
            log.add("logs", "info", "windows_eventlog_unavailable",
                    "Could not read the Security event log via wevtutil - this may need an "
                    "elevated prompt, or Audit Logon/Logoff may not be enabled on this machine")
            return
        blocks = split_wevtutil_text_events(raw_text)
        for severity, key, message in analyze_windows_event_blocks(blocks):
            log.add("logs", severity, f"live:winevt-security:{key}", f"[Security event log] {message}")
        return
    #Linux: read EVERY known/discovered plain-text log file, not just
    #the dedicated auth log(s) - the "I mean everything" ask.
    log_paths = list_linux_log_files()
    for log_path in log_paths:
        for severity, key, message in analyze_lines(read_tail_lines(log_path)):
            #Report each finding, keyed by the log path too so the exact
            #same source IP pattern found in two different log files
            #(unlikely, but possible) is not silently deduplicated away.
            log.add("logs", severity, f"live:{log_path}:{key}", f"[{log_path}] {message}")
    #No flat log file exists at all - a journald-only distro (this
    #project's own development sandbox is one real example). Fall back
    #to journalctl's own text output rather than reporting nothing just
    #because there was no FILE to point at.
    if not log_paths:
        for severity, key, message in analyze_lines(read_journalctl_tail()):
            log.add("logs", severity, f"live:journalctl:{key}", f"[journalctl] {message}")


#Define list_available_logs, which answers "what logs/event channels
#could I even look at on THIS machine" as a plain, JSON-serializable list
#of {"id", "label"} dictionaries - "id" is what read_log_content() below
#expects back (a real file path on Linux, "journalctl" for the fallback,
#or a Windows Event Log channel name), "label" is what a person actually
#reads in a picker. This is the shared core behind BOTH a local "View
#System Logs" picker (gui/app.py calls this directly) and a remote one
#(cli.py's --list-logs flag calls this same function and prints its
#result as JSON, over SSH, via modules/remote.py's list_remote_logs()) -
#one implementation, so a remote target's own picker always lists
#exactly what IT has, never what the analyst's own machine has.
def list_available_logs():
    if IS_WINDOWS:
        #The three standard channels this module already knows how to
        #read/analyze - same set check()/the old "View System Logs" dump
        #already used, just now offered as individually pickable items
        #instead of all three dumped into one window at once.
        return [{"id": name, "label": f"{name} (Windows Event Log)"} for name in WINDOWS_EVENT_LOGS]
    #Linux: every real, readable log file this machine actually has.
    log_paths = list_linux_log_files()
    if log_paths:
        return [{"id": path, "label": path} for path in log_paths]
    #No flat log file exists at all - offer journalctl itself as the one
    #pickable item, same fallback check()/the old dump already used.
    return [{"id": "journalctl", "label": "journalctl (no flat log files found on this machine)"}]


#Define read_log_content, which reads and analyzes exactly ONE log/
#channel by the "id" list_available_logs() above handed out, returning a
#plain, JSON-serializable dictionary: {"name": the id itself, "raw_text":
#the log's own raw tail text, ready to show/search as-is, "findings": the
#same (severity, key, message) tuples analyze_lines()/analyze_windows_
#event_blocks() already produce, for the "WORTH A LOOK" summary a viewer
#shows above the raw text} - or {"name", "raw_text": "", "findings": [],
#"error": ...} if the id was not recognized at all. The shared core
#behind both a local picker (gui/app.py calls this directly) and a
#remote one (cli.py's --read-log flag calls this same function and
#prints its result as JSON, via modules/remote.py's read_remote_log()) -
#same "one implementation, reused over SSH" reasoning as list_available_
#logs() above. Deliberately never writes anything to the shared Log
#object/findings.jsonl - check() already does that, on its own regular
#schedule; opening one log in a viewer to look at it is a read, not a
#new scan, and should never create a second, differently-keyed copy of
#findings check() already reports.
def read_log_content(name):
    if IS_WINDOWS:
        #Only a real, known channel name is acceptable here - anything
        #else is not a mistake worth guessing at, just an unrecognized id.
        if name not in WINDOWS_EVENT_LOGS:
            return {"name": name, "raw_text": "", "findings": [], "error": "unrecognized Windows Event Log channel"}
        raw_text = read_windows_eventlog_tail(name)
        event_blocks = split_wevtutil_text_events(raw_text)
        findings = analyze_windows_event_blocks(event_blocks)
        return {"name": name, "raw_text": raw_text, "findings": findings}
    #Linux: "journalctl" is the one special, non-file id - everything
    #else is a real file path from list_linux_log_files().
    if name == "journalctl":
        lines = read_journalctl_tail()
    else:
        lines = read_tail_lines(name)
    raw_text = "".join(lines)
    findings = analyze_lines(lines)
    return {"name": name, "raw_text": raw_text, "findings": findings}


#The same severity ordering app.py's own (now-retired) _format_important_
#findings used - "high" first, then "medium", then "info" - so the new
#per-log viewer's "WORTH A LOOK" summary sorts findings exactly the same
#way the old all-logs-at-once dump always did. Kept here instead of in
#gui/log_viewer.py so it lives next to the (severity, key, message)
#tuples it actually sorts, and so a future non-GUI caller (a report, a
#CLI summary) can reuse the identical ordering without importing a GUI
#file just to get at it.
_SEVERITY_DISPLAY_ORDER = {"high": 0, "medium": 1, "info": 2}


#Define format_findings_summary, which turns the plain list of
#(severity, key, message) tuples read_log_content() above returns into
#one readable block of text for a log viewer's "WORTH A LOOK" section -
#most severe first, or a plain "nothing stood out" line instead of an
#empty, confusing section if the list is empty. Unlike app.py's old
#_format_important_findings (which this replaces for the new per-log
#viewer), the messages here are never prefixed with a source label -
#the new viewer only ever shows ONE log's findings at a time, so there
#is no second log's messages to tell these apart from.
def format_findings_summary(results):
    if not results:
        #Say so plainly - an empty section with no explanation would
        #read as a bug, not as "nothing suspicious in this log."
        return "(nothing in this log matched a known brute-force/suspicious-login pattern)"
    ordered = sorted(results, key=lambda item: _SEVERITY_DISPLAY_ORDER.get(item[0], 3))
    return "\n".join(f"[{severity.upper()}] {message}" for severity, _key, message in ordered)


#Define analyze_uploaded_text, called directly by the GUI's "Upload Log"
#button - NOT a LIVE_MODULES entry, since it has no fixed file path of
#its own to read on a schedule; it runs once, against whatever file the
#analyst just picked. Auto-detects whether the uploaded TEXT is a
#wevtutil-style Windows event export (one or more "Event[N]:" blocks) or
#an ordinary Linux-style plain-text log, and routes to whichever of this
#file's two analyzers actually applies - answering "lets you upload
#winevents as well and it analyzes those" without needing a second,
#separate upload button: the person just picks a file, and this module
#works out what it's looking at. A genuinely BINARY .evtx upload is
#handled separately, by evtx_review.py (see app.py's upload handler for
#where that split happens - this function only ever sees already-
#decoded text). filename is used only to make each finding's key unique
#to that specific upload, so analyzing two different uploaded files back
#to back never has one's findings silently suppress the other's by
#sharing a (module, key) pair.
def analyze_uploaded_text(config, log, filename, text):
    #Cap however many lines/events get analyzed, same reasoning a live
    #read is capped either way.
    capped_text = "".join(text.splitlines(keepends=True)[-MAX_LOG_LINES:])
    event_blocks = split_wevtutil_text_events(capped_text)
    if event_blocks:
        #This looks like a wevtutil text export - analyze it as Windows
        #events, not as plain log lines.
        results = analyze_windows_event_blocks(event_blocks)
        source_label = "Windows event log"
    else:
        #An ordinary Linux-style plain-text log.
        results = analyze_lines(capped_text.splitlines(keepends=True))
        source_label = "log"
    #Report every finding, keyed by the uploaded file's own name so it
    #is clearly distinguished from a live, on-machine finding.
    for severity, key, message in results:
        #Log it through the shared Log object, same as check() above.
        log.add("logs", severity, f"uploaded:{filename}:{key}", f"[uploaded {source_label}: {filename}] {message}")
    #Hand back the plain results list too, so the GUI can show an
    #immediate on-screen summary without having to re-read findings.jsonl.
    return results
