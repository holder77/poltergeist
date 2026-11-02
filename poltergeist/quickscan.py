#DESCRIPTION: This file is "Quick Scan" - the answer to "can I just run
#             ONE command and get a single readable report, right now?"
#             This is the canonical full-scan implementation: everything
#             the main GUI view and --check/--quickscan print is built by
#             looping over LIVE_MODULES (processes, network, logging,
#             tripwire) generically instead of hardcoding each one, then
#             adding a baseline diff (only if a baseline actually exists)
#             and a canary/Haunting check, plus one section this file adds
#             on its own: a plain listing of SSH key files for the human
#             to eyeball, since judging whether a specific key belongs is
#             a call only a person on the team can make. do_check() in
#             cli.py is now a thin wrapper that just calls run() below, so
#             there is exactly one "run everything, once" implementation
#             instead of two that could quietly drift apart. Every finding
#             here still goes through the normal Log object, so it is
#             saved to findings.jsonl and shows up in the Scribe's report
#             and the Dashboard exactly like any other check - Quick Scan
#             is a VIEW, not a separate system.

#import os so we can list SSH directories, read file permissions, and
#check whether a baseline/canary manifest exists.
import os

#import platform so the SSH-directory section only runs where it applies.
import platform

#import the colorize helper so section headers stand out the same way
#severity labels do elsewhere in the tool.
from .color import colorize

#import LIVE_MODULES so this file loops over every live check generically
#instead of importing and calling each one by name - add a new live module
#to modules/__init__.py and it automatically shows up here too.
from .modules import LIVE_MODULES

#import the deception module directly (not through LIVE_MODULES) for the
#same reason cli.py always has: planting canaries is a deliberate, opt-in
#action, but CHECKING any already-planted ones is something every scan
#should do automatically.
from .modules import deception

#import discovery so we can list currently listening ports directly.
from .discovery import find_listening_ports

#import the sha256_of helper so SSH keys are hashed the same way every
#other file in this project is hashed.
from .evidence import sha256_of

#import EVASIVE_CONTENT_PATTERNS from persistence.py - the exact same
#short, explainable list of dropper/reverse-shell idioms its own
#evasive-persistence check uses (see that module's own comment on it for
#the full reasoning). list_ssh_keys() below reuses it to check whatever
#fixed command an authorized_keys entry restricts itself to running,
#since a key that is only good for running "curl ... | bash" the moment
#it logs in is a backdoor, not an access credential.
from .modules.persistence import EVASIVE_CONTENT_PATTERNS

#import run_exorcise so Quick Scan can fold in a baseline diff exactly
#like "poltergeist exorcise" does - it already prints a clear "no
#baseline yet" message on its own when one does not exist, so this file
#never needs to check for that itself.
from .exorcise import run_exorcise

#Store whether we are on Windows once for the whole file to reuse.
IS_WINDOWS = platform.system() == "Windows"

#Define WINDOWS_USERS_DIR and WINDOWS_ADMIN_AUTHORIZED_KEYS_PATH as their
#own module-level constants (rather than literals buried inside
#list_ssh_keys() below), the same reason persistence.py's own
#SYSTEMD_UNIT_DIRECTORY is one: so a test can monkeypatch either one to
#point at an isolated scratch folder instead of a real machine's actual
#C:\Users or C:\ProgramData\ssh.
WINDOWS_USERS_DIR = r"C:\Users"
WINDOWS_ADMIN_AUTHORIZED_KEYS_PATH = r"C:\ProgramData\ssh\administrators_authorized_keys"

#Define the human-readable section title for each LIVE_MODULES key, so
#the loop in run() below can print a proper heading for whichever live
#modules happen to be registered, instead of a bare module name. A module
#with no entry here just gets its own key as a plain fallback title.
LIVE_MODULE_TITLES = {
    "processes": "PROCESS CHECKS (writable-dir binaries, deleted exes, shells spawned by servers)",
    "network": "NETWORK CONNECTIONS (outside your configured trusted ranges)",
    "logging": "LOGGING HEALTH (log purging / tampering detection)",
    "tripwire": "TRIPWIRE (folders you're watching live, outside any full baseline)",
    "persistence": "EVASIVE PERSISTENCE CHECK (hidden files + dropper/reverse-shell content, no baseline needed)",
    "logs": "LOG ANALYSIS (brute-force / successful-login-after-brute-force detection in the auth log)",
}


#Define print_header, a tiny helper so every section of the scan prints
#its title the exact same way.
def print_header(title):
    #Print a blank line, then the colorized, bracketed section title.
    print(f"\n{colorize(f'=== {title} ===', 'header')}")


#Define KNOWN_SSH_KEY_TYPE_PREFIXES: the fixed set of key-type tokens a
#real OpenSSH public key or authorized_keys line can start with - this is
#deliberately an allowlist of REAL protocol identifiers (every one
#OpenSSH itself understands and prints via ssh-keygen), not a guess, so
#parse_public_key_line() below can reliably tell "this token IS the key
#type" apart from anything else that might precede it on the same line
#(an authorized_keys entry's own comma-separated options, for instance).
KNOWN_SSH_KEY_TYPE_PREFIXES = (
    "ssh-rsa", "ssh-dss", "ssh-ed25519",
    "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com",
)


#Define parse_public_key_line, which pulls the key TYPE (ssh-rsa,
#ssh-ed25519, ...) and trailing COMMENT (almost always "user@host", but
#it is free text OpenSSH never validates - which is exactly why it is
#worth showing: "root@attackbox" or "pwned" as a key's own comment is a
#real tell) out of one line of a .pub file or an authorized_keys/
#administrators_authorized_keys file - all three share the exact same
#"[options] key-type base64-blob [comment]" shape, so one parser covers
#every case this file needs it for. Returns None for a blank line, a
#"#"-comment line, or any line this tool cannot confidently recognize
#the shape of (an authorized_keys options list can itself contain
#commas, quotes, and spaces inside a quoted command="...", so this
#deliberately never tries to parse those options' own structure - it
#only needs to find where the key-type token itself starts, which skips
#straight past any leading options with no risk of misreading them).
def parse_public_key_line(line):
    #Strip surrounding whitespace once, up front.
    stripped = line.strip()
    #A blank line or a full-line comment carries no key to report on.
    if not stripped or stripped.startswith("#"):
        #Nothing to parse.
        return None
    #Split on whitespace - the key type and its base64 blob are always
    #separate whitespace-delimited tokens, whatever comes before them.
    tokens = stripped.split()
    #Walk the tokens looking for the FIRST one that is itself a real,
    #known key-type identifier - this correctly skips past any leading
    #authorized_keys options (command="...",no-agent-forwarding, etc.)
    #without ever needing to parse those options' own internal commas
    #and quotes, since none of them can ever collide with a real key-
    #type name.
    key_type_index = next((i for i, token in enumerate(tokens) if token in KNOWN_SSH_KEY_TYPE_PREFIXES), None)
    #No recognizable key type found at all - not a line this tool can
    #confidently say anything about (a key type newer than this
    #allowlist, a malformed line, or something else entirely).
    if key_type_index is None:
        #Nothing usable to report.
        return None
    #The base64 blob is always the very next token after the key type;
    #without one, this is not a real key line even though its own type
    #token happened to match.
    if key_type_index + 1 >= len(tokens):
        #Nothing usable to report.
        return None
    #Everything AFTER the blob (if anything at all) is the comment -
    #normally one "user@host" token, but OpenSSH never validates its
    #contents, so every remaining token is rejoined verbatim rather than
    #assuming there is ever exactly one.
    comment = " ".join(tokens[key_type_index + 2:])
    #Hand back both pieces this function promises.
    return {"key_type": tokens[key_type_index], "comment": comment}


#Define process_ssh_file, the per-file logic list_ssh_keys() below runs
#against every SSH-related file it finds, on EITHER operating system -
#pulled out into its own function specifically so the one Windows-only
#extra file (administrators_authorized_keys, see list_ssh_keys()'s own
#comment on it) can be run through the exact same checks as every file
#found inside an ordinary per-user .ssh folder, with no duplicated logic.
#Reports its size, permissions, and hash so a human can quickly eyeball
#whether an unfamiliar key has been added, PLUS three concrete judgment
#calls this file is confident enough to make on its own, directly
#answering "help identify bad keys": (1) a key file readable or writable
#by anyone other than its owner is itself a real finding, not just a
#detail to note, since a private key with loose permissions can be read
#(or swapped) by any other account on the box; (2) for a PUBLIC key file
#(a .pub file, or one line of authorized_keys/administrators_authorized_
#keys), the key's own TYPE and COMMENT are pulled out and shown directly
#- the "richer info" this whole function exists for, since a comment of
#"unknown@kali" or a key type that does not match what the rest of a
#team actually uses is itself worth a human's attention, not just an
#opaque hash to compare by eye; (3) an authorized_keys-style entry that
#restricts itself to running one fixed command (the standard
#command="..." OpenSSH restriction) gets that command checked against
#the same dropper/reverse-shell idioms persistence.py's evasive check
#uses - a key that is ONLY good for running "curl ... | bash" the moment
#it's used to log in is a backdoor, not an access credential. Beyond
#these three checks, this still does not try to judge whether a key
#ITSELF (its bits) is good or bad - that call needs a person who knows
#which keys are supposed to be there.
def process_ssh_file(file_path, log):
    #Work out this file's own bare name, used below to decide which of
    #the extra, file-specific checks apply.
    file_name = os.path.basename(file_path)
    #Read the file's permission bits and size.
    try:
        file_stat = os.stat(file_path)
    #The file could have vanished mid-scan, or be unreadable for some
    #other reason - either way, nothing more can be said about it.
    except Exception:
        #Nothing more to do for this one file.
        return
    #Format the permission bits the familiar "rwx" way.
    permissions = oct(file_stat.st_mode)[-3:]
    #For a .pub file specifically, try to pull its own key type/comment
    #out right now, so both the printed line and the logged finding show
    #something like "ed25519 key, comment 'root@laptop'" instead of just
    #a bare hash - judgment call #2 above. A .pub file is always exactly
    #one line, unlike authorized_keys/administrators_authorized_keys
    #(which can hold several different keys and get their own, separate
    #per-line enrichment further down) or a private key file (id_rsa,
    #id_ed25519, with no ".pub" - never in this one-line public-key
    #format at all, so there would be nothing for this parser to find).
    key_info_suffix = ""
    if file_name.endswith(".pub"):
        #Wrap the read so a permission problem or a genuinely empty file
        #never crashes the scan over one key file.
        try:
            with open(file_path, "r", errors="replace") as pub_file:
                #A real .pub file is always exactly one line.
                parsed = parse_public_key_line(pub_file.readline())
        except Exception:
            #Could not read it - nothing more to add here.
            parsed = None
        if parsed:
            #Build the extra text appended to both the printed line and
            #the logged finding's own message below.
            comment_text = f", comment '{parsed['comment']}'" if parsed["comment"] else ", no comment"
            key_info_suffix = f", {parsed['key_type']} key{comment_text}"
    #Print one readable line per key-related file for the human to
    #review, now including the key-type/comment suffix when there is one.
    print(f"  {file_path}  (mode {permissions}, {file_stat.st_size} bytes, "
          f"sha256 {sha256_of(file_path)[:16]}...{key_info_suffix})")
    #Also log it at informational severity so it is captured in the
    #incident report and Dashboard history, not just printed.
    log.add("quickscan", "info", f"sshkey:{file_path}",
            f"SSH file present: {file_path} (mode {permissions}{key_info_suffix})", quiet_dupes=False)

    #Judgment call #1: is this file readable or writable by anyone
    #other than its owner? st_mode's low 6 bits are the group and other
    #permission bits (rw for either is enough to matter, even without
    #execute) - a private key any other local account can read is
    #effectively not private any more, and one any other account can
    #WRITE could be swapped out for an attacker's own key without the
    #real owner ever noticing. Checked for every file here, not just
    #obvious private keys, since a misconfigured authorized_keys or
    #known_hosts file is its own real exposure too. (Windows' own
    #permission model is ACL-based, not these Unix mode bits, so this
    #specific check is a no-op there in practice - st_mode on Windows
    #is a Python-synthesized approximation that is almost always 0o666/
    #0o444 regardless of the file's real ACLs, so it would otherwise
    #either always or never fire; richer ACL-aware checking is future
    #work, not something to fake confidence about here.)
    if not IS_WINDOWS and file_stat.st_mode & 0o077:
        #Report it - the key itself may be perfectly fine, but its
        #permissions are not, so this is still worth a human's
        #attention, same bar as the hidden-file check in persistence.py's
        #own evasive-persistence heuristic.
        log.add("quickscan", "medium", f"sshkey_perm:{file_path}",
                f"{file_path} is readable/writable by more than its owner (mode {permissions}) "
                "- tighten with: chmod 600 " + file_path, quiet_dupes=False)

    #Judgment calls #2 (per-entry) and #3: for authorized_keys, OR
    #Windows OpenSSH Server's own separate administrators_authorized_
    #keys file (see list_ssh_keys()'s own comment on where that lives) -
    #both share the exact same per-line format, one key per line, with
    #the same optional "command=" restriction syntax - check every entry
    #for its own key type/comment, AND whether it restricts itself to a
    #fixed command that looks like one of the same dropper/reverse-shell
    #idioms persistence.py's own evasive check flags (see this file's
    #own module-level import comment for why that specific reuse makes
    #sense here).
    if file_name in ("authorized_keys", "administrators_authorized_keys"):
        #Read the file as plain text; this is always a small, line-
        #oriented text file, so there is no need for the cap/binary-
        #tolerant approach persistence.py uses for arbitrary startup-file
        #content.
        try:
            with open(file_path, "r", errors="replace") as keys_file:
                key_lines = keys_file.readlines()
        except Exception:
            #Could not read it for some reason - nothing more to check
            #for this one file.
            key_lines = []
        #Check each line (each one is normally one key) on its own.
        for line_number, line in enumerate(key_lines, start=1):
            #Judgment call #2, per-entry: report THIS line's own key
            #type/comment, regardless of whether it also turns out to be
            #restricted below - seeing what KIND of key was added and
            #whose it claims to be matters for every single entry here,
            #not just a restricted one.
            parsed = parse_public_key_line(line)
            if parsed:
                comment_text = f", comment '{parsed['comment']}'" if parsed["comment"] else ", no comment"
                log.add("quickscan", "info", f"sshkey_entry:{file_path}:{line_number}",
                        f"{file_path} line {line_number}: {parsed['key_type']} key{comment_text}",
                        quiet_dupes=False)
            #A restricted key's line starts with command="...",
            #optionally alongside other comma-separated options - look
            #for that fixed command substring specifically, not the
            #whole line, since the key material itself will also contain
            #plenty of base64-looking text that must never be matched
            #against these patterns.
            if 'command="' not in line:
                #An ordinary, unrestricted key - nothing more to judge
                #on this one line.
                continue
            #Pull out just the command="..." portion to search within,
            #not the rest of the line (the key's own base64 blob could
            #otherwise coincidentally contain one of these substrings).
            command_start = line.index('command="') + len('command="')
            restricted_command = line[command_start:line.find('"', command_start)]
            #Check that one restricted command against the same short
            #pattern list persistence.py's own check uses.
            for pattern, description in EVASIVE_CONTENT_PATTERNS:
                if pattern in restricted_command:
                    #Report it at high severity - a restricted key that
                    #can ONLY run a dropper/reverse-shell command is a
                    #backdoor by design, not an access credential with a
                    #quirky restriction.
                    log.add("quickscan", "high", f"sshkey_cmd:{file_path}:{line_number}",
                            f"{file_path} line {line_number}: a key is restricted to a command "
                            f"that {description} - {restricted_command.strip()[:120]}", quiet_dupes=False)
                    #One matching pattern is enough to flag this line;
                    #move on to the next line rather than reporting the
                    #same command multiple times for each pattern it
                    #happens to also match.
                    break


#Define list_ssh_keys, which finds every SSH key-related file under the
#usual locations on EITHER operating system and runs each one through
#process_ssh_file() above. Linux/macOS checks every real home directory's
#own ~/.ssh folder (plus root's); Windows checks every real user
#profile's own \.ssh folder the exact same way (Win32-OpenSSH, whether
#installed as the built-in optional feature or a separate client, uses
#this identical per-user layout - C:\Users\<name>\.ssh\id_rsa, .pub,
#authorized_keys, known_hosts, config - so almost all of this logic
#needs no OS branching at all), PLUS one Windows-only extra file outside
#any per-user folder: the OpenSSH SERVER feature's own
#C:\ProgramData\ssh\administrators_authorized_keys, which is specifically
#where an ADMINISTRATOR account's authorized keys are checked instead of
#(not in addition to) that account's own per-user authorized_keys file -
#a real, documented Win32-OpenSSH quirk, and exactly the kind of place a
#planted backdoor key would hide precisely because it is easy to forget
#to check.
def list_ssh_keys(config, log):
    #Build the list of home/profile directories to check - Windows user
    #profiles under C:\Users, or Linux/macOS home directories under
    #/home plus root's own.
    if IS_WINDOWS:
        #List every real user profile folder under C:\Users. A missing
        #or inaccessible C:\Users (should not happen on real Windows, but
        #this should never crash the scan either way) just means there
        #is nothing to check here.
        home_dirs = ([os.path.join(WINDOWS_USERS_DIR, name) for name in os.listdir(WINDOWS_USERS_DIR)]
                     if os.path.isdir(WINDOWS_USERS_DIR) else [])
    else:
        #Build the list of home directories to check, including root's.
        home_dirs = ["/root"] + [os.path.join("/home", name) for name in os.listdir("/home")] if os.path.isdir("/home") else ["/root"]
    #Loop over every home/profile directory we are going to check.
    for home_dir in home_dirs:
        #Build the path to this user's .ssh folder.
        ssh_dir = os.path.join(home_dir, ".ssh")
        #Skip any home directory that has no .ssh folder at all.
        if not os.path.isdir(ssh_dir):
            #Move on to the next home directory.
            continue
        #Loop over every file actually sitting in this .ssh folder.
        for file_name in os.listdir(ssh_dir):
            #Build the full path to this one file.
            file_path = os.path.join(ssh_dir, file_name)
            #Only look at regular files, not subfolders.
            if not os.path.isfile(file_path):
                #Move on to the next file in this folder.
                continue
            #Run this one file through every check above.
            process_ssh_file(file_path, log)
    #Windows-only: the OpenSSH SERVER's own separate server-wide file for
    #ADMINISTRATOR accounts specifically - see this function's own
    #top comment for why this lives outside any per-user .ssh folder and
    #is easy to forget to check.
    if IS_WINDOWS:
        #Most Windows boxes do not run the OpenSSH Server feature at
        #all, so this file simply not existing is completely normal.
        if os.path.isfile(WINDOWS_ADMIN_AUTHORIZED_KEYS_PATH):
            #Run it through the exact same checks as any other
            #authorized_keys-style file.
            process_ssh_file(WINDOWS_ADMIN_AUTHORIZED_KEYS_PATH, log)


#Define run, the single "run everything, once" function every front end
#now calls: the GUI's automatic periodic scan and its "Scan Now" button,
#the text menu's "Scan now" item, and the --check/--quickscan flags.
def run(config, log):
    #Print the top banner for the whole scan.
    print(colorize("\n=== POLTERGEIST QUICK SCAN ===", "header"))
    #Section 1: what is listening right now, plain and simple.
    print_header("OPEN LISTENING PORTS")
    #Get the current list of listening ports and print each one. ALSO log
    #each one as its own quiet info finding (quiet_dupes so an unchanged
    #port does not spam the console every scan the way a real "new"
    #finding would) - this is new specifically so the GUI Dashboard's
    #"live ports" row has something to read for a REMOTE target. Before
    #this, the Dashboard called straight into discovery.py's own
    #find_listening_ports() itself, which - running inside the GUI's own
    #local process - always showed the OPERATOR's own machine's ports,
    #never the actual remote target's, on a remote target (this machine
    #runs quickscan.py, the thing that calls find_listening_ports()
    #correctly for whichever box it is actually running ON). Logging it
    #here means pull_evidence() carries it back for the Dashboard to read
    #from findings.jsonl instead, same as everything else it shows.
    for entry in find_listening_ports():
        #Print "port/proc" on its own line.
        print(f"  tcp  {entry['port']:<6} {entry['proc']}")
        #Also record it so the Dashboard (local OR remote target) always
        #has a recent, correct-machine copy to read back.
        log.add("quickscan", "info", f"port:{entry['port']}", f"tcp {entry['port']}  {entry['proc']}", quiet_dupes=True)

    #Section 2: a baseline diff, but ONLY if a baseline actually exists -
    #this is what surfaces Sentinel's "NEW/REMOVED/CHANGED since baseline"
    #findings right here in the main feed, same as every other section,
    #instead of needing a separate menu item to see them.
    print_header("BASELINE DIFF (persistence, users, file integrity, packages)")
    #run_exorcise already prints its own clear message when no baseline
    #has been taken yet, so there is nothing extra to handle here.
    run_exorcise(config, log)

    #Section 3 onward: every registered live module, in whatever order
    #modules/__init__.py's LIVE_MODULES dictionary lists them - this is
    #what automatically picks up Tripwire folders too, with no special
    #case needed here for it.
    for module_name, check_function in LIVE_MODULES.items():
        #Look up this module's section title, falling back to its bare
        #key if no nicer title has been written for it yet.
        print_header(LIVE_MODULE_TITLES.get(module_name, module_name.upper()))
        #This call both prints AND logs through the shared Log object.
        check_function(config, log)

    #Section: Haunting's canary files, if any have ever been planted.
    print_header("HAUNTING: CANARY FILES (bait files that alert if opened)")
    #Work out whether any canaries have ever actually been planted, so we
    #can say so plainly instead of printing a header over total silence.
    canary_manifest = os.path.join(config["evidence_dir"], "canaries", "manifest.txt")
    if os.path.exists(canary_manifest):
        #Check every planted canary; this prints/logs only if one was touched.
        deception.check(config, log)
    else:
        #Say so plainly rather than leave the section looking broken.
        print("  (none planted yet - see Plant Canaries)")

    #Last section: SSH key files, for manual human review.
    print_header("SSH KEY FILES (for manual review - this tool does not judge which keys belong)")
    #Run the SSH listing helper defined above.
    list_ssh_keys(config, log)

    #Close with a one-line reminder of where to go for more detail.
    print(colorize("\n=== END QUICK SCAN === (see 'Recent findings' or the Dashboard for full detail)", "header"))
