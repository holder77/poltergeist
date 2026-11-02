#DESCRIPTION: This file is the one shared list every button in the GUI is
#             built from. It holds NO logic and imports NOTHING from the
#             rest of the project on purpose - it is pure, plain data, so
#             it can be read and checked on its own without pulling in
#             psutil, Tkinter, or anything else. Each entry describes ONE
#             action a human can trigger (what to call it, which group it
#             belongs under, the plain-English tooltip that explains it,
#             and whether it needs a bit of typed input first). The GUI's
#             app.py is the only place that turns a "key" below into an
#             actual call to cli.py's run_action() - the SAME dispatcher
#             the text menu uses, so a button here and a text-menu choice
#             always do exactly the same thing. This file just says what
#             exists and how to describe it, matching the same cutesy-
#             name-plus-plain-description rule the CLI menu and
#             help_text.py's glossary already follow.
#
#             There is now only ONE target per running install - local or
#             remote, chosen in the setup wizard (see config.py's "target"
#             key and cli.py's run_wizard()) - so there is no separate
#             "Fleet" group of multi-host actions any more. Every action
#             below already knows how to run itself against whichever
#             target is currently configured; a button never needs to
#             say which machine it means, since the window's own header
#             already names it.

#Define GROUPS as an ordered list of section names, so the GUI always
#lays out buttons in the same grouped order a Poltergeist user already
#recognizes from the text menu's own four section headers, rather than
#whatever order a dict happens to iterate in.
GROUPS = [
    "Setup & Baseline",
    "Checking",
    "Active Defense",
    "Extra Tools",
]

#Define ACTIONS as the full list of button descriptions. "needs_input"
#tells app.py which themed dialog (from dialogs.py) to pop up BEFORE
#calling the action, and is None for actions that need nothing extra.
#"danger" marks every action that asks for a typed confirmation word
#rather than just a click, and should be drawn in the alarming red accent
#color - right now that is only Shield: MUTE, hard to undo blind if
#clicked by accident. (Reset Baseline used to be the other one, but it
#is no longer a button at all here - see "baseline"'s own entry just
#below for where that reset moved to.) "confirm_word" names the
#exact word that typed confirmation must match (dialogs.py shows it in
#the prompt - "Type MUTE to confirm" / "Type RESET to confirm" - rather
#than guessing or hardcoding one single word for every danger action).
#"key" matches, one-for-one, an action_key that cli.py's run_action()
#already understands, EXCEPT "dashboard_open", which is GUI-only (the
#text menu does not need a button to open a browser tab) and is handled
#directly in app.py instead of being passed through to run_action().
ACTIONS = [
    #--- Setup & Baseline ---
    #There is no standalone "Reset Baseline" button any more - direct
    #feedback asked for it to go away entirely, since the whole point of
    #this button is already covered automatically, with its own warning
    #where one is actually needed: a baseline resets itself, silently,
    #the instant a brand new instance of Poltergeist launches (see
    #gui/app.py's __init__, right where it loads an existing config), and
    #resets again, WITH a confirmation dialog first, the moment "Setup /
    #Edit Settings" is clicked (see gui/app.py's _on_setup_clicked) -
    #since re-opening Setup might mean pointing this same running
    #instance at a different host entirely, which can never be allowed
    #to leave a stale locked baseline sitting there unnoticed. Between
    #those two, there is no situation left where a PERSON manually
    #resetting a baseline by hand is still the only way to get back to
    #an unlocked state - so app.py no longer shows this key as a button
    #at all. exorcise.reset_baseline() itself (what both of the above
    #automatic resets actually call) is unchanged and still used exactly
    #as carefully as before - it still only ever MOVES the old baseline
    #into evidence/baseline_history/, never deletes it.
    {
        "key": "baseline",
        "group": "Setup & Baseline",
        "label": "Sentinel: Baseline",
        "tooltip": "Hash every startup location, local account, installed package, and protected file on the monitored machine - RIGHT NOW. Do this only once, on a box you're sure is clean. Everything after this is compared back against this exact snapshot. Locks for the rest of this running instance - closing and relaunching Poltergeist (or clicking Setup / Edit Settings) always starts the next baseline fresh automatically.",
        "needs_input": None,
        "danger": False,
        "confirm_word": None,
    },
    #--- Checking ---
    {
        "key": "scan",
        "group": "Checking",
        "label": "Scan Now",
        "tooltip": "One command, one report: the baseline diff (if you have one yet - a plain note if you don't), every live check (processes, network, logging health, Tripwire folders), and canary status, all together, right now. Nothing is changed or deleted - only looked at and reported.",
        "needs_input": None,
        "danger": False,
        "confirm_word": None,
    },
    #--- Active Defense (never kills or deletes anything) ---
    {
        "key": "canaries",
        "group": "Active Defense",
        "label": "Plant Canaries",
        "tooltip": "Drops fake 'bait' files with tempting names (like scoring_credentials.txt) into every bait location you've chosen (or just Poltergeist's own evidence folder, if you haven't chosen one yet - see \"Canary: Choose a Bait Location\"). If anyone ever opens one, you get an alert. It never locks out or punishes whoever touched it - it only tells you.",
        "needs_input": None,
        "danger": False,
        "confirm_word": None,
    },
    {
        "key": "canary_add",
        "group": "Active Defense",
        "label": "Canary: Choose a Bait Location",
        "tooltip": "Pick any ONE real folder on the monitored machine (a web root, a shared drive - wherever someone poking around would actually look) and seed it with fake bait files right now. Capped at 3 locations at once - open a separate instance if you need more. Different from Tripwire: this detects someone OPENING a fake file, not a real file CHANGING.",
        "needs_input": "folder",
        "danger": False,
        "confirm_word": None,
    },
    {
        "key": "canary_remove",
        "group": "Active Defense",
        "label": "Canary: Stop Seeding a Location",
        "tooltip": "Pick one of the location(s) Canary is currently seeding and stop watching it. The fake bait files Poltergeist planted there are cleaned up too - nothing that belongs to the monitored machine is ever touched.",
        "needs_input": "bait_folder",
        "danger": False,
        "confirm_word": None,
    },
    {
        "key": "tripwire_add",
        "group": "Active Defense",
        "label": "Tripwire: Watch a Folder",
        "tooltip": "Pick any ONE folder (a full path, on the monitored machine) and start watching it live, right now, without re-running the whole Sentinel baseline. Hashes it as-is, then flags any file added, changed, or removed in it from now on. Capped at 3 watched folders at once - open a separate instance if you need more.",
        "needs_input": "folder",
        "danger": False,
        "confirm_word": None,
    },
    {
        "key": "tripwire_remove",
        "group": "Active Defense",
        "label": "Tripwire: Stop Watching a Folder",
        "tooltip": "Pick one of the folder(s) Tripwire is currently watching and stop watching it. Its stored hashes are dropped so it is never reported as 'changed' again, but nothing about the folder itself is touched.",
        "needs_input": "watched_folder",
        "danger": False,
        "confirm_word": None,
    },
    {
        "key": "shield_rule",
        "group": "Active Defense",
        "label": "Shield: Add One Rule",
        "tooltip": "Type a plain-English rule - 'block ip 10.0.0.5' or 'block port 4444' - and it's translated to iptables/netsh for you on the monitored machine. No firewall syntax to remember.",
        "needs_input": "rule",
        "danger": False,
        "confirm_word": None,
    },
    {
        "key": "shield_mute",
        "group": "Active Defense",
        "label": "Shield: MUTE",
        "tooltip": "Drops ALL traffic on the monitored machine except your trusted IPs. This is the panic button - hard to undo blind, so it asks you to type a word first instead of just clicking a button.",
        "needs_input": "typed_confirm",
        "danger": True,
        "confirm_word": "MUTE",
    },
    #--- Extra Tools ---
    {
        "key": "oracle",
        "group": "Extra Tools",
        "label": "Oracle: Scan Services",
        "tooltip": "Checks both live service banners and every installed package's version against a small OFFLINE list of known-risky versions. This can't reach the internet mid-competition, so refresh that list beforehand.",
        "needs_input": None,
        "danger": False,
        "confirm_word": None,
    },
    {
        "key": "oracle_refresh_hints",
        "group": "Extra Tools",
        "label": "Oracle: Refresh OSINT Hints",
        "tooltip": "PRE-COMPETITION ONLY - run this on THIS machine, before the event, while you still have real internet access. Pulls the latest CISA Known Exploited Vulnerabilities list and folds it into the offline hint file 'Oracle: Scan Services' reads from. Fails gracefully (and changes nothing) if the internet isn't reachable, which is expected once a competition starts.",
        "needs_input": None,
        "danger": False,
        "confirm_word": None,
    },
    {
        "key": "snapshot",
        "group": "Extra Tools",
        "label": "Medium: Take Snapshot",
        "tooltip": "Best-effort whole-volume backup (Windows Volume Shadow Copy or Linux LVM), on top of Sentinel's regular file-by-file backups. Only works if the monitored machine actually supports it - tells you honestly if it doesn't.",
        "needs_input": None,
        "danger": False,
        "confirm_word": None,
    },
    {
        "key": "snapshot_revert",
        "group": "Extra Tools",
        "label": "Medium: Revert a Folder",
        "tooltip": "Pick ONE real folder on the monitored machine and roll it back to the last snapshot taken - this OVERWRITES whatever is in it right now, including deleting anything added since. Scoped to one folder at a time on purpose, so a bad revert can't undo more than you asked. Only works if a snapshot was already taken (see Medium: Take Snapshot) and the box genuinely supports it.",
        "needs_input": "revert_folder",
        "danger": True,
        "confirm_word": "RESTORE",
    },
    {
        "key": "scribe",
        "group": "Extra Tools",
        "label": "Scribe: Write Report",
        "tooltip": "Turns everything logged so far into one clean Markdown incident report, with every suggested command included. Ready to hand to judges. Always runs locally - a remote target's findings are already synced back here the moment any action runs against it.",
        "needs_input": None,
        "danger": False,
        "confirm_word": None,
    },
    {
        "key": "dashboard_open",
        "group": "Extra Tools",
        "label": "Open Dashboard in Browser",
        "tooltip": "This window IS the live view, but if you also want the auto-refreshing web page in a browser tab (already running in the background on this machine only), this opens it.",
        "needs_input": None,
        "danger": False,
        "confirm_word": None,
    },
    #"view_logs" and "upload_log" are BOTH GUI-only, same reason
    #"dashboard_open" is: neither one is a thing cli.py's run_action()
    #needs to know how to do for the text menu or a remote target - see
    #app.py's own _on_action_click for how each is actually handled.
    #"view_logs" shows the raw tail of the monitored machine's own real
    #logs, right here in the window - the literal "look through logs of
    #current machine... not just auth.log but also syslog I mean
    #everything and if its a windows enviroment it goes to winevents"
    #ask. On Linux this means every known/discovered log file under
    #/var/log (with a journalctl fallback on journald-only distros); on
    #Windows this means a LIVE read of the Security/System/Application
    #Event Log channels via wevtutil. Local target only for now (see its
    #own handler's comment for why); a remote target's brute-force
    #findings still show up on the Dashboard either way, via
    #modules/log_review.py's own LIVE_MODULES entry, which runs on
    #whichever machine quickscan itself runs on.
    {
        "key": "view_logs",
        "group": "Extra Tools",
        "label": "View System Logs",
        "tooltip": "Shows the raw tail of the monitored machine's own logs, right here - on Linux, every log file found under /var/log (syslog, kernel, cron, package manager, and more - not just the auth log); on Windows, a live read of the Security/System/Application Event Log channels. Local target only for now - a remote target's brute-force findings still show up on the Dashboard, this is just the raw log text itself.",
        "needs_input": None,
        "danger": False,
        "confirm_word": None,
    },
    {
        "key": "upload_log",
        "group": "Extra Tools",
        "label": "Upload Log to Analyze",
        "tooltip": "Pick any log file from YOUR OWN machine (pulled off a box, handed over by a teammate, whatever) - a plain Linux-style log, a Windows Event Log text export (wevtutil '/f:text' or PowerShell), or a genuine binary Windows .evtx file - and run the same brute-force / successful-login-after-brute-force check against it (the binary .evtx case gets a more basic structural read instead - see its own results for why). Logged as its own finding either way.",
        "needs_input": None,
        "danger": False,
        "confirm_word": None,
    },
    #"upload_pcap" is GUI-only, same reason the two above are: there is
    #no fixed capture file for this to re-run on a schedule. This is the
    #"upload... pcaps to analyze" half of the original ask, answered
    #with a basic flow summary (who talked to whom, on what port, how
    #much) plus two basic heuristics - see modules/pcap_review.py's own
    #top comment for exactly why this stays "basic" on purpose (pure
    #Python, no tshark/scapy dependency).
    {
        "key": "upload_pcap",
        "group": "Extra Tools",
        "label": "Upload PCAP to Analyze",
        "tooltip": "Pick a packet capture (.pcap) file from YOUR OWN machine and get a basic flow summary - who talked to whom, on what port, how much data - plus a flag for well-known suspicious ports and port-scan-shaped traffic. Classic .pcap only (not the newer .pcapng format). Logged as its own finding either way.",
        "needs_input": None,
        "danger": False,
        "confirm_word": None,
    },
]


#Define get_actions_by_group, a tiny helper the GUI panel uses so it never
#has to filter the list itself or hardcode the group order a second time.
def get_actions_by_group():
    #Build one dict of {group_name: [action, action, ...]}, in GROUPS order.
    grouped = {group_name: [] for group_name in GROUPS}
    #Loop over every action in the fixed list above.
    for action in ACTIONS:
        #File it under its own group. A typo'd group name here would raise
        #a KeyError immediately rather than silently vanish, which is
        #exactly what we want while this file is still being edited.
        grouped[action["group"]].append(action)
    #Hand back the grouped dictionary.
    return grouped


#Define get_action, a tiny lookup helper so app.py can find one action's
#metadata by its key without writing its own search loop.
def get_action(key):
    #Loop over every action looking for a matching key.
    for action in ACTIONS:
        #Return the first (and only, since keys are meant to be unique) match.
        if action["key"] == key:
            #Hand back this one action's full metadata dictionary.
            return action
    #If nothing matched, say so clearly instead of returning None and
    #letting a typo'd key fail mysteriously somewhere else later.
    raise KeyError(f"No menu action with key '{key}'")
