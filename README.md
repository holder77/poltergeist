# Poltergeist

A modular, cross-platform (Windows + Linux) blue team audit tool for
defense competitions. Each install watches exactly ONE target — either
the machine it's running on, or a single other machine reached over SSH
(any auth you'd use by hand: your SSH agent/default key, a specific key
file with its own passphrase, or plain username+password) — chosen in a
setup wizard that runs fresh on **every** launch. It is not tied to any
one competition's network: that wizard probes the actual target (locally,
or remotely over the same SSH connection) and suggests real networks, VPN
ranges, and ports as defaults, which you confirm or edit, rather than
asking you to type them from memory.

**Core rule: evidence is never deleted, and nothing acts on its own.**
Flagged processes get a full JSON snapshot and a copy of their binary.
Tampered files are always quarantined (copied) *before* anything restores
them. Every finding that's safe to act on comes with a **suggested**
command — a way to pause or block something without destroying it —
which the tool prints and a human decides whether to run. Nothing in
Poltergeist kills a process, deletes a file, or runs a suggested command
by itself.

It launches as a **strict black-and-white gothic desktop GUI** by
default — click through the setup wizard instead of typing at prompts,
press a button instead of remembering a menu number, hover anything for
a plain-English explainer, and watch the one window keep itself
continuously, ambiently refreshed — no separate "start monitoring" click
needed, it's always scanning on a timer in the background. Everything
still also runs as a plain text menu (`--text`) for headless boxes, SSH
sessions, or anyone who just prefers it — same features, same findings,
same files, just buttons vs. typed numbers. Once a baseline is taken it
**locks** — neither front end will silently retake it; you have to type
`RESET` first, so a baseline can never be accidentally overwritten
mid-competition.

## Quick start

Poltergeist **requires** root/Administrator — almost every module (open
ports, running processes, protected log files, the firewall...) sees far
less, or nothing at all, without it, so it now refuses to even start
without elevated rights (a popup on the GUI, a plain message in the text
menu) rather than silently running half-blind. See
[Running elevated](#running-elevated) below for the easiest way to launch
it on each OS, including a packaged Windows `.exe` and a Linux desktop
shortcut, both of which prompt for elevation automatically.

```bash
git clone <this repo>
cd poltergeist
pip install -r requirements.txt

# run directly, no install needed:
sudo python3 poltergeist.py        # Linux (needs root)
python poltergeist.py              # Windows (needs to be run elevated - see below)

# or install it as a real command:
pip install -e .
sudo poltergeist
```

This launches the GUI by default. It's built on Tkinter (Python's
standard GUI library), not a new dependency — but Tkinter itself isn't
always *in the box*:

- **Windows:** already there. The python.org installer bundles it, so
  nothing extra to do.
- **Linux:** usually a separate OS package, not a `pip install`. Grab it
  before first run:
  ```bash
  sudo apt install python3-tk        # Debian/Ubuntu
  sudo dnf install python3-tkinter   # Fedora/RHEL
  sudo pacman -S tk                  # Arch
  ```

If Tkinter isn't there, Poltergeist doesn't crash — it prints one clear
line saying so and drops straight into the text menu instead. Prefer
that menu anyway, or you're on a headless/SSH box? Add `--text` and skip
the GUI on purpose.

## Running elevated

Poltergeist needs root/Administrator to see anything real, and now
**refuses to start without it** — a popup if it was headed for the GUI,
a plain message if not — rather than silently running for ten minutes
with every section empty. `--version`/`--discover-json`/`--glossary`
and the few other pure, config-free utility flags are the one exception
and work either way, since they don't touch anything privileged.

**Windows — a packaged, self-elevating `.exe`:** build it once (on a
Windows machine — see below), then just use the file:

```
packaging\windows\build_exe.bat
```

This produces a single `dist\Poltergeist.exe`. Launching it **any** way
— a plain double-click, a desktop shortcut, or right-click → *Run as
administrator* — triggers Windows' own UAC prompt automatically, because
the `.exe` has a `requireAdministrator` manifest built right in; you
don't actually have to remember to right-click it, though doing so works
identically. `build_exe.bat` needs Python 3.8+ already installed and
handles the rest itself (installing PyInstaller, rendering the `.exe`'s
own ghost-mascot file icon, then the actual build) — see
`packaging/windows/` for exactly how, including the manifest's own text
explaining why `requireAdministrator` (not `highestAvailable`) was
chosen. **Important:** a real Windows `.exe` can only be built *on*
Windows — PyInstaller bundles whatever OS it's actually run on, it
doesn't cross-compile, so this can't be done from this Linux dev
environment; the `.spec`/manifest/icon-generator are all written and
checked for correctness here, but the actual build has not been run for
real — try it on a real Windows box before relying on it.

**Linux — a one-time shortcut install:**

```bash
bash packaging/linux/install_linux_shortcut.sh
```

Adds a normal clickable "Poltergeist" entry to your application
menu/launcher that asks for your password through the same native
PolicyKit dialog your desktop environment already uses for its own admin
prompts (via `pkexec`), then starts Poltergeist already running as root —
the closest real Linux equivalent to Windows' right-click → *Run as
administrator*, since there's no one universal "run as root" checkbox in
a Linux file manager the way there is in Windows Explorer. If `pkexec`
isn't available (a minimal/server install with no desktop environment),
the script says so and leaves the plain terminal command as the
fallback:

```bash
sudo python3 poltergeist.py
```

First run launches the setup wizard automatically, as a series of
clickable pages in the GUI — no typing except where a value genuinely
needs it (a folder path, a custom rule). Every question shows a default
pulled from probing your actual machine (and tailored to the machine's
*role* — web server, DB, Domain Controller — once you pick one); accept
it or change it, then click Next. Under `--text`, it's the same wizard
as a CLI walkthrough instead — type an answer or press Enter to accept
the default.

The **Dashboard still auto-starts in the background the moment the GUI
(or text menu) comes up** (right after your settings load) — its link
is printed to the console immediately, so there's always a live,
browser-readable view of what's been found, whether or not you're
looking at the GUI window itself.

## Everything it does

Every row below is a button with a hover tooltip in the GUI, and the
same-numbered item in the text menu (`--text`) — same feature, same
findings either way.

| Menu item | Plain description |
|---|---|
| Setup wizard | Runs on **every launch**. Asks which machine to watch (this one, or one other machine over SSH), probes that actual target, and asks a few questions — including what *kind* of machine it is — to tailor its suggestions. Every answer defaults to whatever was already saved, so re-confirming an unchanged setup is just pressing Enter/Next through everything. |
| Sentinel: baseline | Hashes every startup location, local account, installed package version, and the files you listed as critical — do this ONCE, on a box you're sure is clean. **Locks** the instant it succeeds — see "Reset baseline" below. |
| Reset baseline | Only shown/numbered once a baseline is actually locked in (this is the SAME slot Sentinel: baseline uses — it flips between the two). Clears the lock so a fresh baseline can be taken; the old one is **moved**, never deleted, to `evidence/baseline_history/`. Asks you to type `RESET` first. |
| Sentinel: monitor / one-shot check | Diffs the current state against the baseline (if any yet), and runs every live check (processes, network, logging health, evasive persistence, Tripwire folders, log brute-force detection). In the GUI, the main window does this **continuously and automatically** on a timer, feeding the Dashboard below — there is no separate start/stop button to remember. Under `--text`/`--monitor`, it's the same repeating loop, Ctrl+C to stop. |
| Quick Scan | One command, one report: processes, network, logging health, evasive persistence, log brute-force detection, and SSH key files (now including loose-permission and malicious-restricted-command checks), all printed together right now — no baseline required, good for a fast first look |
| Haunting: canaries | Drops fake bait files (honeytokens); alerts if one is ever opened — never kills or locks anyone out |
| Tripwire | Start watching any ONE folder on the fly, mid-competition, without re-running the whole Sentinel baseline — hashes it now, flags any add/change/removal from then on. In the GUI, on a local target, pick the folder with a native folder-browse dialog instead of typing a path by hand. |
| Shield: add one rule | Type `block ip 10.0.0.5` or `block port 4444` in plain English — translated to `iptables`/`netsh` for you |
| Shield: MUTE | Drops all traffic except your trusted IPs — asks you to type `MUTE` to confirm first |
| Oracle | Checks both live service banners (like `nmap -sV`) *and* every installed package's version against a small **offline** CVE hint list you keep updated — this can't reach the internet during a competition |
| Medium: snapshot | Best-effort whole-volume backup via VSS (Windows) or LVM (Linux), if the box actually supports it — tells you honestly if it doesn't |
| Scribe | Turns everything already logged into one clean Markdown incident report, with every finding's suggested command included |
| View System Logs *(GUI, local target)* | Shows the monitored machine's own real logs, tailed live, right in the window — no separate terminal or `tail -f`/Event Viewer needed. On Linux: every log file actually found under `/var/log` (`auth.log`/`secure`, `syslog`/`messages`, kernel, cron, package-manager logs, and more — not just the auth log), with a `journalctl` fallback on journald-only distros with no flat log file. On Windows: a live read of the Security/System/Application Event Log channels via `wevtutil`. |
| Upload Log to Analyze *(GUI)* | Pick any log file off your OWN machine (pulled off a box, handed over by a teammate) with a native file picker, and run the same brute-force / successful-login-after-brute-force check against it — works on a plain Linux-style log, a Windows Event Log text export (`wevtutil`'s own `/f:text`, or PowerShell), or a genuine binary `.evtx` file (gets a more basic structural read — record count, time range, readable text found inside — since decoding the binary event format itself isn't attempted). Logged as its own finding either way. |
| Upload PCAP to Analyze *(GUI)* | Pick a packet capture (classic `.pcap`, not `.pcapng`) and get a basic flow summary — who talked to whom, on what port, how much data — plus a flag for well-known suspicious ports and port-scan-shaped traffic. Pure Python, no `tshark`/`scapy` needed. |
| Dashboard | A live, auto-refreshing findings page at `http://127.0.0.1:8765` — bound to this machine only, never reachable from the network. **Starts automatically** the moment the menu loads; this item just reprints the link, or starts it manually if the auto-start couldn't bind the port. (This is the full chronological history — see "The GUI" below for the GUI's own main-screen Dashboard, which shows only current state.) |
| Help | Prints a plain-English paragraph for every cutesy name above (Sentinel, Oracle, Tripwire, etc) |

In the text menu, output is color-coded by severity (red/yellow/cyan)
wherever your terminal supports it, and respects `NO_COLOR` if you don't
want that; the GUI's findings table uses the same severity colors against
its own dark theme instead. Every one of these is also available as a
command-line flag for scripting — run `python3 poltergeist.py --help` for
the full list (`--baseline`, `--baseline-reset RESET`, `--check`,
`--monitor`, `--interval <seconds>`, `--quickscan`, `--watch <folder>`,
`--shield "<rule>"`, `--oracle`, `--snapshot`, `--report`, `--dashboard`,
`--discover-json`, `--glossary`, `--wizard`, `--gui`, `--text`). Any of
these action flags runs that one action and exits — none of them ever
launches the GUI, so they're safe to script or cron exactly as before;
`--gui`/`--text` only matter when you launch with no action flag at all,
deciding which front end the wizard/menu opens in. A scripted/headless
call with an action flag does **not** force the wizard on every run the
way an interactive launch does — it loads whatever target is already
saved and only runs the wizard if nothing has ever been configured, or
`--wizard` was explicitly passed.

## The GUI

The GUI is the default front end: a single strict black-and-white
window, no browser tab needed (though the full-history web Dashboard is
still there too — see below). It uses plain grayscale throughout, down
to the one destructive-action button style, which is shown in
**inverted video** (solid white fill, black text) instead of a color
accent — there is no red or amber anywhere in it. The window's title
bar and header always name the machine currently being watched:
`Poltergeist: <target label>`.

- **Setup wizard** — runs on every launch, across seven clickable pages.
  The first page asks which machine to watch: this one, or a remote
  machine over SSH (agent/default key, a specific key file + optional
  passphrase, or username+password — a password or passphrase you type
  in is held in memory for that run only and is **never** written to
  `poltergeist_config.json`, a log, or anywhere else on disk; you
  re-type it every launch, by design). The rest of the pages (evidence
  location, networks, ports, thresholds, machine role, critical paths)
  are seeded with real, probed defaults from whichever target you just
  picked, and the critical-paths page has a "Browse and add a folder..."
  button on a local target instead of making you type a path by hand.
  Click **Next**/**Back** to move around; **Finish** saves and opens the
  main window.
- **Button panel** — every action from the table above, grouped the same
  way the text menu numbers them (Setup & Baseline, Checking, Active
  Defense, Extra Tools). Hover any button and a small tooltip explains
  what it does, in plain English, before you click it. The one slot for
  Sentinel: Baseline / Reset Baseline shows whichever of the two
  currently applies, flipping live the instant the lock state changes.
- **The Dashboard is the main screen** — not a scrolling log. A fixed,
  color-coded set of sections (POTENTIAL MALICIOUS PROCESSES + live open
  ports, FILE INTEGRITY, POTENTIAL C2 / SUSPICIOUS NETWORK ACTIVITY,
  POTENTIAL EVASIVE PERSISTENCE, TRIPWIRE, SSH DIRECTORY CONTENTS, and a
  catch-all OTHER ACTIVITY) always shows the single most *current* state
  of each thing being watched — a condition that's still true doesn't
  pile up a new line every scan, it just stays as one line. This is
  deliberately different from the full-history web Dashboard: that one
  is the complete chronological record (good for Scribe's report and for
  "what happened, and when"); this one is "what's true right now, at a
  glance," color-coded the same way severity is everywhere else in this
  tool.
- **A continuously, ambiently refreshing main view** — there is no
  separate "start monitoring" button or toggle: the window keeps
  re-running a full scan on its own, on the configured interval, for as
  long as it's open, feeding the Dashboard above, and shows a live
  countdown to the next pass in the status bar. A manual button click
  still always takes priority; the ambient pass simply waits its turn
  rather than overlapping one.
- **Console pane** — the same text a terminal would show while an action
  runs (progress, errors, a finished Shield MUTE confirmation) streams
  into a pane in the window instead, so nothing is hidden.
- **One action at a time** — same rule as the text menu: starting a
  second action (manual or the ambient pass itself) while one's still
  running is ignored rather than queued or run in parallel, since the
  backend modules share state files that were never built for two things
  writing to them at once.
- **Typed confirmations still apply** — Shield: MUTE and Reset Baseline
  both still require typing the exact confirmation word in a dialog, not
  just clicking "Yes." Nothing about the GUI makes a destructive-sounding
  action easier to trigger by accident.

No Tkinter, or chose `--text`? Everything above still exists, just as
numbered menu items instead of buttons — nothing is GUI-exclusive.

### One target: this machine, or one other machine over SSH

There is exactly one target per running install, chosen in the setup
wizard (which, again, runs on every launch, so switching targets is just
answering its first question differently next time). A remote target is
reached over SSH using **paramiko** (a pure-Python SSH library, so there
is no separate `ssh`/`scp`/`rsync` binary requirement) and supports
whichever way you'd actually log in by hand:

1. **SSH agent / default key** — the normal case if `~/.ssh` already has
   a working key for that host.
2. **A specific private key file** — by path, with an optional passphrase
   if the key itself is encrypted.
3. **Username + password** — for a box (a practice VM, say) that's only
   reachable that way.

Whichever mode is used, Poltergeist deploys itself to the remote
machine, probes it the same way it probes a local target (real
networks/ports/role suggestions, not guesses), and every later action —
Sentinel, Oracle, Shield, all of it — runs there automatically; its
`findings.jsonl` is synced back here after every single action, so the
Dashboard and Scribe's report always reflect the remote target's actual
state, not a stale local copy. Remote targets are Linux-only for now (a
Windows box reached the same way may come later).

## Typical competition flow

1. **As soon as you get a clean box:** run the wizard (it runs
   automatically on launch anyway) and point it at this machine, or at
   the box you're defending over SSH. Then run **Sentinel: baseline**.
   This hashes every startup/scheduler location, local account,
   installed package, and the config files you told it to protect.
   Everything after this point is compared against this snapshot, so
   only do this once you're confident the box is clean — it **locks**
   the moment it succeeds, so it can't be silently retaken by accident.
   Run **Oracle** here too, to catch known-risky versions before the
   round even starts.
2. **During the competition:** the **Dashboard** is already running in
   the background (it started the moment the menu/GUI came up) — keep it
   open in a browser tab. The GUI's own main window is doing the same
   thing on its own, continuously, with no extra step; under `--text`,
   run **Sentinel: monitor** in a terminal you keep open instead. If
   something in one specific folder worries you mid-round, add a
   **Tripwire** on it without touching the main baseline.
3. **If something looks wrong:** run **Quick Scan** for an instant,
   all-in-one report, or just glance at the findings table — it's always
   on screen in the GUI, or menu item **Recent findings** under `--text`.
4. **If you're actually compromised:** **Shield: MUTE** rewrites the
   firewall to drop everything except your trusted IPs. It asks for a
   typed confirmation first, since it's hard to undo blind.
5. **Before judging:** **Scribe** turns the whole findings log into a
   ready-to-submit Markdown incident report.

## Project layout

```
poltergeist/
├── poltergeist.py          # thin launcher — run this directly
├── poltergeist/
│   ├── cli.py               # wizard, menu, argparse entrypoint (launches the GUI by default)
│   ├── config.py            # load/save poltergeist_config.json
│   ├── discovery.py         # probes interfaces/subnets/VPN/ports
│   ├── evidence.py          # Log class, findings.jsonl, quarantine, capture
│   ├── exorcise.py          # baseline + diff-and-restore logic
│   ├── role_profiles.py     # per-machine-role suggested critical paths
│   ├── color.py             # tiny ANSI color helper (NO_COLOR aware)
│   ├── quickscan.py         # one-command combined report
│   ├── report.py            # "Scribe" — Markdown incident report generator
│   ├── dashboard.py         # localhost-only live findings web page
│   ├── help_text.py         # in-app glossary of every module name
│   ├── menu_actions.py      # one shared action list (key/label/tooltip/group) — GUI buttons and text menu both read this
│   ├── gui/                 # the default desktop front end (Tkinter, no new dependency)
│   │   ├── app.py             # main window: layout, ambient auto-scan poll loop, button dispatch into cli.run_action()
│   │   ├── wizard.py          # clickable 7-page setup wizard (local/remote target page first)
│   │   ├── theme.py           # strict black-and-white palette, fonts, ttk styling, Tooltip widget
│   │   ├── live_dashboard.py  # the main-screen Dashboard: fixed, color-coded, CURRENT-state-only sections
│   │   ├── findings_view.py   # (superseded by live_dashboard.py for the main panel; kept as-is, unused)
│   │   ├── console.py         # background action runner + output-pane plumbing
│   │   └── dialogs.py         # themed confirm/prompt/message popups, incl. show_scrollable_text
│   ├── data/
│   │   └── cve_hints.json   # small OFFLINE starter CVE hint list — refresh before a competition
│   └── modules/
│       ├── persistence.py   # scheduled tasks, services, startup locations (state diff) + evasive-content/foothold-directory/systemd-unit LIVE checks
│       ├── users.py         # local accounts + admin/sudo group membership
│       ├── integrity.py     # hashes files listed in critical_paths
│       ├── packages.py      # installed package name+version baseline ("lockfile")
│       ├── processes.py     # live suspicious-process detection (writable/unusual dirs + name/cmdline keyword match)
│       ├── network.py       # live listening ports + established conns + beacon-timing (possible C2) heuristic — beacon check runs even on a "trusted" destination
│       ├── logging_health.py# logging service status + log-file shrink (tampering) detection
│       ├── log_review.py    # live brute-force detection: ALL Linux logs (+journalctl fallback) or live Windows Event Log via wevtutil; GUI "Upload Log to Analyze" (plain log or wevtutil text export)
│       ├── evtx_review.py   # GUI "Upload Log to Analyze" for a genuine BINARY .evtx file — basic record count/time-range + readable-text scan, no binary-XML decode
│       ├── pcap_review.py   # GUI "Upload PCAP to Analyze" — pure-Python basic flow summary, no tshark/scapy
│       ├── tripwire.py      # on-the-fly, single-folder watch (no full re-baseline)
│       ├── deception.py     # canary/honeytoken files (detect + alert only)
│       ├── lockdown.py      # Shield: firewall rules, MUTE, isolation watchdog
│       ├── oracle.py        # service banner + package version vs offline CVE hints
│       └── remote.py        # the one remote target: paramiko SSH connect/deploy/dispatch/pull-evidence
```

## Adding a new check module

1. Write a new file in `poltergeist/modules/`.
   - A **state** module exposes `collect(config)` and returns a dict of
     `{unique_key: value}` — it gets baselined once and diffed later
     (see `packages.py` for a recent, simple example).
   - A **live** module exposes `check(config, log)` and reports findings
     directly through `log.add(..., suggested_fix=...)` — no baseline
     needed (see `logging_health.py` or `tripwire.py` for examples of a
     live module that keeps its own small memory file between runs).
2. Import it and add one line to `STATE_MODULES` or `LIVE_MODULES` in
   `poltergeist/modules/__init__.py`.

Nothing else needs to change — `cli.py` and `exorcise.py` loop over those
two dictionaries generically, and anything a live module logs through
`log.add()` automatically shows up in Quick Scan, the Dashboard, and the
Scribe's report with no extra wiring.

## What's intentionally NOT in here

Earlier drafts of this idea (from other AI chats) included process
self-hiding from `ps`/Task Manager, fileless memory-only execution that
deletes its own binary, spoofing as a kernel thread or `svchost.exe`, and
a covert C2 channel hidden in ICMP/DNS traffic. Those are rootkit and
malware persistence/evasion techniques — identical whether built for
"our own tool" or an attacker's — and are deliberately left out. The same
goes for anything that kills a process or deletes a file automatically:
every finding gets a *suggested* command instead, for a human to run.

## Status

`persistence.py` has TODOs for the Windows side (`schtasks`, registry Run
keys, `Get-CimInstance Win32_Service`) and the Linux `systemctl
list-timers` parse — see the comments in that file. `users.py`'s Windows
`net user` parsing is a first pass and should be tightened.
`snapshot.py`'s folder-level revert (Windows VSS and Linux LVM) is
scaffolded but not wired up yet — see its TODOs. `cve_hints.json` is a
tiny *example* dataset, not a live feed; refresh it from NVD or your own
notes before an actual competition. A remote target is Linux-only for
now — `remote.py`'s deploy/run both assume a POSIX shell and a `python3`
on `PATH`, which a default Windows SSH setup usually doesn't have; a
Windows box reached over SSH may come later. The GUI (`gui/`) needs
Tkinter, which is bundled on Windows but a separate OS package on most
Linux distros (see Quick start); if it's missing or fails to import for
any other reason, `cli.py` catches that import itself, prints one line
saying so, and falls back to the text menu automatically — it does not
try to patch over a missing Tkinter or guess at a workaround. Because of
that fallback, and because a headless/SSH box should never try to pop a
window, `--text` always forces the text menu outright. The GUI's logic,
data flow, and the text-menu fallback path have all been tested against
fake-tkinter and fake-paramiko harnesses that exercise the real code
(there is no real display or network access in the environment this was
built in); its actual on-screen rendering has not been eyeballed on a
real desktop — if something looks off visually, that's the first place
to check, and the usual fix is `--text` while it gets sorted out.
Double-click launching now exists on both OSes — see
[Running elevated](#running-elevated) — but the Windows `.exe` build
specifically has only been checked for correctness here (spec file,
manifest, icon generator), never actually run, since producing a real
`.exe` requires a Windows machine this dev environment doesn't have; try
`packaging\windows\build_exe.bat` for real on Windows before trusting it.
Contributions / PRs welcome once this is pushed up.

## License

v1.0 — (c) 2026 [Josh Holder](https://github.com/holder77) — released
under the [MIT License](LICENSE).
