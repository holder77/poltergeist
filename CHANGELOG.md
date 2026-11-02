# Changelog

## [Unreleased]
### Fixed — a flood of flashing console/PowerShell windows on Windows during every scan
Real bug report: on a local Windows target, a console or PowerShell
window kept popping open and closing, repeatedly, while the GUI's
ambient auto-scan ran. Root cause: `subprocess.run()`, called from a
windowed/GUI process with no console of its own, makes Windows allocate
a brand-new, briefly-visible console window for each child process it
spawns, unless told not to. `modules/users.py` and `modules/deception.py`
already had the fix for this (`CREATE_NO_WINDOW`) from an earlier bug
report, but it was never propagated to the rest of the project - and the
worst offenders turned out to be exactly the modules that run on *every
single scan pass*: `modules/persistence.py` (the single most-called
`run_command` in the project - `schtasks`, `reg query` per registry key,
and a `powershell` call for services, all re-run every scan by both its
STATE `collect()`, invoked every scan via `exorcise.py`'s diff, and its
own separate LIVE `check()`), `modules/packages.py` (another real
`powershell` process, also STATE, also every scan), `modules/
logging_health.py` (`sc query eventlog`, a registered LIVE module), and
`modules/log_review.py` (`wevtutil`, also LIVE). Applied the same fix
(`CREATE_NO_WINDOW` via a `_HIDE_CONSOLE_KWARGS` dict, Windows-only,
empty/inert on Linux) everywhere it was missing - those four, plus
`discovery.py` (the wizard's own probing), `modules/snapshot.py`
(Medium's snapshot/revert), and `modules/lockdown.py` (Shield's firewall
rules) for full consistency, even though those three aren't part of the
ambient loop and so weren't the main source of the flood. Verified
`_HIDE_CONSOLE_KWARGS` is an empty, no-op dict on this Linux dev
environment (there is no Windows box to reproduce the actual flashing on
directly) and re-ran every existing regression test that exercises these
`run_command()` helpers - all still pass.

### Fixed — setting up a remote (SSH) target failed with "poltergeist.py: No such file or directory", when run from the packaged `.exe`
Real bug report: the Setup wizard's remote-machine page connected fine
(auth, deploy, and the remote config push all reported success) but then
failed with the target's own `python3` unable to find `poltergeist.py`
in the folder it had just deployed into. Root cause: both wizards (text
and GUI) told `remote.probe_target_remote()` to deploy from `REPO_ROOT` -
the folder containing `poltergeist.py` and the `poltergeist/` package in
a plain source checkout. That is the wrong folder once this is the
packaged Windows `.exe` added earlier in this same release: the README
deliberately says to copy that one `.exe` file anywhere, so there is
usually no real source tree sitting next to it at all, and even the
`.exe`'s own notion of "where am I" (`__file__`-based, under
PyInstaller) does not reliably point anywhere a real file lives. Deploy
would quietly walk whatever near-empty folder the `.exe` happened to be
sitting in, "succeed" having copied little or nothing useful, and only
fail three steps later when the remote side tried to actually run
something that was never copied.

Fixed with two changes. First, `config.py` now tells `REPO_ROOT` and a
new `DEPLOYABLE_SOURCE_ROOT` apart: `REPO_ROOT` (used for this machine's
own `poltergeist_config.json`/`evidence/`) now correctly resolves to the
`.exe`'s own folder when frozen (`sys.executable`), instead of the
unreliable `__file__` math - a smaller, related fix, since local
settings/evidence were at risk of landing somewhere equally wrong.
Second, and the actual fix for this bug: `poltergeist.spec` now bundles
a full, plain-text copy of `poltergeist.py` and the entire
`poltergeist/` package *inside* the `.exe` itself, under a
`_deploy_source` folder, built by walking the repo with the exact same
exclusion rule `deploy_to_target()` itself already uses
(`_is_excluded_from_deploy`, imported directly into the spec file so the
two can never drift apart). `DEPLOYABLE_SOURCE_ROOT` reads that bundled
copy back out via PyInstaller's own `sys._MEIPASS` when it is present,
falling back to `REPO_ROOT` only if an older/hand-built `.exe` is
missing it. Both `cli.py`'s text wizard and `gui/wizard.py`'s GUI wizard
now pass `DEPLOYABLE_SOURCE_ROOT` instead of `REPO_ROOT` into
`probe_target_remote()`. A plain `python poltergeist.py` run is
completely unaffected - `DEPLOYABLE_SOURCE_ROOT` is just `REPO_ROOT`
again in that case, verified directly. Re-ran the full existing remote
test suite (`fake_paramiko_test.py`, `fake_tk_wizard_test.py`) and the
full GUI regression suite - all still pass.

### Added — v1.0: hard elevation requirement, a packaged Windows `.exe`, and a Linux desktop shortcut
Bumped to v1.0 and added a real author/copyright/URL
(`(c) 2026 Josh Holder`, `github.com/holder77`), defined once in
`__init__.py` and shown both under the GUI header's tagline (the GitHub
part is a real clickable link, opened via `webbrowser.open()`) and right
under the CLI's ghost banner - plus a new `--version` flag. `LICENSE`'s
copyright line now names Josh Holder too, matching.

`is_admin()` used to only print a warning and carry on. It now gates
`main()` outright (`enforce_elevation_or_exit()`) - every real launch
path (the GUI, the text menu, and every scripted flag like `--check`/
`--baseline`/`--monitor`) refuses to start without root/Administrator,
showing a real popup if headed for the GUI or a plain stderr message
otherwise, then exits. The handful of pure, config-free utility flags
(`--version`, `--discover-json`, `--list-dir`, `--list-logs`,
`--read-log`, `--glossary`) are deliberately exempt, since they're
harmless/read-only and some are also what a remote target's own deployed
copy is invoked with over SSH (already wrapped in its own `sudo -S` by
`modules/remote.py` before this check would even run there).

New `packaging/` folder with both OSes' "make this easy to launch
elevated" story:
- **Windows** (`packaging/windows/`): `build_exe.bat` installs
  PyInstaller, renders the `.exe`'s own file icon from the exact same
  ghost-mascot pixel math `gui/icon.py` already draws the live window
  icon from (`generate_icon.py`), then builds a single-file
  `dist/Poltergeist.exe` with `poltergeist.manifest`
  (`requireAdministrator`) embedded - launching it ANY way (a plain
  double-click included, not only right-click → "Run as administrator")
  now triggers Windows' own UAC prompt automatically. Honesty note: a
  real `.exe` can only be built ON Windows (PyInstaller doesn't
  cross-compile) - everything here was written and checked for
  correctness in this Linux dev environment (the manifest's XML
  validated, `generate_icon.py`'s actual output verified byte-for-byte
  against a stubbed `tkinter`, including catching and fixing a real
  Pillow gotcha where the base image handed to a multi-size `.ico` save
  has to be the LARGEST one or the smaller sizes silently get dropped),
  but the actual PyInstaller build itself has not been run for real -
  try it on a real Windows box first.
- **Linux** (`packaging/linux/`): `install_linux_shortcut.sh` adds a
  normal clickable application-menu entry that elevates via `pkexec` -
  the same native PolicyKit password dialog every major desktop
  environment already uses for its own admin prompts, and the closest
  real Linux equivalent to Windows' right-click → "Run as
  administrator" (there's no universal one-click "run as root" in a
  Linux file manager the way there is in Windows Explorer). Generates a
  small wrapper script that forwards `DISPLAY`/`XAUTHORITY` through
  `pkexec`'s own near-empty environment, since a GUI app launched
  through `pkexec` with no further help can't find a display to open a
  window on at all - a real gotcha, caught and fixed while building and
  testing this end to end (with a stand-in `pkexec` in this sandbox,
  since this environment has no desktop/PolicyKit agent of its own).
  Falls back to printing the plain `sudo python3 poltergeist.py`
  command if `pkexec` isn't available at all (a minimal/server install).
  `README.md`'s own Quick start section documents the plain
  `sudo`/"run as Administrator" fallback either way.

### Added — flashing taskbar icon + ding when a new CRITICAL finding appears
When a brand-new HIGH-severity (red "CRITICAL") finding shows up on the
Dashboard, the taskbar icon now flashes - alternating a normal/inverted
icon on a timer, since there is no single Tkinter API for "flash the
taskbar entry" that works identically on both OSes - until the window is
focused (clicking the taskbar entry or the window itself both count, the
same "like getting a new message on Teams" behavior that was asked for),
and a short two-tone bell ("ding") plays alongside it. The ding is
synthesized in pure Python (`gui/notify_sound.py` - no numpy, no bundled
audio file, no new dependency) and played via `winsound` on Windows or by
shelling out to whichever of `paplay`/`aplay`/`ffplay` is actually
installed on Linux, falling back to Tk's own plain `root.bell()` if none
of those are present. A new "Mute Dings" button next to Setup/Edit
Settings mutes the sound only (session-only, never saved to
`config.json`) - the icon still flashes regardless, since muting means
"stop the noise", not "stop telling me". The very first observation
after a target is confirmed is always treated as the starting baseline,
never as a batch of "new" criticals, so opening the GUI (or switching
targets) against a machine that already has active criticals doesn't
immediately flash/ding.

### Changed — taskbar icon redesign: ghost + diagonal slash + friendly-name initials
The old "ghost paired with a Windows-panes or penguin glyph" taskbar icon
is gone. The window/titlebar icon is now always the plain ghost by itself;
the taskbar icon is the ghost confined to the top-left with a diagonal
slash down to the bottom-right, followed by the first 3 characters of
whatever friendly name was given to the target (e.g. "SEN" for
"sent1") - rendered through a small hand-built 3x5 pixel font - so
running several Poltergeist windows against different boxes side by side
stays easy to tell apart at a glance on the taskbar. This relies on
Windows' own ICON_SMALL/ICON_BIG size convention and is honestly
documented in `gui/icon.py` as not fully portable: most Linux desktop
environments don't make the same size-based distinction and may show one
icon everywhere. Below 24px even the taskbar icon falls back to the plain
ghost, since the full ghost+slash+label layout is illegible noise at that
size.

### Changed — Shield: MUTE and other danger buttons match the normal button style
`Danger.TButton` (used by Shield: MUTE, Medium: Revert a Folder, and the
red "Confirm" buttons in typed-word/yes-no confirmation dialogs) was
previously inverted-video (solid white background, black text). It's now
styled identically to every other button - same background, text color,
and hover/pressed states - per request.

### Changed — CLI banner no longer repeats "POLTERGEIST" under the ghost, and "Blue team" is now in blue
The ASCII ghost banner's trailing `P O L T E R G E I S T` wordmark line
was removed (both the text menu and the GUI header already show the name
in plain text elsewhere, so it was redundant). In the GUI header's
tagline ("Blue team audit tool - never kills a process, never deletes
evidence."), the words "Blue team" are now rendered in a soft blue - the
one deliberate splash of real color anywhere in this project's otherwise
strict monochrome palette.

### Fixed — Medium's snapshot/revert are now real, not placeholders
`modules/snapshot.py`'s Linux snapshot command used to be a hardcoded,
explicitly-fake `lvcreate` call against a made-up device name, and
`revert_directory()` was a complete TODO stub on both OSes that only
ever printed "not wired up yet" and returned `False`. Both are now
implemented: Linux snapshots do real volume-group/logical-volume
discovery first (`findmnt`/`lsblk`/`lvs`, distinguishing "lvm2 isn't
installed" from "this box's root isn't on an LVM volume at all" from
"found it" - all three genuinely verified against this project's own
LVM-less dev box) before sizing a real snapshot at 20% of the origin
volume; Windows snapshots now parse their own `ShadowID`/`DeviceObject`
out of `wmic`'s text output right after creating a shadow copy, which
`revert_directory()` needs to find it again later. Revert itself is new
on both OSes - "Medium: Revert a Folder" (also `--revert FOLDER
--revert-confirm RESTORE` on the command line) mounts the LVM snapshot
(or locates the VSS shadow-copy device path) and mirrors ONE chosen
folder back to exactly what the snapshot held, including removing
anything added since - scoped to one folder at a time on purpose, and
gated by a typed RESTORE confirmation the same way Shield: MUTE already
gates its own hard-to-undo action. This is the one deliberate exception
to "never touch real files" outside Shield MUTE/baseline-reset/Canary's
own bait-file cleanup, since the whole point is a human-invoked,
explicitly-confirmed undo, never automatic remediation of a finding.
Honesty note: this sandbox has no real LVM volume group and no real
Windows VSS environment, so the actual mount/shadow-copy steps could
only be verified against their own honest failure paths here; the
file-restore logic itself (`_mirror_directory()`) is pure Python and WAS
fully tested end to end. Try this for real on a throwaway LVM/VSS box
before trusting it in an actual competition.

### Added — Oracle can now refresh its offline CVE hints from CISA's KEV feed
Oracle's known-risky-version check was limited to 5 hand-typed starter
entries in `modules/data/cve_hints.json`, since the tool is designed to
run with no internet access during a competition. There is now one
explicit, opt-in, PRE-COMPETITION-ONLY action - "Oracle: Refresh OSINT
Hints" in the menu/GUI, or `--oracle-refresh-hints` on the command line -
that fetches CISA's free, no-API-key "Known Exploited Vulnerabilities"
(KEV) catalog exactly once and folds it into the same offline hint file
`modules/oracle.py`'s own scan already reads from, grouping every CVE by
vendor+product so a widely-hit product gets one combined entry instead
of a dozen duplicates. This is the one and only network call anywhere
in this project that looks up vulnerability data, and it is deliberately
never run automatically, never part of any scan, and never dispatched to
a remote target - exactly the same "never hang, never crash, just say so
and change nothing" offline-fallback shape `ntp_sync.py` already uses,
since a locked-down range refusing this request is the normal, expected
case. The 5 hand-typed starter entries (and anything added by hand) are
always kept; only a previous refresh's own entries are ever replaced, so
running it again never piles up duplicates. The new entries are tagged
as a looser vendor+product-name match (not the precise version-string
hints above), and the hint file is stamped with when it was last
refreshed.

### Added — Canary bait files can now be planted in real, chosen locations
"Plant Canaries" used to only ever drop bait files into Poltergeist's own
evidence folder - a location no real attacker has any reason to browse,
making the feature nearly useless as shipped. Canary now has its own
Tripwire-style folder list (`modules/deception.py`'s new
`add_folder()`/`remove_folder()`, capped at 3 locations, reusing the same
GUI folder browser Tripwire already has, local and remote alike): "Canary:
Choose a Bait Location" seeds any real folder (a web root, a shared
drive) right now, and "Canary: Stop Seeding a Location" stops watching
one and cleans up the bait files Poltergeist itself planted there - the
one deliberate, narrow exception to "never delete anything", since these
are synthetic files this module created for exactly this purpose. Falls
back to the evidence folder alone (with a clear note) if nothing has
been chosen yet, so the feature still does something useful out of the
box. Also added an honest, best-effort diagnostic: planting now checks
whether the target folder's filesystem actually tracks last-access time
at all (Linux `noatime` mounts, Windows's NTFS last-access tracking -
disabled by default since Vista) and warns plainly when it doesn't,
since Canary's whole detection method depends on that tracking working.
The GUI's own live Dashboard tab now shows a dedicated CANARY section
with the currently-seeded locations, the same treatment Tripwire's
watched folders already get.

### Fixed — resolved findings no longer stay on the Dashboard forever
Killing a flagged process or deleting a dropped file by hand used to
leave its finding sitting on the web Dashboard and the GUI findings
table looking permanently active, even scans later - nothing ever told
either view the condition had gone away, since findings.jsonl is
append-only and a brand new `Log` is built fresh every scan pass. Two
changes fix this: `evidence.py` gained `latest_state()` (collapses the
history down to one row per finding, the exact logic the GUI's own
Dashboard tab already used) and `resolve_stale()` (lets a live-check
module compare what it finds true THIS scan against what was true last
scan, and log one new low-severity "resolved" note - never a delete -
for anything that dropped out). `processes.py` and `persistence.py`
(the two modules behind the process/file-integrity findings in this
round's bug report) now call it at the end of their own checks. The web
Dashboard and the GUI findings table both now show that deduped,
current-as-of-this-scan view instead of the raw, ever-growing history -
matching how the GUI's own Dashboard tab already worked.

### Fixed — Dashboard/findings table showed raw UTC instead of local time
The web Dashboard and the GUI's own findings table were still printing
every finding's timestamp as the raw, unconverted UTC string ("...Z")
this session's earlier NTP fix writes to disk - only the generated
incident report was actually converting it for display. A finding
logged a moment ago could misleadingly look hours old to whoever's
looking at it from a timezone behind UTC. Both views now run every
timestamp through a new shared `evidence.format_ts_for_display()`
(the same local-timezone conversion the report already used) before
showing it; an old, pre-NTP-fix timestamp with no "Z" marker is left
exactly as it was, since there's no safe way to guess which timezone it
was originally written in.

### Added — interactive folder browser for Tripwire, local AND remote
"Tripwire: Watch a Folder" now opens a real, clickable folder browser -
step into a subfolder, step back Up, pick "Select This Folder" - instead
of either the old native-OS picker (local only) or a blind typed path
(remote only). Works identically for a remote (SSH'd) target: the new
`modules/fs_browse.py` backs the listing, reused over SSH via three new
`modules/remote.py` functions and three new config-free `cli.py` flags
(`--list-dir`/`--list-logs`/`--read-log`) - the exact same "deploy & run
as self" design every other remote feature already uses, so a remote
browse always shows the REMOTE machine's own real folders (Windows
drive letters included on a Windows target), never the analyst's own.
Still entirely read-only - browsing never creates, deletes, or changes
anything on either machine.

### Added — View System Logs: remote support, a log picker, and a search bar
"View System Logs" now works against a remote (SSH'd) target too, not
just local - and instead of dumping every log/channel into one giant
window, a picker lets you choose exactly which log or Windows Event Log
channel to open. Each one opens in its own viewer: a "WORTH A LOOK" IOC
summary at the top (same brute-force analysis as before, now per-log),
the full raw text below it, and a live search box that highlights every
match as you type. Backed by two new `modules/log_review.py` functions
(`list_available_logs`/`read_log_content`), reused over SSH for a remote
target the same way the new folder browser is. Never writes to
findings.jsonl - this is a read-only viewer, not a new scan.

### Added — NTP-corrected, timezone-explicit timestamps on every finding and report
Every finding's own timestamp (and the incident report's "Generated:"
line) now checks itself against a real NTP time source first, instead
of just trusting whichever machine's own system clock happened to be
running - a new `ntp_sync.py` tries `pool.ntp.org`, `time.cloudflare.com`,
and `time.google.com` in turn (hand-rolled SNTP, no new dependency),
caches the measured offset for 5 minutes, and gracefully falls back to
the uncorrected system clock (never blocking or slowing a scan) if NTP
is unreachable - common on a locked-down competition range. Every
stored timestamp is now also explicit UTC ("...Z") rather than an
ambiguous bare local-clock reading, so findings from two different
machines (the analyst's own, and a remote target) in the same report
can finally be compared apples-to-apples. The incident report displays
every timestamp - its own header and every single finding - converted
into whichever timezone the machine generating the report is actually
set to (report.py always runs on the analyst's own machine, never a
remote target), with no hardcoded location anywhere: on a machine set
to Mountain Time this just shows Mountain Time automatically. The
report's header also states plainly whether its timestamps were
actually NTP-verified or are only as good as the local system clock.
Findings logged before this change (no "Z" marker) are shown unchanged,
clearly labeled "(pre-sync, timezone unknown)" rather than guessed at.

### Changed — ghost banner art tweak
Minor touch-up to the braille-art ghost's own bottom row, in both the
text menu and the GUI header (one shared constant, so both update
together).

### Added — Windows registry Run/RunOnce keys, Windows services, and Linux systemd timers to persistence detection
Three gaps left over from the Windows Scheduled Tasks work: (1) HKLM and
HKCU `...CurrentVersion\Run`/`RunOnce` registry values are now baselined
and live-checked (name-keyword and evasive-command-pattern matches, same
bar as scheduled tasks) via `reg query`. (2) Windows services are now
baselined via PowerShell's `Get-CimInstance Win32_Service`, specifically
so a service quietly flipped from Manual to Automatic start mode is
caught on the next baseline diff, plus the same live name/command checks.
(3) Linux systemd timers are now baselined via `systemctl list-timers
--all`, which also catches a timer shipped under `/lib/systemd/system`
that the existing `/etc/systemd/system`-only file scan never saw.

### Added — Tripwire shows its currently watched folders, and can stop watching one
The Dashboard's TRIPWIRE card now lists every folder currently being
watched, not just alerts about changes inside them. A new "Tripwire:
Stop Watching a Folder" button (and `--unwatch` flag, and text-menu
option) lets you pick one of the watched folders to stop watching.
Watching is capped at 3 folders at once - trying to add a 4th is refused
with a clear message instead of silently doing something confusing;
open a separate instance of Poltergeist if you need to watch more.

### Added — richer SSH key info (type + comment), and Windows support
The SSH directory listing now shows each public key's own TYPE
(ssh-rsa, ssh-ed25519, ecdsa-...) and COMMENT (usually "user@host", but
never validated by OpenSSH, so an odd one like "unknown@kali" is itself
worth a look) instead of just a bare hash - for every `.pub` file, and
for every individual line of `authorized_keys`. This whole check also
now runs on Windows: every real user profile's own `.ssh` folder under
`C:\Users`, plus the OpenSSH Server feature's own separate
`administrators_authorized_keys` file (easy to forget, since it lives
outside any per-user folder).

### Fixed — two simultaneously running instances were secretly sharing one config, baseline, findings file, and Dashboard port
Real side-by-side test: running "sent1" and "sent2" as two separate GUI
instances at once showed sent1's findings mixed into sent2's dashboard,
and both windows reported the SAME baseline as locked, no matter which
target either one was actually pointed at. Root cause: `config.json` and
the `evidence/` folder are both fixed paths next to the install - every
running instance was reading and writing the exact same two files/folder
regardless of which target it was configured for, so whichever instance
saved its settings LAST silently overwrote the other's, and both saw an
identical (shared) baseline lock and findings list. This also made the
GUI's own new "open a separate new instance to keep this one's baseline"
advice (see the Setup warning below) actively untrue.
- **Fixed**: `config.py` now claims one of several numbered "instance
  slots" the moment it is first imported (once per running process) - the
  first instance to launch gets the plain, unnumbered
  `poltergeist_config.json`/`evidence/` pair exactly as before (no
  migration, nothing changes for the common case of one running
  instance); a second instance launched while the first is still running
  automatically gets its own, completely separate
  `poltergeist_config_2.json`/`evidence_2/` pair instead - a third gets
  `_3`, and so on. Each slot is claimed with a small lock file (just that
  process's own PID) that releases itself automatically on a clean exit,
  and self-heals if an instance was closed in a way that skipped that
  cleanup (a lock whose PID is no longer running is treated as free).
- The web Dashboard's port is now per-instance too (8765 for the first
  instance, 8766 for a second, 8767 for a third...), so two instances'
  "Open Dashboard in Browser" buttons (and the status bar's own printed
  link) never collide or silently show each other's data either.
- A remote deploy now also excludes every OTHER instance's own numbered
  config/evidence/lock files, not just the plain instance's - so running
  a deploy from whichever instance ISN'T the first one never leaks that
  instance's own local settings or findings onto the target.

### Changed — baseline resets automatically now; "Reset Baseline" button removed
Direct feedback: the standalone "Reset Baseline" button added one extra,
easy-to-forget manual step for something that should just already be true
by the time it matters. It's gone now, replaced with two automatic resets:
- **A fresh launch of the GUI always starts with an unlocked baseline.**
  Opening a new instance of Poltergeist is now itself "already reset" -
  no manual step needed before the first "Sentinel: Baseline" click.
- **Clicking "Setup / Edit Settings" always resets the baseline too**,
  whether or not anything about the target actually changes - there is
  only one baseline per running instance, so re-opening Setup can never
  be allowed to leave a stale locked baseline sitting there, silently
  being compared against whatever gets configured next. Unlike the
  silent launch-time reset above, this one interrupts something already
  on screen (and possibly already monitoring), so it now shows a warning
  first and asks for an OK before doing anything - the warning also says
  plainly what to do instead if the goal is to watch an ADDITIONAL host
  without disturbing this one: open a separate new instance for that
  host, rather than reusing Setup on this one.
- `exorcise.reset_baseline()` itself is unchanged - it still only ever
  **moves** the old baseline into `evidence/baseline_history/`, never
  deletes it, exactly as careful as the manual button used to be.

### Added — a confirmation (and an automatic final report) on quitting the GUI
Clicking the window's own close button (the OS `[X]`) used to close the
whole thing immediately, with no way to catch an accidental click and no
chance to capture a final report before everything logged so far is only
ever reachable by relaunching and clicking "Scribe: Write Report" by hand.
- Direct feedback: closing the window now asks "Are you sure you want to
  quit this instance?" first. Confirming writes a final Scribe incident
  report automatically (the same thing "Scribe: Write Report" does by
  hand), shows a popup naming exactly where it was saved, THEN closes the
  window - nothing logged during the session is left stranded behind a
  closed window with no report ever generated from it.

### Reverted — GUI goes straight to the main panel again when a config exists
A brief, since-reverted change made the GUI always open to the Setup
wizard on every launch, pre-filled from the previous config. Follow-up
feedback asked for the original behavior back, so this is reverted: the
GUI once again skips straight to the main action panel whenever a saved
config already exists, and only shows the wizard on a genuinely first-ever
run (or whenever "Setup / Edit Settings" is clicked by hand). The icon
work below is unaffected and still applies on this path too.

### Fixed — Windows taskbar button still showed the plain Python logo
The titlebar icon (top-left corner of the window) was showing the real
ghost icon correctly, but the Windows taskbar BUTTON for the app kept
showing the generic Python logo regardless. `root.iconphoto()` only
controls the window's own titlebar icon - Windows decides which icon to
show on the taskbar button (and how to group the window) based on the
PROCESS's own "AppUserModelID," which defaults to python.exe's/
pythonw.exe's own identity for anything launched with plain `python`.
- **Fixed**: `gui/app.py` now calls
  `ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(...)`
  with Poltergeist's own unique ID, at import time (before any window is
  created - setting it later has no effect), Windows-only (`sys.platform
  == "win32"`, silently skipped everywhere else). This tells Windows the
  process is its own distinct application rather than "just Python," so
  the taskbar button now shows the real ghost+OS icon too, matching the
  titlebar.

### Fixed — real taskbar icon crash that silently fell back to the text menu
The ghost+OS icon (added below) built its pixel data as a hand-rolled
Tcl brace-string (`"{{#fff #000} ...}"`) and handed that whole string to
`PhotoImage.put()`. That string was only ever exercised against a fake
test stub in development (this project's own sandbox has no real Tk to
test against) and turned out not to be valid once run against a real Tk
interpreter - it raised during the window's own construction, which
`cli.py`'s broad safety net around launching the GUI caught silently and
fell back to the terminal text menu instead, with no window ever
appearing.
- **Fixed**: `gui/icon.py`'s `build_icon_photoimage()` now hands
  `PhotoImage.put()` a native Python list of lists of plain `"#rrggbb"`
  strings (one inner list per pixel row) instead of a hand-built
  brace-string - the documented, version-safe way to pass a whole grid
  in one call, since Tk's own implementation builds the correct Tcl list
  from it directly rather than trusting a hand-rolled one.
- Confirmed, and left as-is since it was already correct: `evidence.py`'s
  `Log.add()` opens `findings.jsonl` in append mode only - nothing
  Poltergeist does ever overwrites or deletes a previous evidence folder.

### Added — Real ghost icon (titlebar + taskbar), dynamic by target OS
The window was showing Tkinter's own stock default icon (a quill/feather)
in both the titlebar and the taskbar the whole time - Poltergeist never
actually set its own icon anywhere.
- **Added**: `gui/icon.py` builds the icon entirely in code (plain
  geometry - circles/ellipses and a scalloped-hem formula for the ghost),
  not from a bundled image file, so it survives being zipped and deployed
  to a remote box exactly like every other `.py` file already does.
- The icon is the ghost mascot alone until a target has actually been
  confirmed once; from then on it's HALF ghost, half a small, genuinely
  generic glyph for whichever OS that target actually runs - a plain
  round-headed "penguin" silhouette for Linux, four generic filled
  squares ("window panes") for Windows. Neither glyph copies or
  resembles any real logo, mascot, or trademark - see `icon.py`'s own
  module docstring for the full reasoning on that.
- Which OS a target runs is now recorded on the saved config itself
  (`target.os`, "windows" or "linux") straight from the wizard's own real
  probe of the machine (never guessed) - both `cli.py`'s text wizard and
  `gui/wizard.py`'s GUI wizard set it the moment a connection/probe
  actually succeeds. The icon switches the instant a different target is
  confirmed, and already shows the right OS-aware glyph for a
  PREVIOUSLY-confirmed target from the moment the (pre-filled, per the
  item above) wizard opens, before it's even been clicked through again.

### Fixed — Help dialog text ran off the right edge instead of wrapping
The "What does everything do?" window got its scrollbar fixed last round,
but its text still didn't wrap - every long, plain-English tooltip
description (like "Oracle: Scan Services") just kept running off the
dialog's right edge with no horizontal scrollbar ever built for this
dialog either, so it still looked cut off even though it was now
technically scrollable vertically.
- **Fix**: `gui/dialogs.py`'s `show_scrollable_text()` (the shared dialog
  behind Help, View System Logs, and every upload-results window) now
  takes an optional `wrap` parameter. The Help dialog passes `wrap="word"`
  so its prose wraps normally at the dialog's edge. Every other caller
  (raw log text, file paths, scan results) keeps the original unwrapped
  behavior, since mid-word wrapping a long path or command makes it
  harder to read, not easier - but those now also get a proper horizontal
  scrollbar, which this dialog never actually had before.

### Fixed — C2 beacon detection missed a C2 handler that rotates its remote port
Directly diagnosed from a side-by-side with the Shadow Watch/Harbinger
scanner against the same live lab box: Harbinger's IOC scanner flagged
`172.28.20.1` as a `[POTENTIAL BEACON]` on two different remote ports
(`54320` and `34478`), but Poltergeist's "POTENTIAL C2 / SUSPICIOUS
NETWORK ACTIVITY" section stayed completely empty against the exact same
box the whole time.
- **Root cause**: the beacon-timing heuristic (`modules/network.py`)
  tracked its "have we seen this destination enough times to judge its
  timing" history keyed by `remote_ip:remote_port` together. A C2 handler
  that deliberately rotates which port it listens on for each check-in -
  specifically to defeat "same ip:port seen repeatedly" tracking - reset
  that sample count back to 1 on literally every single connection, so
  the 4-sample minimum needed to say anything was never reached, no
  matter how long a scan ran. The beacon was real and checking in on a
  perfectly regular timer; the tracking key was just never stable enough
  to notice.
- **Fix**: beacon history is now tracked by destination IP alone. The
  finding's message plainly says when a destination has been reached on
  more than one port ("port-hopping, likely intentional") instead of
  just naming a single port, so that behavior is surfaced to the analyst
  rather than hidden. A regular beacon that stays on one fixed port the
  whole time is still caught exactly as before.

### Changed — Dashboard sections now show HIGH (red) findings before MEDIUM (orange) ones
Each section still caps at 8 visible rows, but previously that cap was
purely chronological - a section with more than 8 findings could end up
hiding a genuine HIGH finding behind older MEDIUM ones that simply
happened to be logged first. Rows are now sorted red-before-orange-
before-info before the cap is applied, so a real HIGH finding can never
be silently pushed out of view by a lower-severity one.

### Fixed — GUI console pane and Dashboard could freeze permanently after re-opening Setup
Found from a real report: the terminal running `python3 poltergeist.py` kept
showing live scan output the whole time, but the app's own window - both the
Output console pane and the Dashboard - never updated again after a certain
point, making it look like the tool had completely stopped working even
though it genuinely hadn't.
- **Root cause**: clicking the header's own "Setup / Edit Settings" button
  (exactly what you'd do to fix a target and point it at a different box,
  such as after a connection timeout) destroyed the whole button panel to
  make room for the wizard, but left `self._action_buttons` still holding
  references to those now-destroyed button widgets. The moment anything
  toggled the shared "busy" flag next (the wizard's own probe/deploy step
  does exactly that), the main window's recurring `_poll_loop` tried to
  enable/disable every one of those now-invalid buttons and hit a real
  `_tkinter.TclError: invalid command name ...` - an uncaught exception
  inside a `root.after()` callback. Because that error happened *before*
  `_poll_loop` reached its own line that reschedules itself, the loop
  simply never ran again for the rest of the session. The console pane and
  Dashboard are ONLY ever repainted from inside that loop, so both froze
  solid from that moment on - while every actual scan/deploy action kept
  running completely normally in the background (which is exactly why the
  real terminal kept showing fresh output the whole time).
- **Fix, two layers**: (1) re-opening Setup now also clears
  `self._action_buttons` (`gui/app.py`'s `_show_wizard()`), the same way
  switching to the main panel already did - the actual root cause. (2) As a
  second line of defense, `_poll_loop` itself is now wrapped so that
  *nothing* happening inside one tick - this bug or any other, known or
  not - can ever again stop it from rescheduling: it always prints a
  traceback for anything that goes wrong and always queues the next tick
  regardless, so the console/Dashboard can no longer freeze permanently
  no matter what fails inside a single tick.

### Fixed — Remote scans could freeze / show repeated authentication failures mid-scan
Each scan cycle against a remote target was opening TWO separate fresh SSH
logins (one to run the command, a second right after to pull evidence
back). Against a competition-lab box with its own SSH connection-rate
defenses, that second rapid-fire login could get rejected even with
completely correct credentials - surfacing as a real, repeating
`paramiko.AuthenticationException` and an apparently "frozen" scan.
- **Fix**: `modules/remote.py`'s `dispatch()` now opens exactly one SSH
  connection per scan cycle and shares it between running the command and
  pulling evidence back (`run_remote_command()`/`pull_evidence()` both
  accept an `existing_client` now). Half as many logins per cycle, so
  this can only help, never hurt.

### Changed — Dashboard sections restructured to match the layout you're used to
- **Open Listening Ports** is now its own top-level section (it was
  previously folded into "malicious processes," where a real process
  finding could get buried behind a page of routine open-port rows).
- **File Integrity / Root Directory Scrub** now actually gets live data.
  The "foothold directory" checks (new/world-writable files dropped in
  system folders) were already running every cycle but were filed under
  the "persistence" module, so this section - which only listens for
  "integrity" findings - always read empty even with real findings
  elsewhere on screen. They're now correctly filed under "integrity," so
  root-directory-scrub findings show up where they're labeled to be,
  separately from scheduled-task/cron/timer persistence findings.

### Fixed — A remote target's real findings never reached the local Dashboard at all (evidence folder was double-nested)
The deeper cause behind "still showing nothing" even after the Dashboard's
wrong-machine-ports bug (below) was fixed, and even once the console
output was visibly full of real `[HIGH]`/`[MEDIUM]` findings for the
target: the path the remote scan was actually writing `findings.jsonl` to
and the path the local machine's `pull_evidence()` was pulling it back
*from* did not match - off by exactly one extra folder level - so every
remote scan genuinely found plenty, wrote it somewhere real, and
`pull_evidence()` silently never found anything new to bring back. The
Dashboard (and the findings table, and the Scribe report) were all
reading a local `findings.jsonl` that had simply stopped updating.
- **Root cause**: every remote action this tool runs starts with `cd
  <remote_path> && python3 poltergeist.py ...` - so by the time that
  process is actually running, its own current working directory *is
  already* the deployed folder (`remote_path`, "poltergeist" by default).
  But the config pushed to the remote side was setting `evidence_dir` to
  `remote_path + "/evidence"` (e.g. `"poltergeist/evidence"`) - a
  RELATIVE path that then resolved against a working directory that was
  *already* `.../poltergeist`, landing one folder too deep at
  `.../poltergeist/poltergeist/evidence` instead of the intended
  `.../poltergeist/evidence`. `pull_evidence()` always looked in the
  correct, single-nested spot, so it just quietly never found anything
  there to pull.
- **Fix**: the remote-side `evidence_dir` pushed during both the initial
  probe (`modules/remote.py`'s `probe_target_remote()`) and the final
  settings push (`cli.py`'s text wizard and `gui/wizard.py`'s GUI wizard)
  is now the bare string `"evidence"`, with no `remote_path` prefix -
  correct precisely because the remote process's cwd is always already
  `remote_path` by the time it's read.
- **For an already-deployed target** (like one set up before this fix):
  re-run Setup against it once. That pushes the corrected config over the
  existing deployment - no fresh deploy needed. Nothing at the old,
  double-nested location is ever deleted (this tool never deletes
  evidence); it's simply abandoned in favor of the correct path.

### Changed — small UI/text cleanups from feedback
- "Haunting: Plant Canaries" is now just "Plant Canaries" (button label,
  CLI text-menu line, and the quickscan hint that points you to it).
- The Help menu ("What does everything do?") now opens in the same
  scrollable, resizable dialog the log viewer uses, instead of a
  non-scrollable popup that cut off partway through the list.
- Oracle now always prints a one-line "Oracle scan complete: N port(s)
  checked (M gave a readable banner), P package(s) checked, Q known-risk
  match(es) found" summary when you run it, even on a totally clean box
  where nothing gets logged - previously a clean scan finished in total
  silence, which looked exactly like the button not doing anything.
  (Scribe's "report written to..." / "nothing to report" line was
  already doing this correctly; Oracle now matches it.)

### Fixed — Dashboard's "POTENTIAL MALICIOUS PROCESSES" section was showing the ANALYST'S OWN machine's ports, not the target's
The real cause of "still absolutely nothing showing" on the Dashboard,
confirmed directly from a screenshot: the section's live port listing
(`tcp 8862 SearchHost.exe`, `tcp 2225 com.docker.backend.exe`,
`svchost.exe`, `wslrelay.exe`...) was plainly Windows/WSL process names -
the OPERATOR's own laptop, not the remote Linux target `sent1` the rest
of the screen was labeled for.
- **Root cause**: `gui/live_dashboard.py`'s `build_live_ports_rows()`
  called `discovery.find_listening_ports()` directly - which runs
  wherever the GUI's own Python process happens to be running, i.e. the
  analyst's machine, ALWAYS, regardless of which target is selected.
  That's correct for a local target (the GUI and the thing being scanned
  are the same machine) but silently wrong for a remote one. Worse: with
  the per-section row cap (8) and most boxes having at least a handful
  of listening ports, the analyst's own routine local ports could fill
  the ENTIRE section before a single real remote "process" finding ever
  got a chance to show - a genuinely malicious process finding could be
  sitting there, cut off behind a "+N more" note, while the visible rows
  were 100% irrelevant local noise.
- **Fixed two ways**: (1) `quickscan.py`'s own listening-ports section -
  which DOES correctly run on whichever machine the scan is actually
  happening on, local or remote - now also logs each port as a quiet
  `quickscan`/`port:` finding, so it travels back through the exact same
  `pull_evidence()` sync every other remote finding already uses; the
  Dashboard reads these back from `findings.jsonl` instead of calling
  `discovery.py` itself, so it always shows the TARGET's ports, not the
  analyst's. (2) Within the section, real findings are now listed BEFORE
  the routine port rows, so a genuine malicious-process finding can never
  be pushed past the row cap by ordinary port listings again.
### Fixed — Four real detection gaps found by comparing a live scan against the Shadow Watch/Harbinger reference tool on the same VM
Direct follow-up to the elevation fix above: once scans could actually
read root-owned files, the Dashboard STILL showed almost nothing while
the reference tool ("this is the report on harbngr... I think
orchestrator.py is what has everything you need to reference") found
real, planted findings on the exact same box - malicious processes,
root-directory dropper files, a C2 beacon, and anomalous systemd
persistence. Each gap below was found by reading `orchestrator.py`'s own
`_scan()` method line by line and checking whether Poltergeist's
equivalent module had a matching check at all - three genuinely did not,
and one existed but was being silently short-circuited.
- **Processes**: `modules/processes.py` had no keyword or "unusual
  install location" check at all - a process literally named
  `shadow_agent.py` running from `/usr/local/sbin` (the reference tool's
  own PID 34 finding) was invisible to it. Added `PROCESS_NAME_KEYWORDS`
  (a short, explainable list: wipe, shadow, miner, backdoor, implant,
  beacon, payload, dropper, rootkit, respawn, reverse, exfil, keylog,
  guard) checked against every process's name AND full command line, high
  severity, plus `UNUSUAL_INSTALL_DIRECTORIES` (`/usr/local/sbin/`,
  `/opt/`, `/srv/`) at a deliberately SOFTER medium severity than the
  existing world-writable-dir check - a stock/minimal competition VM
  almost never runs anything from these, but real software does
  sometimes legitimately live in `/opt` on an ordinary machine (confirmed
  directly against this very dev sandbox, which has real tooling there),
  so this stays a "worth a look" rather than an automatic high.
- **Persistence (dropped files)**: `modules/persistence.py` only ever
  looked at the project's own fixed list of autostart locations
  (cron.d, systemd unit dirs, shell profiles, etc.) - it never scanned
  `/usr/local/sbin`, `/opt`, or `/srv` for dropped files at all, which is
  exactly where the reference tool's "ACTIVE ROOT DIRECTORY SCRUB" found
  `sw-wipe.sh`, `sw-respawn.sh`, and `shadow_agent.py`. Added
  `check_foothold_directories()`: every file found under
  `/usr/local/sbin`, `/opt`, `/srv` is reported (high severity if its
  name matches a keyword, medium "worth a look" otherwise), while
  `/tmp`, `/dev/shm`, `/var/tmp` are only reported on a keyword match -
  ordinary temp-file churn there is expected and would otherwise flood
  the Dashboard with noise. Same keyword list as the process check above.
- **Persistence (systemd units)**: nothing in Poltergeist looked at
  *.timer/*.service unit names at all - the reference tool's "POTENTIAL
  EVASIVE PERSISTENCE" findings for `logrotate-guard.timer` and
  `logrotate-guard.service` had no equivalent here. Added
  `check_systemd_units()`: any `.timer` file in `/etc/systemd/system`
  whose exact name is not on `KNOWN_BENIGN_TIMER_NAMES` (the standard
  Debian/Ubuntu-family stock timer names) is flagged medium severity;
  `.service` files are flagged only on a keyword-name match (too many
  legitimate service names exist to allowlist them all).
- **Network (the actual cause of the missing C2 finding)**: the
  reference tool flagged `172.28.20.1` - the box's own auto-discovered
  default gateway - as a `[POTENTIAL BEACON]`. Poltergeist's own
  beacon-timing heuristic (added last round) never got a chance to even
  look at that connection: `network.py`'s trust check skips a
  destination entirely the moment it falls inside the user's "networks
  being defended" CIDR or the "Trusted external IPs" list - and the
  setup wizard was pre-filling that exact gateway address into "Trusted
  external IPs" by default. On a flat, single-subnet lab/competition VM,
  that is precisely where a C2 handler can sit. Fixed two ways: (1) the
  wizard no longer pre-fills the discovered gateway into trusted IPs (it
  is still shown for reference - type it in yourself if you're sure
  traffic through it is routine); (2) more importantly,
  `check_beacon_pattern()` now runs on EVERY established connection
  regardless of trust - a perfectly-timed, regular check-in to a
  "trusted" destination is itself still a strong, specific signal that
  should never be silently suppressed, even though the plain, low-
  specificity "new/unusual connection" listing still stays quiet for a
  trusted destination, to avoid flooding the Dashboard with ordinary
  internal traffic.
- **Not a bug, but worth saying plainly**: a fresh target's Dashboard
  will still show `No baseline found` under BASELINE DIFF until Baseline
  is actually run once - unlike the reference tool, which auto-records
  its own first observation as a baseline the moment it connects,
  Poltergeist's baseline step stays a deliberate, separate action (new
  users, new processes, and file-integrity changes are only ever judged
  against a baseline that was explicitly taken, never a guess). Worth
  running it now on a freshly set-up target.
### Fixed/Added — This round's feedback: SSH wizard fields, Dashboard flicker/color, full log + Windows Event Log coverage
Direct answers to this round's feedback ("ssh options still not working
no spot to upload a key or enter in what I'm doing for that or the user
password dosen't work," the Dashboard "flickering a ton," "add color to
make things that are important stick out," and the log options should
"pull all the logs that a linux distro would have... and if its a
windows enviroment it goes to winevents but also lets you upload
winevents as well and it analyzes those"):
- **Fixed: the SSH setup wizard's key-file/password fields were
  genuinely unreachable, not just hard to notice.** The root cause
  wasn't the auth-mode logic (`_rebuild_auth_subfields()` was already
  correct) — it was that `gui/wizard.py`'s content area was a plain,
  fixed-size, non-scrolling `ttk.Frame` despite a comment claiming it
  was "the scrolling content area." Once a remote target's auth mode
  revealed the key-path/passphrase or username/password fields, they
  could simply run off the bottom of the window with no way to reach
  them. Fixed by making the content area genuinely scrollable: a real
  `tk.Canvas` + `ttk.Scrollbar` + inner frame, with cross-platform
  mouse-wheel support, and every page now resets its scroll position to
  the top when it's built. A real test gap this also closed: the
  existing wizard tests exercised the key-file/password success paths
  by directly poking the frame's internal variables, never by actually
  clicking the radio buttons the way a person does — new tests drive
  the real click-through path instead.
- **Fixed: the Dashboard's heavy flickering.** `gui/live_dashboard.py`'s
  `refresh()` was destroying and rebuilding every row widget on every
  poll tick (every few seconds) — the literal cause of "its refreshing
  giving live information but its alot of flickering." Rewritten to
  build a fixed pool of row widgets once and, on every refresh, only
  reconfigure their text/color and show or hide them in place
  (`grid()`/`grid_remove()`, chosen specifically because it preserves a
  row's exact position, unlike `pack_forget()`), so nothing is ever
  briefly blank. Proven with a new test that captures widget object
  identity across several refreshes and asserts the exact same widgets
  are reused, not recreated.
- **Added: real color on the Dashboard for high-severity items** — a
  new `SEVERITY_COLORS` table in `live_dashboard.py` (bright red accent
  bar, bold red text, and a dark red row background for HIGH; amber for
  MEDIUM; muted gray-blue for INFO), scoped to the Dashboard only so the
  rest of the GUI keeps the strict black-and-white theme an earlier
  round specifically asked for.
- **Added: Linux log coverage is no longer just `auth.log`/`secure`.**
  `modules/log_review.py`'s `list_linux_log_files()` now reads every
  known system log file that actually exists under `/var/log`
  (`syslog`/`messages`, `kern.log`, `daemon.log`, `cron`, `maillog`,
  `boot.log`, both major package managers' logs, `ufw.log`, and more),
  plus anything else matching `*.log` this list didn't anticipate,
  explicitly excluding binary record formats (`wtmp`, `btmp`,
  `lastlog`, `faillog`) so "read everything" never means "read a binary
  file as text." A journald-only distro with no flat log file at all
  (this project's own dev sandbox is one real example) falls back to
  `journalctl` instead of reporting nothing. Both **View System Logs**
  and the live brute-force check (`check()`) use this same broadened
  list.
- **Added: real Windows Event Log support**, live and uploaded —
  "if its a windows enviroment it goes to winevents":
  - **Live**: on a Windows box, `check()` and **View System Logs** now
    read the Security/System/Application channels via `wevtutil`
    (the standard built-in command-line tool — no new dependency).
    The Security channel's 4624/4625 events are parsed and fed into the
    exact same shared brute-force tally the Linux path uses
    (`_tally_brute_force()`), so "5+ failures from one source,
    especially followed by a success" means the same thing and is
    worded the same way regardless of OS.
  - **Uploaded, text export**: **Upload Log to Analyze** auto-detects a
    `wevtutil`-style text export (`/f:text`, or an equivalent
    PowerShell export) by its own `Event[N]:` block shape and routes it
    through the same Windows-side analyzer — no second button needed.
  - **Uploaded, binary `.evtx`**: a genuinely binary Windows Event Log
    file is now also accepted by the same Upload Log button (it sniffs
    the file's own magic bytes first). New module `modules/evtx_review.py`
    walks the real EVTX container format (file header → 64KB chunks →
    24-byte record headers) with plain `struct` unpacking — no new
    dependency — to get an accurate record count and time range, plus a
    best-effort scan for human-readable text (usernames, IPs) embedded
    in each record for manual review. Deliberately does **not** attempt
    to decode the binary-XML event content or judge severity from it
    (that would need a full binary-XML token decoder, and an unreliable
    guess is worse than an honest "basic read only, export to text for
    the full check" — the same "basic X, honest about scope" approach
    `pcap_review.py` already uses for packet captures).
- **Added: "View System Logs" now surfaces what's actually worth
  reading, not just a raw dump.** It now runs the same brute-force /
  successful-login-after-brute-force analysis against whichever
  Linux log files (or Windows Event Log channels) it's about to show,
  and puts a source-labeled, severity-sorted "WORTH A LOOK" summary at
  the top of the window — so spotting what matters doesn't mean
  scrolling through every log file by eye. Says plainly when nothing
  matched, rather than showing an empty summary section. This is a
  read-only display aid only; it never writes to `findings.jsonl` —
  `check()`'s own live scan already does that.
### Added — Remote setup now installs its own missing dependency, instead of stopping to ask for it
Direct follow-up to "we was able to get it to work with Harbinger... what's
the point of even having SSH" — a fair question: Setup already has a shell
on the remote target the moment it connects, so a missing Python package
there should be something it just fixes, not something it stops and asks a
person to go fix by hand in a second terminal.
- `modules/remote.py`'s `check_remote_dependencies()` — called once,
  right after deploying, to confirm the remote machine's own `python3`
  can actually `import psutil` — now **automatically runs `pip install
  psutil` on the remote machine over the very same SSH connection** the
  moment it finds that import missing, chaining four install strategies
  with a shell `||` so one single attempt covers the normal cases: a
  personal install (`--user`), a modern distro that blocks any
  system-wide `pip install` outside a virtualenv under PEP 668 (needs
  `--user --break-system-packages`), a root/admin shell (`--user`
  doesn't apply there), and that same PEP 668 case without `--user`. It
  then re-checks the import — not the install command's own exit code,
  which isn't a reliable signal once several attempts are chained — and
  only surfaces a message to the person at all if psutil is *still* not
  importable after genuinely trying, with the real `pip` output attached
  so the actual blocker (most often: no internet on an isolated
  competition box) is visible immediately, not a second "psutil missing"
  message with nothing new to act on.
  - **Follow-up, same round**: on a minimized-image practice VM, the
    pip-based install above still failed outright, because the image had
    no `pip` module at all (`python3 -m pip` itself errored with "No
    module named pip") - every pip-based strategy depends on pip already
    being importable, so none of them could get off the ground. Fixed
    two ways: the pip-based attempt now tries `ensurepip` first if plain
    `pip --version` doesn't work, to bootstrap pip back in where that is
    still possible; and if pip genuinely cannot be made to work at all,
    a password-auth target now falls back to installing the **distro's
    own pre-built psutil package** (`python3-psutil`) via `apt-get`,
    `dnf`, or `yum` - whichever is actually present - run as root
    through exactly ONE `sudo -S` prompt, answered by reusing the SAME
    password already typed in for the SSH login itself (sent over
    stdin, never as a command-line argument, never logged) - the same
    "ask once, reuse for sudo" approach the Shadow Watch/Harbinger tool
    this was compared against uses for its own root check. A key-based
    login has no password to safely reuse, so that one fallback step is
    simply skipped there, with a clear manual command in its place.
### Fixed — Remote scans were running fully unprivileged, so they missed almost everything
Bug report: "we're in. bad news. Its not reporting anything and there is
forsure crap all over this guy" — the Dashboard for a connected remote
target showed "(nothing to report)" across nearly every section (SSH
directory contents, evasive persistence, suspicious processes, C2
activity), while the Shadow Watch/Harbinger tool found extensive real
findings on that exact same box (malicious processes, root-owned
`/root/.ssh` keys, systemd persistence, beaconing IPs) — provided as the
reference (`orchestrator.py`) for what a working scan actually does.
- **Root cause, confirmed by reading `modules/remote.py`, `cli.py`, and
  `quickscan.py` directly**: Poltergeist's "deploy & run yourself" model
  copies the whole codebase to the target and runs it there as a plain
  background process — under whatever account logged in over SSH, with
  **no elevation anywhere in that path**. A LOCAL run already knows to
  warn "not root/Administrator - visibility will be limited" and the
  reference tool elevates with `sudo` for essentially everything that
  needs root, but nothing in `remote.py`'s actual scan dispatch
  (`--quickscan`, `--baseline`, `--oracle`, etc.) ever did the same. So
  checks that need root — reading `/root/.ssh` (`quickscan.py`'s own
  SSH-key check builds `home_dirs = ["/root"] + ...`), full process
  detail for processes owned by other users, some root-only files —
  silently came back empty. Not a parsing bug, not a detection-rule gap:
  the deployed scan was simply never allowed to look.
- **Fixed**: `modules/remote.py`'s `dispatch()` now elevates the actual
  remote command with `sudo -S -p ''` before running it, reusing the
  exact same password-reuse mechanism already built for the psutil
  auto-installer above (same "ask once, reuse it, send over stdin, never
  as a command-line argument or in any log" approach, directly modeled
  on the reference tool's own `start.py`) — gated the same way, on
  `auth_mode == "password"` with a password actually in hand. The whole
  existing command (python3 resolution, `cd` into the deployed folder,
  the real `poltergeist.py` call) is wrapped in a single `sh -c` so
  everything in it runs as root, not just the first word of it.
- **Added**: a one-time, honest check at Setup time
  (`_test_remote_elevation()`) that actually tries elevating and
  confirms it really became root — not just that `sudo` ran without
  erroring — and tells the person right away which case they're in:
  elevation confirmed and working, elevation attempted but the sudo
  password didn't actually work, or (for a key-file/agent-based login,
  which has no password to reuse at all) a plain explanation that scans
  on that target will run unprivileged unless that account is given
  passwordless (`NOPASSWD`) sudo. This is intentionally surfaced once,
  up front, instead of being discovered later as an unexplained empty
  Dashboard.
- **Worth knowing**: this elevates the scan process itself (read access
  everywhere, same as running locally with `sudo`/as Administrator) — it
  never runs a destructive command as root, consistent with this
  project's one hard rule that nothing it finds is ever auto-killed,
  deleted, or modified; every actionable finding still only ever
  *suggests* a command for a person to run themselves.
### Added — This round's feedback: one main Dashboard, native file pickers, log + pcap upload
Direct answers to this round's feedback ("I don't want that mess of log
crap, I just want the dashboard that covers the big things... with
everything listed like that example with color code to help identify
stuff fast," plus the SSH-login, directory-picker, and log/pcap-upload
asks):
- **The main window now opens on a Dashboard, not a scrolling findings
  log.** `gui/live_dashboard.py` is new: a fixed, color-coded set of
  sections — POTENTIAL MALICIOUS PROCESSES (+ live open ports),
  FILE INTEGRITY / ROOT DIRECTORY SCRUB, POTENTIAL C2 / SUSPICIOUS
  NETWORK ACTIVITY, POTENTIAL EVASIVE PERSISTENCE, TRIPWIRE, SSH
  DIRECTORY CONTENTS, and a catch-all OTHER ACTIVITY — deliberately
  mirroring the layout of the user's own Shadow Watch IOC-sweep screen.
  `findings.jsonl` is still an append-only history (the old web
  Dashboard and Scribe's report both still read the full thing), but
  `evidence.py`'s own `Log.add()` only de-dupes *within one run* — so an
  unchanged condition gets re-logged every scan cycle, which is the
  actual "wall of logs that just keeps updating" the feedback was
  reacting to. `live_dashboard.py`'s `latest_state()` fixes this at the
  *view* layer: it collapses the full history down to the single
  newest record per `(module, key)`, so the main screen always reads as
  "here is what's true right now," not "here is everything that has
  ever happened." `gui/findings_view.py` is no longer used for the main
  panel.
- **The window title and header now name the machine being watched**:
  `Poltergeist: <target label>` (or "this machine" with nothing
  configured), instead of a bare "POLTERGEIST" — set once at startup
  and live-updated the moment the setup wizard finishes with a new
  target.
- **Tripwire: Watch a Folder gets a real folder picker on a local
  target** — `filedialog.askdirectory()`, instead of typing a full path
  by hand — directly answering "a way where we can select directories
  on the current machine... to pick where to put the tripwires." A
  remote target keeps the original typed-path prompt (remote directory
  browsing is intentionally scoped to a later round), with an honest
  message saying so rather than pretending to browse something it
  can't reach. The setup wizard's own critical-paths page got the same
  "Browse and add a folder..." button for Sentinel's baseline paths.
- **View System Logs** (new button): shows the monitored machine's own
  real authentication log (`/var/log/auth.log` / `/var/log/secure`),
  tailed live, right in the window — the literal "look through logs of
  current machine" ask. Local target only for now; a remote target's
  brute-force findings still reach the Dashboard regardless, since the
  detection itself runs wherever quickscan runs.
- **Upload Log to Analyze** (new button) and **Upload PCAP to Analyze**
  (new button) — the "upload logs or pcaps to analyze" ask, both via a
  native file picker, both working against either target type (the
  file always comes from the analyst's own machine):
  - `modules/log_review.py` — regex-matches OpenSSH's own
    `Failed password` / `Accepted password|publickey` lines, counting
    failures per source IP. Flags a brute-force attempt at 5+ failures
    from one IP, and separately, more urgently, flags that same IP
    succeeding afterward. The exact same `analyze_lines()` core backs
    both a new LIVE module (`check()`, registered under module name
    `"logs"` — Linux only for now, Windows keeps login history in the
    Event Log, which needs a separate reading approach) and the Upload
    Log button's `analyze_uploaded_text()`.
  - `modules/pcap_review.py` — a **basic flow summary**, deliberately
    scoped to pure Python with no `tshark`/`scapy` dependency (a
    competition box may have no internet access to install one): reads
    the classic `.pcap` container format (not the newer `.pcapng`) and
    unwraps plain Ethernet + IPv4 + TCP/UDP frames (one level of 802.1Q
    VLAN tagging too) by hand with `struct`, grouping packets into
    flows by their full 5-tuple. Reports byte/packet totals and the
    biggest flows by data volume, plus two basic heuristics: a
    destination port matching a short list of well-known
    trojan/backdoor ports (4444, 31337, 1337, 6666/6667, 12345,
    54321), and one source IP touching a large number of distinct
    ports on the same destination (port-scan shape). Capped at 50,000
    packets per upload so a huge capture can't turn one click into a
    multi-minute hang.
  - `gui/dialogs.py` gained `show_scrollable_text()` — a resizable,
    read-only scrollable text window, used by both new buttons and by
    View System Logs, for anything too long for the existing fixed-size
    message popup.
- **A beacon-timing heuristic in `modules/network.py`**: tracks each
  outbound connection's own destination (`ip:port`, not PID — the
  implant process itself can be short-lived or respawn, but its C2
  endpoint doesn't move) across scans in a small persisted state file,
  and flags very regular check-in timing (coefficient of variation
  ≤ 0.2 across 4+ samples, each at least 2 seconds apart) as a probable
  C2 beacon — the "evasive... possible bad IP's (like C2's)" ask.
- **An evasive-persistence LIVE check in `modules/persistence.py`**
  (`check()`, registered under module name `"persistence"` alongside
  the existing baseline-diff `collect()` under the same key): flags a
  genuinely hidden (dot-prefixed, directory-discovered — see Fixed,
  below) file dropped into a startup location, and separately, scans
  every startup file's own content for dropper/reverse-shell patterns
  (`curl`/`wget` into a shell, a raw `/dev/tcp/` socket, `base64 -d`
  piped to a shell, `nc -e`, `bash -i`, `chattr +i`) and for a reference
  to an executable living somewhere abnormal (`/tmp/`, `/dev/shm/`,
  etc.) — the "evasive persistence" ask.
- **SSH key judgment calls in `quickscan.py`'s existing SSH listing**:
  flags a key file readable/writable by more than its owner (not just
  `0600`), and flags an `authorized_keys` entry restricted to a
  `command="..."` whose text matches the same dropper/reverse-shell
  pattern list `persistence.py` uses — "the ssh directory content to
  help identify bad keys."
### Fixed
- **False positive in the new `persistence.py` evasive-persistence
  check**: it flagged every single ordinary, universally-present
  per-user dotfile (`~/.bashrc`, `~/.profile`, `/root/.bashrc`, ...) as
  a "hidden file in an autostart location," because the hidden-file
  rule treated any dot-prefixed basename as suspicious regardless of
  whether `get_startup_locations()` had *walked a directory to find it*
  (genuinely suspicious) or *named that exact dotfile directly as one
  of its own fixed startup locations* (completely normal — these files
  are always dot-prefixed by convention). Fixed by checking, per
  location, whether it is itself a single named file rather than a
  directory to walk, and only flagging a dot-prefixed basename when it
  was discovered inside a walked directory.
### Changed — Stage 1 pivot: one target, not a fleet
This is a deliberate narrowing, not a feature cut: Fleet (many hosts at
once, over the system's own `ssh`/`scp`/`rsync`, never handling a
password) is replaced entirely by a single, more capable target concept
— one machine, local or remote, with full SSH auth support including a
password, and a simpler GUI built around watching it continuously.
- **One target, chosen in the wizard, every launch.** `config.py`'s new
  `target` key replaces the Fleet host list: `{"mode": "local"}`, or
  `{"mode": "remote", "host", "port", "user", "remote_path", "label",
  "auth_mode", "key_path"}`. `modules/fleet.py` is removed entirely;
  `modules/remote.py` replaces it, built on **paramiko** (new hard
  dependency, pure-Python, so no system SSH client requirement) instead
  of shelling out, specifically so it can support more than key-based
  login.
- **Three SSH auth modes**, not just "whatever's in `~/.ssh`": SSH
  agent/default key (the old Fleet behavior), a specific key file with
  an optional passphrase, or plain username+password — for a box only
  reachable that way. A password or passphrase typed into the wizard is
  held in an in-memory `secret` dict for that run only; it is **never**
  written to `config.json`, a log, or anywhere else on disk, and must be
  re-typed every launch. Fixed a real bug found while testing this: the
  passphrase-needed-retry path (in both the CLI and GUI wizards) could
  never actually fire, because `remote.py`'s `deploy_to_target()`/
  `push_remote_config()` returned a bare `bool` on failure, discarding
  the descriptive error text the retry check depends on finding the
  word "passphrase" in. Both now return `(bool, reason_or_None)`.
- **The setup wizard runs on every launch**, not just the first one —
  "a clean restart every time," with every question defaulting to
  whatever was already saved, so reconfirming an unchanged setup is just
  pressing Enter/Next through everything. The GUI wizard grew a page for
  picking the target and its auth mode, with a live "Connecting..."
  view and the same passphrase-retry flow as the CLI.
- **The baseline locks.** `exorcise.is_baseline_locked()`/
  `reset_baseline()` are new: once Sentinel: Baseline succeeds, neither
  front end will retake it until `reset_baseline()` is called — moving
  (never deleting) the old one to `evidence/baseline_history/`. Both
  front ends require typing `RESET` first, the same friction Shield:
  MUTE already used. `cli.py`'s menu option 2 and the GUI's one shared
  button slot both flip between "Sentinel: Baseline" and "Reset
  Baseline" live, depending on this one check.
- **`cli.py`'s `run_action()`** is new: the single place both the text
  menu and the GUI now dispatch any action from. It decides local vs.
  remote and enforces the baseline lock in exactly one place, so neither
  front end can duplicate (or drift out of sync with) either rule.
- **The GUI's main window is now continuously, ambiently refreshed.**
  The old "Sentinel: Monitor" Start/Stop toggle and its backing
  `MonitorController` class are both removed; `gui/app.py`'s own poll
  loop now re-runs a full scan on a timer by itself for as long as the
  window is open, showing a live countdown in the status bar, and
  `gui/console.py` goes back to having exactly one kind of background
  action (one-shot, whether started by a click or by that timer).
- **Strict black-and-white GUI theme**, replacing the gothic-violet one:
  every `theme.py` palette value is now a pure gray, with the one
  destructive-action button style shown as inverted video (solid white
  fill, black text) instead of a color accent, preserving the findings
  table's HIGH > MEDIUM > INFO brightness ordering in pure grayscale.
- **The original braille-art ghost banner is back in the GUI header**,
  replacing the hand-drawn vector Canvas ghost (`gui/ghost.py`, now
  removed entirely) — both front ends now show the literal same
  `GHOST_BANNER` text, defined once in `cli.py`.
### Added
- `suggested_fix` on every finding: a safe, non-destructive review/pause/block
  command printed with the finding — `Log.add()` never acts on it itself.
- `role_profiles.py` — the wizard now asks what kind of machine this is
  (web server, DB, Domain Controller...) and tailors its suggestions.
- `modules/packages.py` — installed package name+version baseline (the
  "lockfile" idea), diffed the same way as every other state module.
- `modules/logging_health.py` — logging service status AND log-file
  shrink detection (catches a cleared auth.log/syslog), with an honest
  "could not determine" finding instead of going silent when systemd
  itself isn't available to query.
- `modules/tripwire.py` — watch any one folder on the fly, mid-competition,
  without re-running the whole Sentinel baseline.
- `modules/oracle.py` + `data/cve_hints.json` — service banner grabbing
  and installed-package version checking against a small offline CVE hint
  list (refresh before a real competition; this cannot reach the internet).
- `modules/lockdown.py` — plain-English Shield rule parser (`block ip ...`,
  `block port ...`) on top of the existing MUTE command.
- `modules/snapshot.py` — best-effort VSS (Windows) / LVM (Linux) whole-volume
  snapshot; folder-level revert is scaffolded with clear TODOs, not wired up yet.
- `report.py` — the Scribe: turns findings.jsonl into a Markdown incident report.
- `dashboard.py` — localhost-only, auto-refreshing live findings web page,
  built on the standard library only (no new dependency).
- `quickscan.py` — one-command combined report (processes, network,
  logging, SSH key listing) in the style of a Harbinger IOC scan.
- `color.py` — small ANSI color helper for severity-coded output, respects
  `NO_COLOR` and only activates on a real terminal.
- `help_text.py` — in-app glossary explaining every cutesy module name
  in plain English.
- Matching CLI flags for every new feature: `--quickscan`, `--watch`,
  `--shield`, `--oracle`, `--snapshot`, `--report`, `--dashboard`, `--glossary`.
- `modules/fleet.py` — SSH-based multi-host management ("Fleet"): remember
  other hosts you're defending (`add_host`/`remove_host`), deploy this
  whole install to them (`rsync`, falling back to `scp -r`), trigger
  `--baseline`/`--check` on all of them remotely, and pull each one's
  `findings.jsonl` back into `evidence/fleet/<label>/`. Every function
  shells out to the system's own `ssh`/`scp`/`rsync` with `BatchMode=yes`
  (fail fast instead of a password prompt this tool must never show),
  `ConnectTimeout=10`, and `StrictHostKeyChecking=accept-new` — it never
  sees or handles a password itself. New menu section (options 15-21) and
  flags: `--fleet-add`, `--fleet-remove`, `--fleet-list`, `--fleet-deploy`,
  `--fleet-baseline`, `--fleet-check`, `--fleet-pull`.
- `dashboard.py` now **auto-starts in the background** (daemon thread) the
  moment the interactive menu loads, right after the config is ready —
  its link prints immediately, before the menu even appears, instead of
  needing a separate manual step. Its page-builder and menu option 14
  both re-read the config fresh on every request/click, so re-running the
  setup wizard mid-session (which can change `evidence_dir`) is reflected
  immediately rather than silently serving stale data.
- `dashboard.py` and `report.py` both now fold in every Fleet host's
  pulled-down findings alongside this machine's own — tagged by host,
  merged and sorted by time on the Dashboard, and labeled `module@host`
  (local findings keep their plain, untagged form) with a host summary
  line in the Scribe's report.
- **A real desktop GUI (`gui/`), now the default way Poltergeist launches**,
  replacing the text menu as the first thing you see (the text menu is
  still there in full — see `--text` below). Built on Tkinter (standard
  library; still zero new dependencies) with a dark, gothic visual theme
  and a hand-drawn (not image-asset) vector ghost mascot, deliberately
  asymmetric so it reads as unsettling rather than cartoony:
  - `menu_actions.py` — one shared list of every action (key, group,
    label, tooltip, what input it needs) that both the GUI's buttons and
    a future front end can read, so the feature set itself lives in
    exactly one place.
  - `gui/wizard.py` — the setup wizard as six clickable pages (welcome,
    networks, ports, thresholds, role, critical paths) instead of typed
    CLI prompts; same discovery-backed defaults as before.
  - `gui/app.py` — the main window: a scrollable button panel grouped
    the same way the text menu numbers them, a live findings table, and
    an output console pane, all polled from one `root.after()` loop so
    nothing ever touches a widget from a background thread.
  - `gui/theme.py` — the color palette, font fallback logic, `ttk`
    styling, and a custom hover-tooltip widget used on every button.
  - `gui/ghost.py` — the mascot's geometry as pure, testable coordinate
    math, kept separate from drawing.
  - `gui/console.py` — `BackgroundRunner` (one action at a time, matching
    the text menu's existing synchronous behavior, since backend modules
    share mutable state files that were never built for concurrent
    access) and `MonitorController` (an event-based start/stop for
    Sentinel: Monitor, since a GUI has no Ctrl+C).
  - `gui/findings_view.py` and `gui/dialogs.py` — the live findings table
    (merges local + Fleet findings, same as the Dashboard) and themed
    confirm/prompt/message popups, replacing Tkinter's plain gray
    defaults (Shield: MUTE still requires typing the word `MUTE`, not
    just a click).
  - New flags: `--gui` (explicit alias for the default) and `--text`
    (force the original text menu — the right choice for a headless box,
    an SSH session, or anyone who just prefers it). If Tkinter isn't
    installed, `cli.py` catches that on its own, prints one line saying
    so, and falls back to the text menu automatically; it never tries to
    half-start a broken window. Fleet's own remote `--baseline`/`--check`
    calls never reach this decision at all, since they exit on their own
    flag before the GUI-vs-text branch is reached.
### Fixed
- `gui/console.py`'s `ConsoleRedirect` (the file-like object swapped in
  as `sys.stdout` while a GUI-driven action runs) had no `isatty()`
  method. `color.py`'s `colorize()` — called on nearly every line
  `evidence.py`'s `Log.add()` prints, i.e. almost all GUI output — checks
  `sys.stdout.isatty()` before deciding whether to colorize, so the very
  first colorized line in any GUI-run action raised `AttributeError` and
  aborted it, surfacing as a traceback dumped into the console pane
  instead of real results. Added `isatty() -> False`, which fixes the
  crash and is also simply correct: this is a queue-backed window pane,
  not a real terminal, and a Tkinter `Text` widget doesn't interpret ANSI
  codes anyway, so this also stops raw `\x1b[...]` escape sequences from
  showing up as literal garbage around severity labels in the console
  pane.

## [0.1.0] - unreleased
### Added
- Initial project scaffold: `poltergeist.py` launcher, `poltergeist/` package.
- `config.py` — load/save/default settings.
- `discovery.py` — probes interfaces, subnets, VPN ranges, gateway, listening ports.
- `evidence.py` — `Log` class, findings.jsonl, process capture, file quarantine.
- State modules: `persistence.py`, `users.py`, `integrity.py` (persistence has
  Windows-side TODOs: schtasks, registry Run keys, services, systemd timers).
- Live modules: `processes.py`, `network.py`.
- `deception.py` — canary/honeytoken file planting and access detection.
- `lockdown.py` — firewall "mute" command and isolation watchdog (manual trigger).
- `exorcise.py` — baseline snapshot + diff-and-restore with mandatory quarantine.
- `cli.py` — interactive wizard + menu + argparse entrypoint.
- Packaging: `requirements.txt`, `pyproject.toml`, `.gitignore`, `LICENSE`, `README.md`.
