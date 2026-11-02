#DESCRIPTION: This file is the GUI's main window - the single place that
#             ties the gothic monochrome theme, the braille ghost banner
#             (the exact same art the text menu prints, imported from
#             cli.py so there is only ever ONE copy of it), the clickable
#             wizard, the button panel, and the live findings table/output
#             console all together into one actual application.
#             launch_gui() at the very bottom is the one function the
#             rest of the project calls to try starting the GUI at all;
#             everything above it only runs once that's already been
#             attempted. This file is also the one place in the whole
#             gui/ package that's allowed to import tkinter at the very
#             top - that's deliberate, since importing THIS file is
#             exactly the moment poltergeist.gui.__init__.launch_gui()
#             finds out whether Tkinter is even available on this machine.
#
#             Stage 1 pivot note: there is now only ONE target (local or
#             a single remote machine over SSH, chosen in the wizard) and
#             NO separate "Sentinel: Monitor" toggle button - this window
#             keeps itself continuously, ambiently refreshed on its own
#             timer instead (see _poll_loop below), the same way the text
#             menu's own --monitor loop would, just with no Ctrl+C needed
#             since closing the window is the "stop" here. Every button
#             click (and every ambient auto-scan pass) is dispatched
#             through cli.py's run_action() - the SAME function the text
#             menu's own numbered choices call - so a button here and a
#             text-menu choice always do exactly the same thing, with no
#             separate copy of "how do I run Oracle" living in this file.

#import tkinter and ttk for the actual window and every widget in it.
import tkinter as tk
from tkinter import ttk, filedialog

#import queue and webbrowser: queue backs the thread-safe console output
#pipe (console.py builds on top of it); webbrowser is only used by the
#one "Open Dashboard in Browser" action.
import queue
import webbrowser
#import traceback so _poll_loop's own never-fails wrapper (see its
#comment) can print a full traceback for anything that goes wrong
#inside one tick, without that exception ever being allowed to stop
#the recurring loop itself.
import traceback

#import os so "View System Logs" can check whether a given auth log
#path actually exists before trying to read it.
import os
#import sys/ctypes for the Windows-only AppUserModelID fix right below.
import sys
import ctypes

#On Windows, tell the OS this process is its OWN distinct application,
#BEFORE the very first Tk window is ever created. Without this, Windows
#groups any Python-launched GUI under python.exe's/pythonw.exe's own
#taskbar identity, which is why the real bug report looked like "the
#titlebar icon is right, but the TASKBAR icon is still the plain default
#Python logo" - setting the window's own icon via root.iconphoto() (see
#_apply_icon() below) only ever controlled the titlebar; Windows was
#still pulling the taskbar button's icon from python.exe itself, because
#as far as Windows' own taskbar grouping was concerned, this process WAS
#python.exe, not "Poltergeist." This has to run at import time, this
#early, specifically because it only has any effect if it happens before
#Tk (or anything else) creates the first actual window - setting it any
#later, even first thing inside App.__init__(), is too late once a
#window already exists. The string itself is just an arbitrary, unique
#identifier - it is never shown anywhere, it just needs to be
#consistent and not collide with some other installed application's own.
if sys.platform == "win32":
    try:
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
            "Poltergeist.SecurityAuditTool.GUI.1")
    #If this ever fails (an unusual/very old Windows build, a restricted
    #environment, etc.), the window still works fine - it just falls
    #back to showing the generic Python taskbar icon, exactly like
    #before this fix. Never let this stop the GUI from starting.
    except Exception:
        pass

#import this project's own GUI building blocks. Each one is documented
#in its own file; this file's job is only to wire them together.
from . import theme
from . import dialogs
from . import wizard as wizard_module
from . import icon as icon_module
from . import notify_sound
from .live_dashboard import DashboardView, get_active_high_severity_keys
from .console import BackgroundRunner, drain_queue

#import the new interactive folder browser and log viewer dialogs -
#folder_browser.browse_for_folder() replaces the old split between a
#native local-only picker and a remote typed-path prompt for Tripwire's
#"Watch a Folder" (see _on_action_click's own "folder" branch below);
#log_viewer.view_logs() replaces the old local-only, dump-everything
#_handle_view_logs() entirely (see that method's own replacement below).
#Both work identically for a local or a remote target - this file is
#the one place that decides WHICH real listing/read function each one
#gets handed, never either dialog file itself.
from . import folder_browser
from . import log_viewer

#import the shared action metadata - the one list every button in the
#panel below is built from.
from .. import menu_actions

#import the config functions this file needs directly.
#DASHBOARD_PORT is THIS instance's own web Dashboard port (8765 for the
#first running instance, 8766 for a second simultaneous one, and so on -
#see config.py's own _select_instance_paths() for the full reasoning).
#Every place in this file that used to hardcode "8765" now reads this.
from ..config import load_config, config_exists, DASHBOARD_PORT

#import GHOST_BANNER (the one, canonical braille-art ghost, typed once in
#cli.py and printed by the text menu) and run_action (THE single place
#both front ends dispatch any action from - it already knows how to pick
#local vs. remote, and already enforces the baseline lock) straight from
#cli.py. Nothing in cli.py imports this gui package back, so this stays a
#one-way dependency, not a circular one.
from ..cli import GHOST_BANNER, run_action

#import the version/copyright/URL pieces directly (rather than parsing
#cli.py's own VERSION_LINE string back apart) so the GUI's version row
#below can split them into a plain part and a separate clickable part.
from .. import __version__, __copyright__, __url__

#import the tripwire module directly (not through run_action) so this
#file can read the CURRENT list of watched folders itself - needed both
#to show the person which folder(s) they can pick from when stopping one,
#and to refuse opening the "watch a new folder" picker at all once
#MAX_WATCHED_PATHS is already reached, rather than letting them pick a
#folder only to have it rejected afterward.
from ..modules import tripwire

#import the deception module directly for the exact same reason -
#Canary's own "choose a bait location"/"stop seeding a location" actions
#need this file to read the CURRENT list of seeded folders itself.
from ..modules import deception

#import fs_browse and remote directly - fs_browse.list_directory() backs
#the new folder browser for a LOCAL target, and remote.list_remote_
#directory()/list_remote_logs()/read_remote_log() back it (and the new
#log viewer) for a REMOTE one, both over the exact same SSH connection
#every other remote feature already uses. See fs_browse.py's and
#remote.py's own top comments for the full "deploy & run as self"
#reasoning behind why this always shows the TARGET's own real folders/
#logs, never the analyst's own machine's.
from ..modules import fs_browse
from ..modules import remote

#import is_baseline_locked directly - the one piece of live state this
#file needs to decide whether the "Sentinel: Baseline" button is
#currently clickable. reset_baseline is imported alongside it: there is
#no more standalone "Reset Baseline" button (see _on_setup_clicked's own
#comment below for why) - this file now calls reset_baseline() directly,
#automatically, instead of going through run_action("baseline_reset").
from ..exorcise import is_baseline_locked, reset_baseline

#import report directly, so _on_close below can write a final incident
#report automatically on the way out, the same way cli.py's own
#run_action("scribe") does - no need to go through run_action() for this
#one either, since it is always local/in-process, never dispatched to a
#remote target (see report.py's own module docstring for why).
from .. import report

#import the dashboard module, so the background web server can be
#started the moment a config exists.
from .. import dashboard

#import log_review directly (not through cli.py's run_action()) for the
#same reason dashboard_open is handled directly below: "View System
#Logs" and "Upload Log to Analyze" are both GUI-only conveniences, not
#backend actions the text menu or a remote target need a generic
#dispatch path for. evtx_review is the sibling module that handles a
#genuinely BINARY Windows Event Log (.evtx) upload - see its own top
#comment - which _handle_upload_log below routes to by sniffing the
#uploaded bytes' own file magic.
from ..modules import log_review, pcap_review, evtx_review

#import evidence.Log directly so "Upload Log to Analyze" can log its
#findings through the exact same shared findings.jsonl every other
#module writes to, without needing a full run_action() call for it.
from ..evidence import Log


#Define App, the class for the whole GUI application. Only one of these
#is ever created per run - launch_gui() at the bottom builds one and
#calls its run() method.
class App:
    #Define the constructor: build the window and show either the
    #wizard (no config yet) or the main panel (config already exists).
    def __init__(self):
        #Build the root window itself.
        self.root = tk.Tk()
        #Give the window its title, shown in the OS title bar/taskbar.
        self.root.title("Poltergeist")
        #Start at a comfortably large size, but let the person resize
        #freely in either direction down to something still usable.
        self.root.geometry("1200x780")
        self.root.minsize(960, 620)
        #Apply the gothic monochrome theme to this window and get back
        #the chosen font tuples, used throughout the rest of this class.
        self.fonts = theme.apply_theme(self.root)
        #Keep a short local name for the palette too, since almost every
        #widget built below needs to reference a color from it.
        self.palette = theme.PALETTE

        #Show the real ghost mascot (built entirely in code - see
        #gui/icon.py's own module docstring for why there is no bundled
        #image file) instead of Tk's own stock default icon, starting
        #from the very first frame this window ever draws - not just once
        #a target happens to be configured. No friendly name known yet,
        #so the (larger, taskbar-sized) icons fall back to plain ghost
        #too, same as the titlebar-sized one always does - see
        #_apply_icon() below once a real target name exists.
        self._icon_images = []
        self._apply_icon(friendly_name=None)

        #Build the one shared queue every background action's printed
        #output flows through on its way into the on-screen console pane.
        self.output_queue = queue.Queue()
        #Build the single-action-at-a-time background runner. There is
        #no separate MonitorController any more - the ambient auto-scan
        #pass below is just another zero-argument function handed to
        #this SAME runner, on a timer, instead of a second always-on
        #background thread of its own.
        self.runner = BackgroundRunner(self.output_queue)

        #This dict maps each menu_actions key to its actual ttk.Button
        #widget, filled in while the button panel is built, so later code
        #can enable/disable individual buttons without having to search
        #for them again.
        self._action_buttons = {}
        #The one dedicated frame the "Sentinel: Baseline" button lives
        #inside, so hiding it once locked never reshuffles anything else
        #in the panel - see _build_button_panel's own comment on this for
        #why a plain pack()/pack_forget() on the outer panel would not be
        #safe here. (There used to be a second, "Reset Baseline" button
        #sharing this same slot, shown instead of this one once locked -
        #that button is gone now, reset having moved to two automatic
        #places instead; see menu_actions.py's own comment on "baseline"
        #for where. This slot now simply shows the button while unlocked
        #and nothing at all once locked.)
        self._baseline_slot_frame = None
        #Remember which lock state the baseline slot was last drawn for,
        #so _poll_loop only touches it on an actual CHANGE, not every tick.
        self._last_lock_state = None
        #Remember the last busy state the poll loop saw, so it only
        #touches every OTHER button's enabled state on an actual change.
        self._last_busy_state = False
        #A simple tick counter so the findings table refreshes every ~2
        #seconds (a fixed number of 150ms poll ticks) instead of on every
        #single tick, which would be far more often than needed.
        self._findings_tick_counter = 0
        #--- New-critical-finding notification state (flash + ding) ---
        #See _check_for_new_critical_findings()/_start_icon_flash() below
        #for the full mechanism. None (not an empty set) is deliberate
        #here: it means "no baseline taken yet," so the very FIRST check
        #after a target is configured only records what's already active
        #rather than treating every pre-existing critical finding as
        #brand new and flashing/dinging immediately on open.
        self._seen_high_severity_keys = None
        self._flashing = False
        self._flash_job = None
        self._flash_showing_alert_frame = False
        #Stop flashing (and restore the normal icon) the moment this
        #window actually gets focus - clicking the taskbar entry is
        #exactly how a person "clicks it" to dismiss the flash, the same
        #behavior as a Teams/Slack taskbar flash, and this fires for a
        #direct click on the window too, not just via the taskbar.
        self.root.bind("<FocusIn>", self._on_window_focus_in)
        #How many milliseconds have accumulated toward the NEXT ambient
        #auto-scan pass, reset to zero every time one actually starts.
        #Only advances while idle, so a long-running manual action never
        #causes a scan to fire the instant it finishes just to "catch up".
        self._scan_accum_ms = 0
        #The background web Dashboard server, started the first moment a
        #config actually exists; None until then.
        self.dashboard_server = None
        #The active configuration dictionary. None until either an
        #existing config is loaded or the wizard finishes for the first
        #time - nothing below ever assumes this is already set.
        self.config = None
        #The in-memory-only secret for whatever target is currently
        #configured (a password or key passphrase for a remote target,
        #or simply {} for a local one). Exactly like the text menu's own
        #copy of this value, it is NEVER written to config.json, a log,
        #or anywhere else on disk - see modules/remote.py's own module
        #docstring for the full reasoning. It is only ever actually held
        #here for the lifetime of this one running window; closing the
        #window and reopening it means re-typing it, by design.
        self.secret = {}

        #Build the fixed header strip (ghost banner + title + Setup
        #button) at the very top of the window.
        self._build_header()
        #Build the status bar at the very bottom, BEFORE the resizable
        #main area below, so it claims the bottom edge of the window and
        #the main area fills everything left over above it.
        self._build_status_bar()
        #Build the one resizable container whose CONTENTS get swapped
        #between the wizard and the main action panel - everything in
        #this container gets destroyed and rebuilt on that one switch,
        #nothing elsewhere in the window does.
        self.main_container = ttk.Frame(self.root, style="TFrame")
        self.main_container.pack(fill="both", expand=True)

        #If a config from a previous run already exists, trust it and go
        #straight to the main action panel - no reason to make someone
        #re-click through the whole wizard just to re-confirm a target
        #they already set up last time. Only a genuinely first-ever run
        #(nothing saved yet) lands on the wizard. The wizard itself is
        #always still one click away via the "Setup / Edit Settings"
        #button on the main panel, for anyone who DOES want to change
        #something. (This was briefly changed to always show the wizard
        #on every launch, per earlier feedback - that was reverted after
        #direct follow-up feedback asking for this original behavior
        #back, so going forward this is the intended, final behavior.)
        if config_exists():
            self.config = load_config()
            #Every freshly launched instance starts with a clean baseline
            #lock, regardless of whatever was locked in the last time
            #this install was run - there is one baseline per RUNNING
            #instance now, not one tied to the saved config file, exactly
            #matching direct feedback: a new instance should already be
            #ready for a fresh "Sentinel: Baseline" click with no manual
            #"Reset Baseline" step needed first. This is silent and
            #automatic specifically because it happens before this window
            #has shown anything at all yet - there is nothing on screen
            #for a warning dialog to interrupt. (See _on_setup_clicked's
            #own comment below for the other place this same reset now
            #happens, WITH a warning, since that one DOES interrupt
            #something already on screen and possibly already running.)
            reset_baseline(self.config)
            #Show the right ghost/taskbar icon pair immediately for the
            #already-confirmed target, same as every other path that
            #ends up with a real config in hand.
            self._apply_icon(friendly_name=(self.config.get("target") or {}).get("label"))
            self._apply_target_title()
            self._start_dashboard_once()
            self._show_main_panel()
        else:
            self._show_wizard()

        #Treat the window's own close button the same as a clean exit.
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        #Kick off the recurring poll loop that drains console output,
        #keeps the baseline button in sync, runs the ambient auto-scan,
        #and refreshes the findings table - see _poll_loop() below.
        self.root.after(150, self._poll_loop)

    #Define run, the one method launch_gui() calls once the window is
    #fully built - this is what actually makes the window appear and
    #start responding to clicks, and it blocks until the window closes.
    def run(self):
        #Hand control to Tkinter's own event loop.
        self.root.mainloop()

    #--- Header ---

    #Define _build_header, the fixed strip across the top of the window:
    #the braille ghost banner, the "POLTERGEIST" title and tagline, a
    #small Help button, and the always-available Setup/Edit Settings
    #button.
    def _build_header(self):
        #Build the header's own frame, painted with the darkest
        #background color so the banner's glow stands out against it.
        header = tk.Frame(self.root, background=self.palette["bg"])
        header.pack(fill="x", side="top")
        #Show the exact same braille-art ghost the text menu prints,
        #imported straight from cli.py rather than kept as a second copy
        #here - a monospace font is required for braille cell art to line
        #up at all; a proportional font would stagger every row.
        ghost_label = tk.Label(header, text=GHOST_BANNER, font=self.fonts["mono_small"], justify="left",
                                background=self.palette["bg"], foreground=self.palette["glow"])
        ghost_label.pack(side="left", padx=(16, 10), pady=6)
        #Build a frame to hold the title and tagline, stacked vertically.
        title_block = tk.Frame(header, background=self.palette["bg"])
        title_block.pack(side="left", pady=10, anchor="w")
        #Build the big title itself. Its text gets rewritten by
        #_apply_target_title() below the instant a config exists, to
        #"POLTERGEIST: <target name>" - kept as a plain "POLTERGEIST" here
        #only as the fallback shown for the handful of frames before that
        #(there is no target to name yet on a first-ever launch, before
        #the wizard has saved anything). Keeping a reference to this one
        #widget is what lets _apply_target_title() update it in place
        #later, rather than rebuilding the whole header.
        self._target_title_label = tk.Label(title_block, text="POLTERGEIST", font=self.fonts["title"],
                                             background=self.palette["bg"], foreground=self.palette["glow"])
        self._target_title_label.pack(anchor="w")
        #Build the tagline underneath it, in the dimmer text color - split
        #across TWO Label widgets packed side by side in their own row,
        #rather than one Label with one string, specifically so "Blue
        #team" can be colored differently (theme.py's own "accent_blue")
        #from the rest of the sentence. A single tk.Label can only ever
        #have one foreground color for its whole text, so getting part of
        #one line to read in a different color needs two widgets lined up
        #next to each other instead - this is the one deliberate splash
        #of real color anywhere in this otherwise strict-monochrome GUI.
        tagline_row = tk.Frame(title_block, background=self.palette["bg"])
        tagline_row.pack(anchor="w")
        tk.Label(tagline_row, text="Blue team", font=self.fonts["subtitle"],
                 background=self.palette["bg"], foreground=self.palette["accent_blue"]).pack(side="left")
        tk.Label(tagline_row, text=" audit tool - never kills a process, never deletes evidence.",
                 font=self.fonts["subtitle"], background=self.palette["bg"],
                 foreground=self.palette["text_dim"]).pack(side="left")
        #Build the version/copyright row right under the tagline - same
        #two-widgets-side-by-side trick as tagline_row just above, since
        #the GitHub link part needs to be clickable (its own foreground
        #color, hand cursor, and a click handler) while the version and
        #copyright text in front of it is plain, dim, inert text.
        version_row = tk.Frame(title_block, background=self.palette["bg"])
        version_row.pack(anchor="w")
        tk.Label(version_row, text=f"v{__version__}  -  {__copyright__}  -  ", font=self.fonts["small"],
                 background=self.palette["bg"], foreground=self.palette["text_dim"]).pack(side="left")
        #__url__ is the full "https://github.com/..." form (needed to
        #actually open it); strip the scheme just for display, the same
        #way a browser's own address bar quietly does.
        #Kept as self._github_link_label (not a throwaway local) so a
        #test can reach it directly to confirm the click handler is wired
        #correctly, the same way self._mute_button is kept for its own
        #tests below.
        self._github_link_label = tk.Label(version_row, text=__url__.replace("https://", ""),
                                            font=self.fonts["small"], background=self.palette["bg"],
                                            foreground=self.palette["accent_blue"], cursor="hand2")
        self._github_link_label.pack(side="left")
        #Open the real URL in the system's default browser on click - the
        #exact same webbrowser.open() call dashboard_open's own button
        #already uses, just bound to a label instead of a ttk.Button so
        #it reads as a plain inline link rather than a button sitting in
        #the middle of a sentence.
        self._github_link_label.bind("<Button-1>", lambda event: webbrowser.open(__url__))
        #Build a frame on the far right for the header's two buttons.
        button_block = tk.Frame(header, background=self.palette["bg"])
        button_block.pack(side="right", padx=16, pady=10, anchor="n")
        #The Help button opens the full plain-English glossary, for
        #anyone who wants to read every description at once instead of
        #hovering over each button one at a time.
        help_button = ttk.Button(button_block, text="Help", command=self._show_help)
        help_button.pack(side="right", padx=(8, 0))
        #The Setup button re-opens the wizard at any time, to edit
        #settings - it's deliberately NOT one of the grouped actions in
        #menu_actions.py, since it changes the GUI's own view instead of
        #calling a backend check/action.
        setup_button = ttk.Button(button_block, text="Setup / Edit Settings", command=self._on_setup_clicked)
        setup_button.pack(side="right")
        #The "Mute Dings" toggle - mutes ONLY the sound a brand-new
        #CRITICAL (high-severity) finding plays (see notify_sound.py and
        #_check_for_new_critical_findings() below); the taskbar icon
        #still flashes either way, since the point of muting is "stop
        #making noise," not "stop telling me at all." Kept as its own
        #button (not folded into Setup) since it's something a person
        #reasonably wants to flip quickly, mid-session, without opening
        #a whole settings flow - session-only (not written to config.py),
        #same as every other purely-visual GUI preference in this file.
        self._dings_muted = False
        self._mute_button = ttk.Button(button_block, text="Mute Dings", command=self._on_mute_dings_clicked)
        self._mute_button.pack(side="right", padx=(0, 8))

    #Define _apply_icon, which (re)builds and applies the window/titlebar/
    #taskbar icon pair for whichever friendly_name names (the exact
    #string from config["target"]["label"] - "sent1", "DC01", whatever
    #the wizard's own label field held - or None for "not known yet").
    #Called once in __init__ with friendly_name=None (before any target
    #is confirmed) and again from _on_wizard_complete below, once the
    #just-confirmed target's real friendly name is known.
    def _apply_icon(self, friendly_name):
        #Remember this for _flash_tick() below, which needs to rebuild
        #BOTH the normal and inverted icon sets on demand without every
        #caller having to thread friendly_name through it separately.
        self._current_friendly_name = friendly_name
        #Build the icon at a few sizes at once - root.iconphoto() picks
        #whichever fits best for a given context, which (per gui/icon.py's
        #own module docstring) is also what lets the SMALLEST size stay
        #plain-ghost (titlebar) while the larger ones carry the new
        #ghost+slash+name taskbar design, at least on Windows' own
        #titlebar-vs-taskbar icon-size convention.
        images = icon_module.build_icon_photoimages(friendly_name)
        #Keep a live reference to every PhotoImage for as long as this
        #window exists - Tkinter does NOT keep its own reference once
        #iconphoto() returns, so without this the icon would quietly
        #vanish (or raise) the next time Python's garbage collector runs.
        #Replacing (not appending to) the list is deliberate: the OLD
        #images are no longer referenced anywhere once this line runs,
        #and are safe to free, the moment a DIFFERENT target's OS gets
        #confirmed later in the same session.
        self._icon_images = images
        #True means "use this as the default icon for every toplevel
        #window this app creates" (every themed popup dialog included),
        #not just this one root window.
        self.root.iconphoto(True, *images)

    #--- New-critical-finding notification (flashing taskbar icon + ding) ---

    #Define _check_for_new_critical_findings, called once per poll tick
    #(from _poll_loop_tick, only once the main panel is actually showing)
    #to compare the CURRENT set of active high-severity ("CRITICAL" in
    #the Dashboard's own red-label sense) findings against what was active
    #last tick. Anything newly present starts the icon flashing and (if
    #not muted) plays the ding - anything that was already active before
    #this window even opened is deliberately NOT treated as new (see the
    #self._seen_high_severity_keys None-sentinel comment in __init__).
    def _check_for_new_critical_findings(self):
        current_keys = get_active_high_severity_keys(self.config)
        if self._seen_high_severity_keys is None:
            #First observation since this target was configured/opened -
            #this is the baseline, not a batch of brand-new findings.
            self._seen_high_severity_keys = current_keys
            return
        newly_critical = current_keys - self._seen_high_severity_keys
        self._seen_high_severity_keys = current_keys
        if not newly_critical:
            return
        #Something genuinely NEW just turned critical - alert, the same
        #way a new message would in a chat app: flash the taskbar icon
        #(until the window is clicked/focused) and, unless muted, play
        #the chime.
        self._start_icon_flash()
        if not self._dings_muted:
            #play_critical_ding() returns False if nothing on this box
            #could actually play it (see notify_sound.py's own comment) -
            #fall back to Tk's own plain system beep rather than the
            #person getting no audible alert at all.
            if not notify_sound.play_critical_ding():
                self.root.bell()

    #Define _start_icon_flash, which begins alternating the window's own
    #icon between its normal appearance and an inverted one on a fixed
    #timer - see gui/icon.py's own build_icon_photoimage() "invert"
    #parameter. This is the most PORTABLE way to get a visibly blinking
    #taskbar button: there is no single Tkinter API that flashes "the
    #taskbar entry specifically" the same way on both Windows and Linux
    #(Windows has a native FlashWindowEx call; most Linux desktops have
    #no equivalent exposed through Tk at all) - but swapping the window's
    #OWN icon on a timer works identically everywhere, since every
    #taskbar/panel shows whatever icon the window currently has.
    def _start_icon_flash(self):
        if self._flashing:
            #Already flashing (an earlier critical finding's flash is
            #still running) - let it continue rather than restarting the
            #blink rhythm from scratch.
            return
        self._flashing = True
        self._flash_showing_alert_frame = False
        self._flash_tick()

    #Define _flash_tick, the recurring half of the flash - toggles
    #between the normal and inverted icon once per call and reschedules
    #itself, until _stop_icon_flash() below sets self._flashing to False.
    def _flash_tick(self):
        if not self._flashing:
            #Stopped since this tick was scheduled (the window gained
            #focus in the meantime) - do nothing further.
            return
        self._flash_showing_alert_frame = not self._flash_showing_alert_frame
        images = icon_module.build_icon_photoimages(self._current_friendly_name,
                                                      invert=self._flash_showing_alert_frame)
        #Same "keep a live reference" requirement _apply_icon() follows -
        #overwriting self._icon_images here is safe for the identical
        #reason that one's own comment gives.
        self._icon_images = images
        self.root.iconphoto(True, *images)
        #Half a second per frame - fast enough to clearly read as
        #"blinking," slow enough not to look like a glitch.
        self._flash_job = self.root.after(500, self._flash_tick)

    #Define _stop_icon_flash, which ends the blink and restores the
    #icon's normal (non-inverted) appearance - called from
    #_on_window_focus_in below.
    def _stop_icon_flash(self):
        if not self._flashing:
            return
        self._flashing = False
        if self._flash_job is not None:
            self.root.after_cancel(self._flash_job)
            self._flash_job = None
        #Restore the plain, non-inverted icon right away rather than
        #waiting for whatever frame happened to be showing when the
        #window gained focus to just sit there.
        self._apply_icon(self._current_friendly_name)

    #Define _on_window_focus_in, bound to <FocusIn> in __init__ - this is
    #"the person clicked it" for the purposes of dismissing the flash,
    #whether that click landed on the taskbar entry or directly on the
    #window itself.
    def _on_window_focus_in(self, event=None):
        self._stop_icon_flash()

    #Define _apply_target_title, which makes both the OS window title
    #bar/taskbar AND the big header label read "Poltergeist: <name of
    #the machine currently being monitored>" - the user explicitly asked
    #for this ("At the top of the application Have it where its
    #Poltergeist: <name of current machine monitoring>"), so someone with
    #several of these windows open (or just glancing over at one) can
    #tell at a glance which box each one is actually watching, without
    #having to reopen Setup to check. Uses the exact same fallback logic
    #as cli.py's text-menu header, so both front ends always agree on
    #what a target is called: its own "label" if the wizard set one (the
    #remote wizard page always does), or "this machine" for the plain
    #local-target case, which has no label of its own to show.
    def _apply_target_title(self):
        #Nothing to show yet - leave the plain fallback title in place
        #(this only happens for the brief window before the wizard has
        #ever saved anything, on a first-ever launch).
        if not self.config:
            return
        #Work out the label the exact same way run_menu() does.
        target_label = (self.config.get("target") or {}).get("label") or "this machine"
        #Update the OS-level window title (title bar / taskbar entry).
        self.root.title(f"Poltergeist: {target_label}")
        #Update the big header label to match.
        self._target_title_label.configure(text=f"POLTERGEIST: {target_label}")

    #Define _on_mute_dings_clicked, the "Mute Dings" button's own handler -
    #just flips the one flag _check_for_new_critical_findings() below
    #checks before playing a sound, and updates the button's own label so
    #the current state is always visible at a glance (no separate
    #indicator anywhere else).
    def _on_mute_dings_clicked(self):
        self._dings_muted = not self._dings_muted
        self._mute_button.configure(text="Unmute Dings" if self._dings_muted else "Mute Dings")

    #Define _show_help, the Help button's handler.
    def _show_help(self):
        #Build one combined block of text, one paragraph per action,
        #reusing the exact same tooltip wording every button already
        #shows on hover, just all in one place at once.
        lines = ["Every action below only ever ALERTS and SUGGESTS. Nothing in Poltergeist",
                 "kills a process, deletes a file, or runs a suggested command by itself -",
                 "a human decides.\n"]
        #Walk every action in menu_actions.py, in its own defined order.
        for action in menu_actions.ACTIONS:
            #Add this action's label and its full tooltip description.
            lines.append(f"{action['label']}:\n  {action['tooltip']}\n")
        #Show it all as a genuinely scrollable, resizable window -
        #show_message() has no scrollbar at all, which is exactly what
        #cut the glossary off at "Oracle: Scan Services" before (the
        #list has grown since the ghost-emoji/icon and other requests
        #that followed only add more text). show_scrollable_text() is
        #the same widget "View System Logs" already uses for exactly
        #this reason - a real Text widget with a real scrollbar.
        #wrap="word" is deliberate here and differs from every other
        #caller of this same dialog: this text is plain-English prose
        #(tooltip descriptions), not raw log lines or file paths, so it
        #should wrap at the dialog's right edge like a normal paragraph
        #instead of running off it - which, with the default "none"
        #wrap and no horizontal scrollbar ever having been built for
        #this dialog, is exactly what was cutting every long
        #description off flush against the right edge (see the actual
        #report: "Oracle: Scan Services" line running off-screen).
        dialogs.show_scrollable_text(self.root, self.palette, self.fonts, "What does everything do?",
                                      "\n".join(lines), wrap="word")

    #--- Status bar ---

    #Define _build_status_bar, the thin strip pinned to the very bottom
    #of the window showing what's currently happening and a reminder
    #that the web Dashboard is also live.
    def _build_status_bar(self):
        #Build the bar's own frame, using the slightly-raised panel look
        #so it visually separates itself from the main content above it.
        bar = ttk.Frame(self.root, style="Raised.TFrame")
        bar.pack(fill="x", side="bottom")
        #Build the status text itself, updated by _set_status() below.
        self.status_label = ttk.Label(bar, text="Idle.", style="Dim.TLabel")
        self.status_label.pack(side="left", padx=10, pady=4)
        #Build the standing reminder that the web page is also available,
        #on the opposite side of the same bar.
        ttk.Label(bar, text=f"Web dashboard also live at http://127.0.0.1:{DASHBOARD_PORT}",
                  style="Dim.TLabel").pack(side="right", padx=10, pady=4)

    #Define _set_status, the one place the status label's text changes,
    #so every caller stays consistent instead of formatting its own text.
    def _set_status(self, text):
        #Update the status label's displayed text.
        self.status_label.configure(text=text)

    #--- Dashboard web server ---

    #Define _start_dashboard_once, which starts the background web
    #Dashboard server the first time a config actually exists, and does
    #nothing on any later call (it's called again defensively after the
    #wizard finishes, in case this is a first-ever run).
    def _start_dashboard_once(self):
        #Only start it if it isn't already running.
        if self.dashboard_server is None:
            #dashboard.start_background() takes no config argument at all
            #- its handler re-reads the config fresh from disk on every
            #single page request, so it never goes stale even if the
            #wizard changes evidence_dir later in this same session. It
            #DOES take this instance's own port, so two simultaneously
            #running instances never fight over the same one (see
            #DASHBOARD_PORT's own import comment above).
            self.dashboard_server = dashboard.start_background(DASHBOARD_PORT)

    #--- Wizard / main panel switching ---

    #Define _on_setup_clicked, the "Setup / Edit Settings" button's own
    #handler (replacing a direct command=self._show_wizard). Re-opening
    #Setup now ALWAYS resets the current baseline lock too, the same
    #reset_baseline() call __init__ above already makes automatically on
    #a fresh launch - there is only one baseline slot per RUNNING
    #instance, so re-confirming settings here (which might mean pointing
    #this same instance at a totally different machine) can never be
    #allowed to leave a stale "locked" baseline sitting there, silently
    #being compared against whatever is configured next. Direct feedback
    #asked for exactly this, PLUS a warning first (unlike the silent
    #launch-time reset above, this one interrupts something already on
    #screen, so it gets a dialog instead of happening invisibly) that
    #plainly says what is about to happen and what to do instead if the
    #goal is actually to monitor an ADDITIONAL host without disturbing
    #this one: open a separate new instance of Poltergeist for that host,
    #rather than reusing this button on this one.
    def _on_setup_clicked(self):
        #Nothing configured yet at all (the very first, cold-start
        #wizard page, before anything has ever been saved) - there is no
        #baseline, no evidence_dir, nothing to warn about losing yet.
        #Just show the wizard directly, exactly like before this change.
        if self.config is None:
            self._show_wizard()
            return
        #A real config already exists - warn plainly before doing
        #anything, and let the person back out with Cancel.
        proceed = dialogs.confirm_yes_no(
            self.root, self.palette, self.fonts, "Setup / Edit Settings",
            "Opening Setup resets the current baseline lock, whether or "
            "not anything actually changes here - there is only one "
            "baseline per running instance.\n\n"
            "If you want to start monitoring another host WITHOUT losing "
            "this one's current baseline, open a separate new instance "
            "of Poltergeist for that host instead of using this button "
            "on this one.\n\n"
            "Click OK to continue and reset the baseline, or Cancel to "
            "back out and leave everything exactly as it is.",
            confirm_label="OK", cancel_label="Cancel", danger=True,
        )
        if not proceed:
            #The person backed out - leave the main panel exactly as it
            #was, with the current baseline (if any) still intact.
            return
        #Clear the lock - the exact same function the old standalone
        #"Reset Baseline" button used to call, just reached directly now
        #instead of through its own separate button+typed-RESET step;
        #the warning dialog just above is this flow's own confirmation.
        reset_baseline(self.config)
        #Now actually show the wizard, same as always.
        self._show_wizard()

    #Define _show_wizard, which clears the resizable main area and shows
    #the clickable setup wizard in it.
    def _show_wizard(self):
        #Destroy whatever is currently showing (either the main panel's
        #widgets, or nothing at all on the very first launch).
        for child in self.main_container.winfo_children():
            #Destroy this one child widget and everything inside it.
            child.destroy()
        #Forget every reference to a button/frame that just got destroyed
        #above. This matters because _poll_loop's busy-state sync (far
        #below) runs on EVERY tick, unconditionally, and loops over
        #self._action_buttons.values() to enable/disable them - it is not
        #gated on which screen is currently showing. Before this fix,
        #re-opening the wizard from the header's own "Setup / Edit
        #Settings" button (the exact thing re-running Setup after a fixed
        #target asks you to do) destroyed the button-panel widgets here
        #but left self._action_buttons still pointing at them. The moment
        #the wizard's own probe/deploy step then toggled self.runner.busy
        #(it runs on the same shared background runner as every other
        #action), that sync loop tried to call .state() on an already-
        #destroyed widget and raised _tkinter.TclError: "invalid command
        #name ...!button" - an UNCAUGHT exception inside a root.after()
        #callback, which means _poll_loop never reached its own final
        #self.root.after(150, self._poll_loop) call and so never ran
        #again for the rest of the session. The background scan/deploy
        #work kept running fine (it does not depend on _poll_loop at
        #all) - which is exactly why the real terminal kept showing
        #live progress - but the GUI's console pane and Dashboard view
        #are only ever repainted FROM INSIDE _poll_loop, so both froze
        #solid, looking indistinguishable from "nothing is happening."
        self._action_buttons = {}
        self._baseline_slot_frame = None
        self._last_lock_state = None
        #Build and show the wizard, wiring its completion callback to
        #_on_wizard_complete below, and seeding it with whatever is
        #already configured so re-running it is just pressing Next
        #through everything that has not changed.
        wizard_frame = wizard_module.WizardFrame(self.main_container, self.palette, self.fonts, self._on_wizard_complete,
                                                   previous_config=self.config)
        wizard_frame.pack(fill="both", expand=True)

    #Define _on_wizard_complete, called by the wizard once it has saved
    #a finished config. Takes BOTH the config and this run's in-memory
    #secret - see this file's own secret comment above for why that
    #second value matters and is never written anywhere.
    def _on_wizard_complete(self, config, secret):
        #Adopt the freshly saved config and secret as the active ones.
        self.config = config
        self.secret = secret
        #Show this (possibly brand-new, possibly just re-confirmed)
        #target's name in the title bar and header right away.
        self._apply_target_title()
        #Update the titlebar/taskbar icon pair to match this (possibly
        #brand-new, possibly just-changed) target's own friendly name -
        #the exact label just confirmed in the wizard, so switching
        #targets mid-session (or just re-confirming the same one) always
        #keeps the taskbar icon's own 3-letter tag in sync with whichever
        #machine this window is actually pointed at right now.
        self._apply_icon(friendly_name=(config.get("target") or {}).get("label"))
        #Make sure the Dashboard is running now that we definitely have
        #a config (covers the very first run, where it wasn't yet).
        self._start_dashboard_once()
        #Reset the ambient-scan clock so switching targets (or just
        #re-confirming the same one) doesn't fire an immediate scan
        #against whatever partial progress the OLD target's clock had
        #already built up.
        self._scan_accum_ms = 0
        #Reset the critical-finding baseline too, for the exact same
        #reason: a DIFFERENT target's own pre-existing critical findings
        #should never be treated as "brand new" just because this window
        #switched to watching it - see this flag's own None-sentinel
        #comment in __init__. Also stop any flash left over from the
        #PREVIOUS target, since it no longer means anything once the
        #window has moved on to a different machine.
        self._seen_high_severity_keys = None
        self._stop_icon_flash()
        #Swap over to the normal action panel.
        self._show_main_panel()

    #Define _show_main_panel, which clears the resizable main area and
    #builds the real working view: the button panel on the left, the
    #live findings table and output console stacked on the right.
    def _show_main_panel(self):
        #Destroy whatever is currently showing (the wizard, most likely).
        for child in self.main_container.winfo_children():
            #Destroy this one child widget and everything inside it.
            child.destroy()
        #Reset the button-tracking state, since the old buttons (if any)
        #were just destroyed above.
        self._action_buttons = {}
        self._baseline_slot_frame = None
        self._last_lock_state = None

        #Build one horizontal splitter: the button panel on the left,
        #everything else on the right. A PanedWindow lets the person
        #drag the divider if they want more or less room for buttons.
        split = ttk.PanedWindow(self.main_container, orient="horizontal")
        split.pack(fill="both", expand=True)
        #Build and add the scrollable button panel.
        button_panel = self._build_button_panel(split)
        split.add(button_panel, weight=0)

        #Build a second, vertical splitter for the right-hand side:
        #the findings table on top (most of the space), the output
        #console pane below it (less space, but still resizable).
        right_split = ttk.PanedWindow(split, orient="vertical")
        split.add(right_split, weight=1)

        #Build the dashboard section: a heading label plus the colour-coded
        #card view itself. This REPLACES the old flat, chronological
        #findings table on the main screen - per this round's feedback
        #("I don't want that mess of log crap I just want the dashboard
        #that covers the big things") - with a fixed set of sections
        #showing only each thing's CURRENT state. The old full,
        #ever-growing history is deliberately still available: that's
        #exactly what the separate web Dashboard (started automatically,
        #see _start_dashboard_once below, and still reachable from the
        #"Open Web Dashboard" button) is for - see live_dashboard.py's
        #own module docstring for the full reasoning.
        dashboard_section = ttk.Frame(right_split, style="TFrame")
        ttk.Label(dashboard_section, text="Dashboard", style="Heading.TLabel").pack(anchor="w", padx=8, pady=(8, 2))
        self.dashboard_view = DashboardView(dashboard_section, self.palette, self.fonts)
        self.dashboard_view.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        right_split.add(dashboard_section, weight=3)

        #Build the console section: a heading label plus a read-only,
        #auto-scrolling text area showing whatever the currently-running
        #(or just-finished) action - manual OR ambient - has printed.
        console_section = ttk.Frame(right_split, style="TFrame")
        ttk.Label(console_section, text="Output", style="Heading.TLabel").pack(anchor="w", padx=8, pady=(8, 2))
        self.console_text = tk.Text(
            console_section, height=9, background=self.palette["bg"], foreground=self.palette["text"],
            insertbackground=self.palette["text"], font=self.fonts["mono_small"], wrap="word",
            borderwidth=0, highlightthickness=1, highlightbackground=self.palette["border"], state="disabled",
        )
        self.console_text.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        right_split.add(console_section, weight=1)

        #Show whatever findings already exist right away, instead of
        #waiting for the first poll tick to populate the dashboard.
        self.dashboard_view.refresh(self.config)

    #--- Button panel ---

    #Define _build_button_panel, which builds the scrollable list of
    #grouped action buttons on the left, each with a hover tooltip pulled
    #straight from menu_actions.py.
    def _build_button_panel(self, parent):
        #Build the outer frame this whole panel lives in.
        outer = ttk.Frame(parent, style="TFrame")
        #Build the canvas that makes the panel scrollable - this is the
        #standard Tkinter pattern for a scrollable area, since ttk has no
        #built-in scrollable frame of its own.
        canvas = tk.Canvas(outer, background=self.palette["panel"], highlightthickness=0, width=260)
        scrollbar = ttk.Scrollbar(outer, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        #Build the inner frame that actually holds every button - this is
        #what gets scrolled, via the canvas "window" below.
        inner = ttk.Frame(canvas, style="TFrame")
        inner_window_id = canvas.create_window((0, 0), window=inner, anchor="nw")

        #Define a small handler that keeps the canvas's scrollable region
        #in sync with however tall the inner frame actually ends up being
        #once every button and label has been packed into it.
        def _on_inner_resized(event):
            #Recompute the scrollable area to match the inner frame's
            #real, current bounding box.
            canvas.configure(scrollregion=canvas.bbox("all"))
        #Call that handler every time the inner frame's size changes.
        inner.bind("<Configure>", _on_inner_resized)

        #Define a small handler that keeps the inner frame exactly as
        #wide as the canvas itself, so buttons stretch to fill the panel
        #instead of staying a fixed width while the canvas resizes.
        def _on_canvas_resized(event):
            #Resize the inner window to match the canvas's new width.
            canvas.itemconfigure(inner_window_id, width=event.width)
        #Call that handler every time the canvas itself is resized.
        canvas.bind("<Configure>", _on_canvas_resized)

        #Define the mouse-wheel handler shared by both bindings below.
        def _on_mousewheel(event):
            #Wrapped in a try/except since this binding is intentionally
            #left active briefly after the mouse leaves (see _on_leave
            #below) and the canvas could, in rare timing, already be
            #gone (for example, if Setup/Edit Settings was clicked while
            #the mouse was still over this panel) - scrolling a destroyed
            #widget raises TclError, which we simply ignore here.
            try:
                #Windows and macOS report a signed "delta" in multiples
                #of 120; Linux's X11 instead sends separate Button-4
                #(wheel up) / Button-5 (wheel down) events with no delta
                #at all, so this same handler covers both by checking
                #which kind of event actually arrived.
                if hasattr(event, "delta") and event.delta:
                    #Scroll by whole "units" (rows), in the sign Windows/
                    #macOS actually use.
                    canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
                elif event.num == 4:
                    #X11 wheel-up event.
                    canvas.yview_scroll(-1, "units")
                elif event.num == 5:
                    #X11 wheel-down event.
                    canvas.yview_scroll(1, "units")
            #Ignore scrolling a widget that no longer exists.
            except tk.TclError:
                #Deliberately do nothing.
                pass

        #Only actually listen for mouse-wheel events while the pointer is
        #over THIS panel - binding globally for the whole app's lifetime
        #would otherwise hijack scrolling meant for the findings table or
        #the output console instead.
        def _on_enter(event):
            #Start listening for every flavor of wheel event, app-wide,
            #only while hovered - bind_all is required because Tkinter
            #delivers wheel events to whichever widget has focus, not
            #necessarily the one under the mouse.
            canvas.bind_all("<MouseWheel>", _on_mousewheel)
            canvas.bind_all("<Button-4>", _on_mousewheel)
            canvas.bind_all("<Button-5>", _on_mousewheel)

        #Define the matching handler that stops listening the instant the
        #mouse leaves this panel, so scrolling elsewhere behaves normally
        #again right away.
        def _on_leave(event):
            #Remove all three bindings put in place by _on_enter above.
            canvas.unbind_all("<MouseWheel>")
            canvas.unbind_all("<Button-4>")
            canvas.unbind_all("<Button-5>")

        #Wire both handlers to the OUTER frame (not the canvas alone), so
        #moving onto the scrollbar doesn't cause a spurious enter/leave.
        outer.bind("<Enter>", _on_enter)
        outer.bind("<Leave>", _on_leave)

        #Walk every group, in the fixed order menu_actions.GROUPS defines,
        #and build one heading plus one button per action underneath it.
        grouped_actions = menu_actions.get_actions_by_group()
        for group_name in menu_actions.GROUPS:
            #Build this group's own section heading.
            ttk.Label(inner, text=group_name, style="Heading.TLabel").pack(anchor="w", padx=10, pady=(16, 4), fill="x")
            #Build one button per action belonging to this group.
            for action in grouped_actions[group_name]:
                #"baseline" ("Sentinel: Baseline") gets its own dedicated
                #slot frame rather than being packed straight into "inner"
                #like every other button, because _poll_loop needs to be
                #able to hide it (once locked - see the class docstring
                #note at top of __init__) without that pack_forget()
                #moving some OTHER group's button up to fill the gap, and
                #without a later re-pack() shoving it down to the very
                #end of "inner"'s own packing order. (This slot used to
                #hold a SECOND button too - "Reset Baseline", shown in
                #place of this one once locked - that button is gone now;
                #see menu_actions.py's own comment on "baseline" for
                #where that reset moved to. The slot frame stays, just
                #with nothing to show in it while locked any more.)
                if action["key"] == "baseline":
                    #Build the dedicated slot frame the first time this
                    #key is encountered.
                    if self._baseline_slot_frame is None:
                        #Build it and pack it into "inner" exactly once,
                        #right where this group's one button would
                        #normally go.
                        self._baseline_slot_frame = ttk.Frame(inner, style="TFrame")
                        self._baseline_slot_frame.pack(fill="x")
                    #This button gets built as a child of the slot frame,
                    #not "inner" directly.
                    button_parent = self._baseline_slot_frame
                else:
                    #Every ordinary action is built straight into "inner",
                    #exactly as before.
                    button_parent = inner
                #Pick the inverted-video Danger style for any action
                #marked dangerous in menu_actions.py; every other button
                #uses the ordinary style.
                button_style = "Danger.TButton" if action["danger"] else "TButton"
                #Build the button itself. The default-argument trick
                #(key=action["key"]) is required here, not optional - without
                #it, every single button's command would close over the
                #SAME loop variable and all of them would end up calling
                #the action for whichever key the loop last landed on.
                button = ttk.Button(button_parent, text=action["label"], style=button_style,
                                     command=lambda key=action["key"]: self._on_action_click(key))
                #"Sentinel: Baseline" starts packed either way; the very
                #first _poll_loop tick immediately hides it if a baseline
                #is already locked (compared against self._last_lock_state,
                #which starts at None so that first comparison always
                #counts as "changed").
                button.pack(fill="x", padx=10, pady=3)
                #Attach this action's plain-English tooltip to the button.
                theme.Tooltip(button, action["tooltip"])
                #Remember this button so later code can enable/disable it.
                self._action_buttons[action["key"]] = button
        #Hand back the whole panel for the caller to add to its layout.
        return outer

    #--- Dispatching a button click to the real backend ---

    #Define _on_action_click, called by every button's command except
    #the header's Help/Setup buttons, which have their own direct handlers.
    def _on_action_click(self, key):
        #Refuse to start a second action while one is already running
        #(a manual click, or the ambient auto-scan itself - both share
        #this same runner, so this one check covers either case).
        if self.runner.busy:
            #Tell the person why nothing happened, rather than silently
            #ignoring their click.
            self._set_status("Still busy with another action - please wait.")
            #Do not proceed.
            return
        #Look up this action's full metadata.
        action = menu_actions.get_action(key)
        #"view_logs", "upload_log", and "upload_pcap" are handled
        #completely outside the background runner, unlike every other
        #action here (including "dashboard_open") - ALL THREE need to
        #pop a real Tkinter dialog (a scrollable log viewer, a native
        #file picker) partway through their own work, and Tkinter
        #widgets may only ever be touched from the main thread. The
        #background runner's whole job is running an action's CODE on a
        #separate thread so the window stays responsive during a slow
        #scan/deploy - exactly the thing that would corrupt or hang the
        #GUI if a dialog tried to open from inside it. All three finish
        #in well under a second anyway (one capped file read, one small
        #analysis pass), so running them synchronously, right here,
        #costs nothing a person would ever notice.
        if key == "view_logs":
            #Return early either way - this never touches self.runner.
            self._handle_view_logs()
            return
        if key == "upload_log":
            #Return early either way - this never touches self.runner.
            self._handle_upload_log()
            return
        if key == "upload_pcap":
            #Same reasoning as the two above - pops a native file picker
            #and a results dialog, so it must run synchronously on the
            #main thread.
            self._handle_upload_pcap()
            return
        #Refuse to even open the "pick a new folder" picker once
        #MAX_WATCHED_PATHS is already reached - tripwire.add_path() would
        #reject it anyway (see its own comment), but telling the person
        #BEFORE they go pick a folder (rather than after) is a much
        #friendlier failure, and costs nothing since this is a cheap,
        #local, non-blocking check either way (even for a remote target -
        #see pull_evidence()'s own comment on why tripwire_state.json is
        #synced back for exactly this reason).
        if key == "tripwire_add":
            watched_now = tripwire.load_state(self.config)["watched_paths"] if self.config else []
            if len(watched_now) >= tripwire.MAX_WATCHED_PATHS:
                dialogs.show_message(
                    self.root, self.palette, self.fonts, action["label"],
                    f"Already watching the maximum of {tripwire.MAX_WATCHED_PATHS} folders:\n\n"
                    + "\n".join(f"- {p}" for p in watched_now)
                    + "\n\nStop watching one first, or open a separate instance of "
                    "Poltergeist if you need to watch more at once.",
                )
                return
        #The exact same up-front cap check as tripwire_add just above,
        #for Canary's own bait-location list instead.
        if key == "canary_add":
            seeded_now = deception.load_state(self.config)["bait_folders"] if self.config else []
            if len(seeded_now) >= deception.MAX_CANARY_FOLDERS:
                dialogs.show_message(
                    self.root, self.palette, self.fonts, action["label"],
                    f"Already seeding the maximum of {deception.MAX_CANARY_FOLDERS} locations:\n\n"
                    + "\n".join(f"- {p}" for p in seeded_now)
                    + "\n\nStop seeding one first, or open a separate instance of "
                    "Poltergeist if you need to seed more at once.",
                )
                return
        #If this action needs a bit of typed input first, collect it now
        #(these dialogs block until answered, but that's fine - they run
        #on the main thread, before any background work has started).
        extra_input = None
        needs = action["needs_input"]
        if needs == "folder":
            #Browse the TARGET's own real filesystem interactively,
            #local or remote alike - the direct answer to "I want the
            #entire directory to be explored just like if we did it on
            #the host machine" for a remote target too, not just typing
            #a blind path. list_dir_fn is built differently for each
            #target mode, but folder_browser.browse_for_folder() itself
            #has no idea which kind it got - see that file's own top
            #comment for why that split is safe.
            target_mode = (self.config or {}).get("target", {}).get("mode", "local")
            if target_mode == "local":
                #Wrap modules/fs_browse.py's own list_directory(),
                #called straight in-process, into the (listing, error)
                #pair folder_browser.browse_for_folder() expects -
                #fs_browse.list_directory() itself never fails outright
                #(an unreadable folder comes back as a normal dictionary
                #with its own "error" key, not an exception), so the
                #error half of this pair is always None here.
                list_dir_fn = lambda path: (fs_browse.list_directory(path), None)
            else:
                #Wrap modules/remote.py's list_remote_directory() the
                #same way - it already returns exactly this (listing,
                #error) shape itself, running the SAME fs_browse.py code
                #over SSH on the remote target, so no further
                #translation is needed here at all.
                target = self.config.get("target") or {}
                list_dir_fn = lambda path: remote.list_remote_directory(self.config, target, self.secret, path)
            extra_input = folder_browser.browse_for_folder(
                self.root, self.palette, self.fonts, action["label"], list_dir_fn)
        elif needs == "rule":
            #Ask for one plain-English Shield rule.
            extra_input = dialogs.prompt_text(self.root, self.palette, self.fonts, action["label"],
                                               "Type a rule like:  block ip 10.0.0.5   or   block port 4444   or   allow ip 10.0.0.5")
        elif needs == "watched_folder":
            #"Tripwire: Stop Watching a Folder" picks an EXISTING item,
            #never types or browses to a new one - true for a remote
            #target too, since its own watched_paths come back locally
            #through pull_evidence() (see that function's own comment),
            #so there is nothing here that needs the "local vs. remote"
            #branch "folder" above has.
            watched_now = tripwire.load_state(self.config)["watched_paths"] if self.config else []
            if not watched_now:
                #Nothing to pick from - say so plainly instead of popping
                #an empty picker dialog.
                dialogs.show_message(self.root, self.palette, self.fonts, action["label"],
                                      "Not watching any folders right now.")
                return
            #Let the person pick exactly one of the (at most
            #MAX_WATCHED_PATHS) currently watched folders to stop watching.
            extra_input = dialogs.prompt_choice(
                self.root, self.palette, self.fonts, action["label"],
                "Which folder should Tripwire stop watching?", watched_now,
            )
        elif needs == "bait_folder":
            #"Canary: Stop Seeding a Location" picks an EXISTING item, the
            #exact same shape as "watched_folder" just above.
            seeded_now = deception.load_state(self.config)["bait_folders"] if self.config else []
            if not seeded_now:
                #Nothing to pick from - say so plainly instead of popping
                #an empty picker dialog.
                dialogs.show_message(self.root, self.palette, self.fonts, action["label"],
                                      "Not seeding any locations right now.")
                return
            #Let the person pick exactly one of the (at most
            #MAX_CANARY_FOLDERS) currently seeded locations to stop seeding.
            extra_input = dialogs.prompt_choice(
                self.root, self.palette, self.fonts, action["label"],
                "Which location should Canary stop seeding?", seeded_now,
            )
        elif needs == "revert_folder":
            #"Medium: Revert a Folder" needs BOTH a folder (browsed the
            #exact same way the plain "folder" branch above does - local
            #or remote target alike) AND a typed confirmation word,
            #since this is the one action in this whole project that
            #deliberately overwrites live files on purpose. Both steps
            #happen right here, before any background work starts,
            #exactly like "folder" and "typed_confirm" each do on their
            #own above - this just does both, in order, for one action.
            target_mode = (self.config or {}).get("target", {}).get("mode", "local")
            if target_mode == "local":
                list_dir_fn = lambda path: (fs_browse.list_directory(path), None)
            else:
                target = self.config.get("target") or {}
                list_dir_fn = lambda path: remote.list_remote_directory(self.config, target, self.secret, path)
            folder_to_revert = folder_browser.browse_for_folder(
                self.root, self.palette, self.fonts, action["label"], list_dir_fn)
            if not folder_to_revert:
                #The person backed out of the folder picker itself.
                return
            #Now ask for the typed RESTORE confirmation, the same
            #dialog shield_mute's own "typed_confirm" branch uses -
            #reusing the action's own tooltip as the warning text, same
            #as that branch does, rather than writing a second copy of
            #the same warning here.
            confirmed = dialogs.confirm_typed(
                self.root, self.palette, self.fonts, action["label"],
                f"This will OVERWRITE every file currently in:\n{folder_to_revert}\n\nwith whatever the "
                f"last snapshot held - anything changed in this folder since the snapshot was taken will "
                f"be LOST.\n\n{action['tooltip']}\n\nType {action['confirm_word']} to confirm.",
                action["confirm_word"],
            )
            #Only pass the folder through if the word was typed exactly
            #right - any other outcome means nothing should run at all.
            extra_input = folder_to_revert if confirmed else None
        elif needs == "typed_confirm":
            #Every danger action needing this (right now, only Shield:
            #MUTE) needs the exact word in menu_actions.py's own
            #"confirm_word" typed back, not just a click - this is
            #generic on purpose, so a future danger action needs no new
            #code here, only a new ACTIONS entry. The action's own
            #tooltip already carries the specific warning text, so it is
            #reused as the dialog's message rather than writing a second,
            #separate copy of that warning here.
            confirmed = dialogs.confirm_typed(
                self.root, self.palette, self.fonts, action["label"],
                f"{action['tooltip']}\n\nType {action['confirm_word']} to confirm.",
                action["confirm_word"],
            )
            #A typed_confirm action needs nothing further once confirmed -
            #represent "confirmed" as an empty but non-None marker,
            #distinct from a genuine cancel below.
            extra_input = "" if confirmed else None
        #For every needs_input kind above, None means the person cancelled
        #(closed the dialog, pressed Escape, or typed the wrong word) - in
        #every one of those cases, stop here and do nothing further.
        if needs is not None and extra_input is None:
            #The person backed out; there's nothing to run.
            return
        #"dashboard_open" is GUI-only (see menu_actions.py's own comment
        #on this key) - it never goes through run_action() at all, since
        #opening a browser tab means nothing to the text menu or a remote
        #target. Every other key is handed straight to run_action(), the
        #exact same dispatcher the text menu's own numbered choices call.
        if key == "dashboard_open":
            #Define the actual action: open the web dashboard in a browser.
            def _run_dashboard_open():
                #Open the already-running background Dashboard's URL - THIS
                #instance's own port, not necessarily 8765 (see
                #DASHBOARD_PORT's own import comment above).
                webbrowser.open(f"http://127.0.0.1:{DASHBOARD_PORT}")
                #Confirm in the console pane what just happened.
                print(f"  Opened http://127.0.0.1:{DASHBOARD_PORT} in your default browser.")
            #Hand back the function, not its result.
            action_fn = _run_dashboard_open
        else:
            #Capture config/secret/key/extra_input as default arguments
            #(not closed-over loop variables - there is no loop here, but
            #the same "capture now, not at call time" caution applies
            #since self.config/self.secret could, in principle, change
            #again before this background thread actually runs) so the
            #action runs against exactly the settings that were active
            #the moment this button was clicked.
            action_fn = lambda config=self.config, secret=self.secret, key=key, extra=extra_input: run_action(config, secret, key, extra)
        #Actually start the action on the background runner.
        started = self.runner.start(action_fn)
        #Update the status bar to reflect what's now running.
        if started:
            #Show which action is in progress.
            self._set_status(f"Running: {action['label']} ...")

    #Define _handle_view_logs, "View System Logs"'s own handler - the
    #literal "be able to pull the logs on that monitored machine even if
    #ssh'd in and be able to select the log you want to view and it
    #opens... it scans for the big things that could help you find
    #IOC's but also lets you go through them and look as well as a
    #search bar available" ask. Works for EITHER target now: builds the
    #(list_logs_fn, read_log_fn) pair log_viewer.view_logs() needs,
    #wrapping modules/log_review.py directly for a LOCAL target or
    #modules/remote.py's list_remote_logs()/read_remote_log() (which run
    #the exact same log_review.py code OVER SSH) for a remote one - the
    #new log_viewer.py dialog itself has no idea which kind it got. The
    #picker inside it already offers Windows Event Log channels when
    #the TARGET (not necessarily this analyst machine) is Windows, since
    #list_available_logs()/list_remote_logs() both branch on the
    #machine they actually run on, local or remote.
    def _handle_view_logs(self):
        #Nothing configured yet - should not normally be reachable (the
        #button only exists once the main panel is up), but check anyway
        #rather than assume.
        if not self.config:
            #Nothing to show.
            return
        target_mode = (self.config.get("target") or {}).get("mode", "local")
        if target_mode == "local":
            #Wrap modules/log_review.py's own two functions, called
            #straight in-process, into the (result, error) pairs
            #log_viewer.view_logs() expects - neither local function
            #ever fails outright (an unrecognized name comes back as a
            #normal dictionary with its own "error" key, not an
            #exception), so the error half of each pair is always None.
            list_logs_fn = lambda: (log_review.list_available_logs(), None)
            read_log_fn = lambda log_id: (log_review.read_log_content(log_id), None)
            dialog_title = "View System Logs (local target)"
        else:
            #Wrap modules/remote.py's own two functions instead - they
            #already return exactly this (result, error) shape, running
            #the SAME log_review.py code over SSH on the remote target.
            target = self.config.get("target") or {}
            list_logs_fn = lambda: remote.list_remote_logs(self.config, target, self.secret)
            read_log_fn = lambda log_id: remote.read_remote_log(self.config, target, self.secret, log_id)
            dialog_title = "View System Logs (remote target)"
        log_viewer.view_logs(self.root, self.palette, self.fonts, dialog_title, list_logs_fn, read_log_fn)

    #Define _handle_upload_log, "Upload Log to Analyze"'s own handler -
    #the other half of this round's "upload logs... to analyze... and if
    #its a windows enviroment... lets you upload winevents as well and it
    #analyzes those" ask. Works for EITHER target type, since the file
    #being analyzed always comes from the analyst's own machine (picked
    #here, in this native file dialog), never from the monitored target
    #at all. Reads the file as raw BYTES FIRST (not text) specifically so
    #it can sniff whether this is a genuinely binary Windows .evtx file
    #before deciding how to decode it at all - decoding an .evtx file as
    #text first would corrupt it beyond recovery.
    def _handle_upload_log(self):
        #Nothing configured yet - should not normally be reachable.
        if not self.config:
            #Nothing to do.
            return
        #Open a native file picker, starting wherever the OS thinks is
        #sensible. filetypes is a hint only - "All files" is still
        #offered, since a plain-text log is often saved with no
        #extension at all.
        chosen_path = filedialog.askopenfilename(
            parent=self.root, title="Select a log file to analyze (plain text, wevtutil export, or .evtx)",
            filetypes=[("Windows Event Log", "*.evtx"), ("Log files", "*.log;*.txt"), ("All files", "*.*")],
        )
        #An empty string means the person cancelled the picker.
        if not chosen_path:
            #Nothing to do.
            return
        #Read as raw bytes first - the only way to safely tell a binary
        #.evtx file apart from plain text BEFORE committing to a decode.
        try:
            with open(chosen_path, "rb") as uploaded_file:
                raw_bytes = uploaded_file.read()
        except Exception as exc:
            #Say plainly why nothing could be analyzed.
            dialogs.show_message(self.root, self.palette, self.fonts, "Upload Log to Analyze",
                                  f"Could not read that file: {exc}", kind="error")
            #Nothing else to do.
            return
        basename = os.path.basename(chosen_path)
        if evtx_review.looks_like_evtx(raw_bytes):
            #A genuinely binary Windows Event Log file - hand it to the
            #dedicated, honestly-scoped binary reader rather than the
            #text-based analyzer, which would see nothing but garbage.
            summary = evtx_review.analyze_uploaded_evtx(self.config, Log(self.config), basename, raw_bytes)
            lines = [f"Read {summary['record_count']} event record(s) from {basename}."]
            if summary["first_seen"] and summary["last_seen"]:
                lines.append(f"Time range: {summary['first_seen'].isoformat()} to {summary['last_seen'].isoformat()}")
            if summary["possible_ip_strings"]:
                lines.append("Possible IP address(es) found (unconfirmed which event/field they belong to): "
                              + ", ".join(summary["possible_ip_strings"][:30]))
            lines.append("\nThis is a BASIC structural read only - exact event IDs are not decoded from the "
                          "binary format. For a full brute-force-style check, export this log to text via "
                          "wevtutil ('/f:text') or PowerShell and upload that instead.")
            lines.append("\nAlso logged to findings.jsonl / the Dashboard, under the 'logs' module.")
            dialogs.show_scrollable_text(self.root, self.palette, self.fonts,
                                          "Upload Log to Analyze - Results", "\n".join(lines))
            #Nothing else to do.
            return
        #Not an .evtx file - decode as tolerant text (this could be any
        #log file from any machine, Linux plain-text or a wevtutil text
        #export, not necessarily one this install itself produced), same
        #tolerant-decode handling log_review.py's own read_tail_lines()
        #uses. log_review.analyze_uploaded_text() itself auto-detects
        #which of those two text shapes this actually is.
        text = raw_bytes.decode("utf-8", errors="replace")
        #Run the analysis and log every finding through the SAME shared
        #Log object (and therefore the SAME findings.jsonl/Dashboard)
        #every other module writes to.
        results = log_review.analyze_uploaded_text(self.config, Log(self.config), basename, text)
        #Build a plain summary of what was found, for an immediate
        #on-screen answer - the person should not have to go open the
        #Dashboard just to see what an upload turned up.
        if results:
            summary_lines = [f"- [{severity.upper()}] {message}" for severity, _key, message in results]
            summary = (f"Found {len(results)} finding(s) in {basename}:\n\n"
                       + "\n".join(summary_lines)
                       + "\n\nAlso logged to findings.jsonl / the Dashboard, under the 'logs' module.")
        else:
            summary = (f"Nothing suspicious found in {basename} - no brute-force or "
                       "successful-login-after-brute-force patterns matched.")
        dialogs.show_scrollable_text(self.root, self.palette, self.fonts, "Upload Log to Analyze - Results", summary)

    #Define _handle_upload_pcap, "Upload PCAP to Analyze"'s own handler -
    #the "upload... pcaps to analyze" half of this round's ask. Works
    #for EITHER target type, exactly like _handle_upload_log above,
    #since the capture file being analyzed always comes from the
    #analyst's own machine, never read live off the monitored target.
    def _handle_upload_pcap(self):
        #Nothing configured yet - should not normally be reachable.
        if not self.config:
            #Nothing to do.
            return
        #Open a native file picker. filetypes is a hint only - the
        #picker still allows "All files", since a real capture file is
        #sometimes saved with no extension at all or an unusual one.
        chosen_path = filedialog.askopenfilename(
            parent=self.root, title="Select a .pcap file to analyze",
            filetypes=[("Packet captures", "*.pcap"), ("All files", "*.*")],
        )
        #An empty string means the person cancelled the picker.
        if not chosen_path:
            #Nothing to do.
            return
        #Read the chosen file as raw BYTES, not text - a capture file is
        #binary, unlike the plain-text logs _handle_upload_log reads.
        try:
            with open(chosen_path, "rb") as uploaded_file:
                data = uploaded_file.read()
        except Exception as exc:
            #Say plainly why nothing could be analyzed.
            dialogs.show_message(self.root, self.palette, self.fonts, "Upload PCAP to Analyze",
                                  f"Could not read that file: {exc}", kind="error")
            #Nothing else to do.
            return
        #Run the analysis and log every finding through the SAME shared
        #Log object (and therefore the SAME findings.jsonl/Dashboard)
        #every other module writes to.
        summary = pcap_review.analyze_uploaded_pcap(self.config, Log(self.config), os.path.basename(chosen_path), data)
        #Build a plain, readable summary for an immediate on-screen
        #answer - the person should not have to go open the Dashboard
        #just to see what an upload turned up.
        basename = os.path.basename(chosen_path)
        if not summary["flows"] and not summary["basic_findings"] and summary["total_packets"] == 0:
            #Either an empty capture, or a format this parser could not
            #read at all (pcap_review.py already logged which one).
            text = (f"Could not read any IPv4 TCP/UDP flows from {basename}.\n\n"
                    "This is either an empty capture, or a file format this tool doesn't "
                    "read (only the classic .pcap format is supported - not the newer "
                    ".pcapng format Wireshark saves by default). See the Dashboard's "
                    "'OTHER ACTIVITY' section for the exact reason, if any was logged.")
        else:
            lines = [f"Analyzed {summary['total_packets']} packets across {len(summary['flows'])} "
                     f"IPv4 TCP/UDP flows in {basename}."]
            if summary["truncated"]:
                lines.append("(This capture was larger than this tool reads in one pass - "
                              "results reflect only the first packets read.)")
            if summary["basic_findings"]:
                lines.append("")
                lines.append(f"{len(summary['basic_findings'])} finding(s):")
                for severity, _key, message in summary["basic_findings"]:
                    lines.append(f"- [{severity.upper()}] {message}")
            else:
                lines.append("")
                lines.append("Nothing suspicious found - no well-known suspicious ports or "
                              "port-scan-shaped traffic matched.")
            #Show the biggest flows by data volume too - the plain "who
            #talked to whom, how much" summary the user actually asked
            #for, not just the heuristic findings above it.
            top_flows = sorted(summary["flows"], key=lambda f: f["byte_count"], reverse=True)[:15]
            if top_flows:
                lines.append("")
                lines.append("Top flows by bytes transferred:")
                for flow in top_flows:
                    port_part = f":{flow['destination_port']}" if flow["destination_port"] is not None else ""
                    proto_name = pcap_review.protocol_name(flow["protocol"])
                    lines.append(f"- {flow['source_ip']} -> {flow['destination_ip']}{port_part} "
                                 f"({proto_name}, {flow['packet_count']} packets, {flow['byte_count']} bytes)")
            lines.append("")
            lines.append("Also logged to findings.jsonl / the Dashboard, under the 'pcap' module.")
            text = "\n".join(lines)
        dialogs.show_scrollable_text(self.root, self.palette, self.fonts, "Upload PCAP to Analyze - Results", text)
        #Refresh the Dashboard right away so a genuinely new finding is
        #visible immediately, without waiting for the next poll tick.
        if hasattr(self, "dashboard_view"):
            #Re-read and redraw the dashboard from disk.
            self.dashboard_view.refresh(self.config)

    #--- The recurring poll loop ---

    #Define _poll_loop, the one function in this whole file that runs on
    #a timer (via root.after, which is always safe to call from the main
    #thread) rather than in response to a click. It is the ONLY place
    #that reacts to what the background thread is doing, drives the
    #ambient auto-scan, and keeps the baseline button's label/visibility
    #in sync - which keeps every actual Tkinter widget update safely on
    #the main thread.
    def _poll_loop(self):
        #Belt-and-suspenders wrapper around the real tick logic
        #(_poll_loop_tick, just below). The one fix above (clearing
        #self._action_buttons in _show_wizard) addresses the ROOT cause
        #of the freeze that was just reported - but given how severe and
        #silent the consequence is (the console and Dashboard both stop
        #updating FOREVER, with zero on-screen indication anything is
        #wrong, while background scans keep running and look completely
        #normal in the real terminal), this loop must never again be
        #allowed to die from an uncaught exception, known cause or not.
        #So: run the actual tick in a try/except, and ALWAYS reschedule
        #in a finally - no exception anywhere inside the tick can ever
        #again prevent the next self.root.after(150, ...) call below.
        try:
            #Run one real tick of the loop.
            self._poll_loop_tick()
        #Catch literally anything that goes wrong during the tick.
        except Exception:
            #Print a visible traceback to the real terminal (same place
            #an unhandled Tkinter callback exception would already go),
            #so a problem here is never worse than merely-as-visible as
            #before this fix - but it can no longer stop the loop.
            traceback.print_exc()
        finally:
            #Schedule the NEXT tick no matter what just happened above -
            #this is the one line that actually matters: as long as this
            #always runs, the console/Dashboard can never again freeze
            #permanently just because one tick hit a problem.
            self.root.after(150, self._poll_loop)

    #Define _poll_loop_tick, the actual per-tick work _poll_loop above
    #wraps in its own never-fails try/except/finally. Unchanged from the
    #original _poll_loop other than losing its own reschedule call at the
    #very end, which now lives in the wrapper's finally instead so it is
    #guaranteed to run even if something below raises.
    def _poll_loop_tick(self):
        #Pull out everything currently waiting in the output queue,
        #whether it came from a manual click or the ambient auto-scan
        #below, and append it to the console pane.
        pending_chunks = drain_queue(self.output_queue)
        if pending_chunks:
            #Text widgets are read-only (state="disabled") except for the
            #brief moment we're actually inserting new text into them.
            self.console_text.configure(state="normal")
            #Append every pending chunk, in the order it was produced.
            for chunk in pending_chunks:
                #Insert this chunk at the very end of the existing text.
                self.console_text.insert("end", chunk)
            #Scroll to the bottom so the most recent output is visible
            #without the person having to scroll down themselves.
            self.console_text.see("end")
            #Lock the text widget again so a stray click can't edit it.
            self.console_text.configure(state="disabled")

        #Everything below this point only applies once the main panel
        #(not the first-run wizard) is actually showing.
        main_panel_showing = self.config is not None and hasattr(self, "dashboard_view")

        if main_panel_showing:
            #Check whether the baseline lock has changed since the last
            #tick, and only touch the slot on an actual change.
            locked_now = is_baseline_locked(self.config)
            if locked_now != self._last_lock_state and self._baseline_slot_frame is not None:
                #Hide "Sentinel: Baseline" once locked (there is nothing
                #to show in its place any more - no more standalone
                #"Reset Baseline" button; see menu_actions.py's own
                #comment on "baseline" for where that reset moved to),
                #or show it again once unlocked.
                baseline_button = self._action_buttons.get("baseline")
                if baseline_button is not None:
                    if locked_now:
                        #Hide the "take a baseline" button - nothing
                        #replaces it in this slot while locked.
                        baseline_button.pack_forget()
                    else:
                        #Show it again now that nothing is locked.
                        baseline_button.pack(fill="x", padx=10, pady=3)
                #Remember this state for next tick's comparison.
                self._last_lock_state = locked_now

        #Decide whether the app should currently be "busy", and only
        #touch every button's enabled state on an actual change.
        busy_now = self.runner.busy
        if busy_now != self._last_busy_state:
            #Enable every action button when not busy; disable every one
            #while busy, so a second click can never overlap a running
            #action (manual or ambient).
            for button in self._action_buttons.values():
                #Apply the new enabled state.
                button.state(["disabled"] if busy_now else ["!disabled"])
            #Remember this state for next tick's comparison.
            self._last_busy_state = busy_now

        #Drive the ambient auto-scan clock and the idle status line.
        #Only while the main panel is up, and only while nothing else is
        #already running - a manual action already set its own "Running:
        #..." status line, which this deliberately leaves alone rather
        #than overwriting it every 150ms.
        if main_panel_showing and not busy_now:
            #Advance the clock by this tick's own interval.
            self._scan_accum_ms += 150
            #Work out how long a full interval actually is, in the same
            #units, falling back to a sane default if it's ever missing.
            interval_ms = max(1, self.config.get("interval", 15)) * 1000
            if self._scan_accum_ms >= interval_ms:
                #Time for the next ambient pass - reset the clock FIRST,
                #so a scan that itself takes a while doesn't immediately
                #re-trigger the moment it finishes.
                self._scan_accum_ms = 0
                #Start it on the exact same background runner a manual
                #click would use - "scan" is cli.py's own key for "run
                #everything, once", local or remote either way.
                self.runner.start(lambda config=self.config, secret=self.secret: run_action(config, secret, "scan"))
                #Tell the person what's happening without them clicking
                #anything themselves.
                self._set_status("Auto-scanning...")
            else:
                #Not time yet - show a live countdown so the window
                #visibly reads as "a live scan feed", not just idle.
                remaining_seconds = max(0, round((interval_ms - self._scan_accum_ms) / 1000))
                self._set_status(f"Idle. Next auto-scan in {remaining_seconds}s.")
        elif not main_panel_showing:
            #The wizard is up instead - nothing to show here.
            pass

        #Refresh the dashboard roughly every 2 seconds (13 ticks at this
        #loop's 150ms interval), not on every single tick, which would
        #re-read and rebuild every card far more often than any human
        #could actually perceive a difference.
        self._findings_tick_counter += 1
        if self._findings_tick_counter >= 13:
            #Reset the counter for the next cycle.
            self._findings_tick_counter = 0
            #Only refresh if the main panel is actually showing right now.
            if main_panel_showing:
                #Re-read and redraw the dashboard from disk.
                self.dashboard_view.refresh(self.config)
                #Check for any brand-new critical finding on the exact
                #same cadence - same underlying findings.jsonl read the
                #dashboard refresh above just did, so this piggybacks on
                #it rather than reading the file a second time per tick.
                self._check_for_new_critical_findings()
        #(Rescheduling the next tick now happens in _poll_loop's own
        #finally block above, unconditionally - see its comment.)

    #--- Shutdown ---

    #Define _on_close, called when the window's own close button is used.
    def _on_close(self):
        #Ask for a clear, plain confirmation before quitting at all -
        #direct feedback asked for exactly this, since the window's own
        #[X] is otherwise one single accidental click away from ending a
        #whole monitoring session with no way back.
        if self.config is not None:
            #A real config/evidence_dir exists - mention the automatic
            #final report up front, so nobody is surprised a popup
            #appears right after they click Yes.
            message = ("Are you sure you want to quit this instance?\n\n"
                       "On Yes, a final Scribe incident report is written "
                       "automatically first, so nothing logged so far is "
                       "lost, and you'll be shown exactly where it was saved.")
        else:
            #Nothing has ever been configured yet (still on the very
            #first wizard page) - there is no evidence_dir to write a
            #report into yet, so don't mention one that cannot exist.
            message = "Are you sure you want to quit?"
        should_quit = dialogs.confirm_yes_no(
            self.root, self.palette, self.fonts, "Quit Poltergeist", message,
            confirm_label="Yes", cancel_label="Cancel", danger=True,
        )
        if not should_quit:
            #Back out - leave the window open exactly as it was, nothing
            #written, nothing closed.
            return
        #Write the final incident report automatically, the exact same
        #function "Scribe: Write Report" already calls by hand - only
        #when a real config (and therefore a real evidence_dir) exists
        #at all to write one from.
        report_path = report.generate(self.config) if self.config is not None else None
        #Show exactly where it landed BEFORE the window actually
        #disappears below - once destroy() runs there is no window left
        #to show this in, and the whole point is the person sees this
        #without having to go hunting for the file afterward.
        if report_path:
            dialogs.show_message(
                self.root, self.palette, self.fonts, "Report saved",
                f"Final incident report saved to:\n\n{report_path}",
            )
        elif self.config is not None:
            #A real config existed, but nothing was ever actually logged
            #this run - say so plainly instead of silently skipping the
            #popup the person was just told to expect.
            dialogs.show_message(
                self.root, self.palette, self.fonts, "Nothing to report",
                "No findings were logged this session, so no report was written.",
            )
        #Now actually destroy the window, which ends mainloop() and lets
        #run() (and launch_gui() below) return normally. There is no
        #background loop of this window's own left to signal to stop -
        #the ambient auto-scan lives entirely inside the already-daemon
        #BackgroundRunner thread, which can never, by itself, keep the
        #process from exiting once the window is gone.
        self.root.destroy()


#Define launch_gui, the one function the rest of the project calls to try
#starting the GUI. Returns True if the GUI ran (and the person has since
#closed it normally), or False if it couldn't start at all, so the caller
#(cli.py) knows to fall back to the plain text menu instead. This
#function deliberately catches EVERYTHING, not just the "Tkinter isn't
#installed" case - a broken display connection, a missing font engine, or
#any other oddity on an unusual box should fall back to the always-
#reliable text menu rather than crash the whole program.
def launch_gui():
    #Wrap the entire attempt in one broad try/except.
    try:
        #Build the application window.
        app = App()
        #Hand control to it; this blocks until the window is closed.
        app.run()
        #The GUI ran and was closed normally.
        return True
    #Catch absolutely anything that went wrong trying to start or run it.
    except Exception as error:
        #Explain plainly what happened and what to do about it, without
        #assuming WHY it failed - it could be a missing Tk installation,
        #a missing display on a headless Linux box, or something else
        #entirely, and guessing wrong would be worse than just saying so.
        print(f"  Could not start the GUI ({error}) - falling back to the text menu.")
        print("  (Linux: this usually means Tkinter isn't installed - try 'sudo apt install python3-tk'")
        print("   or your distro's equivalent, then re-run. You can also add --text to always skip the GUI.)")
        #Tell the caller the GUI did not successfully run.
        return False
