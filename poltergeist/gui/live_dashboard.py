#DESCRIPTION: This file is the main-screen Dashboard the GUI's primary
#             view is built from - the direct answer to this round of
#             feedback's biggest ask: "I don't want that mess of log crap
#             I just want the dashboard that covers the big things we
#             want to be monitoring... That main screen has everything
#             listed like that example with color code to help identify
#             stuff fast." "That example" is the user's own separate
#             Shadow Watch tool's one-shot IOC-sweep screen (OPEN
#             LISTENING PORTS / POTENTIAL MALICIOUS PROCESSES / ACTIVE
#             ROOT DIRECTORY SCRUB / POTENTIAL C2 IPs / POTENTIAL EVASIVE
#             PERSISTENCE / SSH DIRECTORY CONTENTS), which this file's
#             section layout deliberately mirrors.
#
#             The chronological findings.jsonl is an APPEND-only log: the
#             ambient auto-scan re-runs every single live module on every
#             pass, and evidence.py's Log.add() only de-dupes WITHIN one
#             run (its "seen" set starts empty every time poltergeist.py
#             is invoked) - so an ongoing, unchanged condition (a port
#             that's still open, a process that's still running) gets
#             RE-LOGGED every single scan cycle. That repetition is
#             exactly the "wall of logs that just keeps updating" the
#             user is reacting against. This file's whole job is to turn
#             that growing history into a small set of fixed sections
#             that each show only the CURRENT state - the single most
#             recent record for each distinct thing being tracked - so
#             the main screen reads as "here is what's true right now",
#             not "here is everything that has ever happened". The old
#             full chronological view is not gone - that's deliberately
#             still what the separate web Dashboard (dashboard.py) shows.
#
#             Written the same way findings_view.py is: every function
#             down to build_sections() takes plain data in and returns
#             plain data out, with NO Tkinter calls anywhere in it, so
#             all of the actual logic here can be unit-tested without a
#             display. Only the DashboardView class at the very bottom
#             touches a real widget.

#import os for this file's own path-building; findings.jsonl itself is
#now read and parsed through evidence.load_findings_file() (see below)
#instead of a local copy, so json is no longer needed directly here.
import os

#import tkinter/ttk for DashboardView itself, at the bottom of this file.
import tkinter as tk
from tkinter import ttk

#import load_findings_file and latest_state from evidence.py rather than
#keeping this file's own local copies - both dashboard.py (the web page)
#and gui/findings_view.py (the GUI's own findings table) now need the
#exact same "collapse the append-only history down to current state"
#logic this file was originally built around (see this file's own module
#docstring above), so one shared, canonical copy in evidence.py replaces
#what used to be three near-identical, independently-drifting copies.
from ..evidence import load_findings_file, latest_state

#import the tripwire module directly so the TRIPWIRE section can show
#which folders are CURRENTLY being watched, not just alerts about
#changes within them - tripwire.py's own watch list is not itself a
#finding in findings.jsonl, so it has to be read separately, the same
#way build_live_ports_rows() below reads live port state from its own
#separate source rather than from a plain finding.
from ..modules import tripwire

#import deception for the exact same reason, so the CANARY section can
#show which real locations are CURRENTLY being seeded with bait files,
#not just alerts about one being accessed.
from ..modules import deception

#NOTE: this file used to import find_listening_ports from discovery.py
#and call it directly here, so the "OPEN LISTENING PORTS" rows were a
#true, instant, right-now listing - exactly like the Shadow Watch screen
#this section mirrors. That was a real bug for a REMOTE target though:
#calling it straight from here runs it inside the GUI's OWN local
#process, on the ANALYST's own machine - not the configured target - so
#a remote target's Dashboard silently showed the operator's own laptop's
#ports (SearchHost.exe, docker, svchost...) instead of the target's.
#quickscan.py's own listening-ports section (which DOES run on whichever
#machine the scan is actually happening on, local or remote) now logs
#each port as a quiet "quickscan"/"port:" finding instead, specifically
#so this file can read it back from findings.jsonl - the exact same way
#everything else on this Dashboard gets to the right machine's data,
#including after pull_evidence() syncs a remote target's findings back.
#This trades "instant, independent of scan cadence" for "always the
#correct target's machine", which is the only one of those two that
#actually matters here.


#Define SECTION_DEFS, the fixed, ordered list of dashboard sections and
#which finding "module" name(s) (see evidence.py's Log.add - every
#finding is tagged with a short module string) feed each one. This is
#the single place that decides the dashboard's shape; add a new module
#to this project and give it a line here to make sure it has a home
#instead of silently falling into the catch-all "OTHER ACTIVITY" section
#at the end.
#
#"ssh" is a special case: it is not a module of its own, it's the subset
#of quickscan's own findings whose key starts with "sshkey:" (see
#quickscan.py's list_ssh_keys(), which logs one line per key file found
#under a .ssh folder) - split out into its own section because the user
#specifically called it out ("the ssh directory content to help identify
#bad keys") as something that needs its own spot, not buried inside a
#generic "quickscan" bucket with everything else quickscan logs.
#
#"ports" is also a special case, same shape as "ssh": it is the live
#port listing (quickscan's own "port:"-keyed findings, see
#build_live_ports_rows() below) PLUS network.py's own "listen:"-keyed
#findings (a brand new/suspicious LISTENING port) - split out into its
#own section, first in the list, to match the Shadow Watch/Harbinger
#layout this Dashboard mirrors, which gives open ports their own
#section ahead of "malicious processes" rather than folding them into
#it. network.py's "listen:" findings used to land in the C2/network
#section below, which made sense for an OUTBOUND/established connection
#but not for "a port is open" - that's a ports question, not a
#connection question, so they show here instead now.
SECTION_DEFS = [
    ("ports", "OPEN LISTENING PORTS", set()),  # handled as a special case below
    ("malicious_processes", "POTENTIAL MALICIOUS PROCESSES", {"process"}),
    ("integrity", "FILE INTEGRITY / ROOT DIRECTORY SCRUB", {"integrity"}),
    #"pcap" is folded into this SAME section, not its own - an uploaded
    #capture's findings (suspicious ports, port-scan-shaped traffic) are
    #the exact same kind of thing the live "network" module already
    #reports, just read from a file instead of from this machine's live
    #connections, so they belong next to each other, not in two
    #separately-labeled C2/network sections a person has to check both of.
    ("network", "POTENTIAL C2 / SUSPICIOUS NETWORK ACTIVITY", {"network", "pcap"}),
    ("persistence", "POTENTIAL EVASIVE PERSISTENCE", {"persistence"}),
    ("tripwire", "TRIPWIRE (your watched folders)", {"tripwire"}),
    #"deception" gets its own section, the same way "tripwire" does just
    #above, rather than falling into the "other" catch-all - both are
    #Active Defense features the user explicitly picks real locations
    #for, and both benefit from showing that chosen-location list right
    #alongside any actual alert, not buried in a generic bucket.
    ("deception", "CANARY (your seeded bait locations)", {"deception"}),
    ("ssh", "SSH DIRECTORY CONTENTS", set()),  # handled as a special case below
    ("other", "OTHER ACTIVITY (users, packages, logging, log analysis, Oracle, Shield...)",
     {"users", "packages", "logging", "logs", "oracle", "deception", "lockdown", "snapshot"}),
]

#How many of the most recent rows to show per section before truncating
#with a "+N more" note - keeps one noisy section from pushing every
#other section off the bottom of the window.
MAX_ROWS_PER_SECTION = 8


#Define categorize, a pure one-line-ish lookup turning one finding's
#"module" field (plus, for the ssh special case, its "key") into the
#dashboard section id it belongs under. Falls back to "other" for any
#module string this project doesn't know about yet, so a future module
#added without updating SECTION_DEFS still shows up SOMEWHERE instead of
#silently vanishing off the dashboard entirely.
def categorize(finding):
    #The SSH special case: a quickscan finding whose key marks it as one
    #of the SSH directory listing lines, regardless of quickscan's own
    #module name. "sshkey" (no trailing colon) deliberately catches all
    #three of quickscan.py's own SSH-related key prefixes - "sshkey:"
    #(the plain listing), "sshkey_perm:" (loose permissions) and
    #"sshkey_cmd:" (a restricted key whose fixed command looks like a
    #dropper/reverse-shell) - so every SSH-related judgment call lands
    #in this same section, not just the plain listing.
    if finding.get("module") == "quickscan" and str(finding.get("key", "")).startswith("sshkey"):
        #This one line belongs in the SSH section.
        return "ssh"
    #The ports special case: a network.py finding about a LISTENING port
    #(brand new, or on the always-suspicious watch_ports list) belongs
    #with the rest of the open-ports picture, not in the C2/established-
    #connection section - see SECTION_DEFS's own comment above for why.
    if finding.get("module") == "network" and str(finding.get("key", "")).startswith("listen:"):
        #This one line belongs in the ports section.
        return "ports"
    #Walk every ordinary section definition looking for a module match.
    for section_id, _title, module_names in SECTION_DEFS:
        #Skip the ssh/ports sections here - neither is ever matched by
        #module name alone, only by the special cases just above.
        if section_id in ("ssh", "ports"):
            #Move on to the next section definition.
            continue
        #A match means this finding belongs in this section.
        if finding.get("module") in module_names:
            #Hand back this section's id.
            return section_id
    #Nothing matched - fall back to the catch-all section.
    return "other"


#NOTE: load_findings_file() and latest_state() both now live in
#evidence.py (imported above) rather than as local copies here - see the
#import comment for why. Everything below this point still uses them by
#their same plain names, unchanged.


#Define build_live_ports_rows, turning this scan's own logged "port:"
#findings (see this file's own comment above for why these come from
#findings.jsonl now, not a direct live call) into the same (severity,
#text) row shape every other section uses.
def build_live_ports_rows(current_state):
    #Pick out just the quickscan module's own "port:"-keyed findings -
    #everything else quickscan logs (SSH key listings, etc.) is handled
    #by its own separate section/special case, not here.
    port_findings = [f for f in current_state if f.get("module") == "quickscan" and str(f.get("key", "")).startswith("port:")]
    #Plain info-severity rows; nothing here is inherently suspicious on
    #its own - network.py's own "network" findings are what flag a port
    #as NEW or a connection as outside the trusted ranges.
    return [("info", f.get("message", "")) for f in port_findings]


#Define build_live_tripwire_rows, turning tripwire.py's own watch-list
#state (NOT a finding - see this file's own import comment above) into
#the same (severity, text) row shape every other section uses, exactly
#the way build_live_ports_rows() above does for live port state. Always
#at most MAX_WATCHED_PATHS rows (tripwire.add_path() itself enforces that
#cap), so this never needs its own truncation logic.
def build_live_tripwire_rows(config):
    #Load the current watch state - this is a cheap, local, synchronous
    #read of one small JSON file, safe to call on every single refresh.
    watched_paths = tripwire.load_state(config)["watched_paths"]
    #One plain info row per currently watched folder, so a person
    #glancing at this card always knows what's being watched right now,
    #not just whether something has changed inside it.
    return [("info", f"Watching: {path}") for path in watched_paths]


#Define build_live_canary_rows, the exact Canary equivalent of
#build_live_tripwire_rows() just above - deception.py's own seeded
#bait-folder list is state, not a finding, so it has to be read
#separately from current_state the same way.
def build_live_canary_rows(config):
    #Load the current bait-folder state - cheap, local, synchronous.
    bait_folders = deception.load_state(config)["bait_folders"]
    #One plain info row per currently seeded location, so a person
    #glancing at this card always knows where bait files are actually
    #sitting right now, not just whether one has been accessed.
    return [("info", f"Seeding: {path}") for path in bait_folders]


#Define format_finding_row, turning one finding dictionary into this
#file's (severity, text) row shape - deliberately a single compact line
#(not the two-line "message\n  -> suggested: fix" shape format_row() in
#findings_view.py uses), since a dashboard card is meant to be scanned
#at a glance across many sections at once, not read line by line; anyone
#who wants the suggested fix for a specific line still gets the full
#detail from the hover tooltip DashboardView attaches to each row.
def format_finding_row(finding):
    #Pull out the two fields this view actually displays, with safe
    #fallbacks so a hand-edited or partial line never crashes the GUI.
    severity = finding.get("severity", "info")
    message = finding.get("message", "")
    #Hand back the finished (severity, text) pair.
    return (severity, message)


#Define build_sections, the main entry point: given a config dict, hand
#back the full, ordered list of dashboard sections, each one already
#deduplicated to current state, capped, and ready for DashboardView to
#draw with no further logic of its own. Every section dict has: "id"
#(the fixed SECTION_DEFS key - DashboardView uses this to update its own
#already-built, persistent card widgets in place, rather than destroying
#and rebuilding everything on every refresh), "title" (display heading),
#"rows" (list of (severity, text) tuples actually shown), and
#"more_count" (how many additional rows were cut off by the per-section
#cap, or 0 if nothing was).
def _load_current_state(config):
    #Shared by build_sections() below and get_active_high_severity_keys()
    #in app.py's own new-critical-finding notification check - both need
    #the exact same "load everything, collapse to current state" step,
    #so it is pulled out here rather than duplicated.
    findings_path = os.path.join(config["evidence_dir"], "findings.jsonl")
    all_findings = load_findings_file(findings_path)
    return latest_state(all_findings)


#Define get_active_high_severity_keys, used by app.py's own notification
#check (see its _poll_loop_tick and _check_for_new_critical_findings) to
#tell WHICH currently-active (CRITICAL, in the GUI's own red-label sense)
#findings exist right now, by (module, key) identity - comparing this
#set tick-to-tick against what it was last time is how that feature
#tells a genuinely NEW critical finding apart from one that was already
#sitting there. A plain set of (module, key) tuples, not the formatted
#rows build_sections() below produces, since identity (not display text)
#is exactly what a tick-to-tick diff needs.
def get_active_high_severity_keys(config):
    current_state = _load_current_state(config)
    return {(finding.get("module"), finding.get("key"))
            for finding in current_state if finding.get("severity") == "high"}


def build_sections(config):
    #Collapse everything ever logged for the currently configured target
    #down to just the current state of each distinct thing being tracked.
    current_state = _load_current_state(config)
    #Bucket every current-state finding into its section. The quickscan
    #module's own "port:"-keyed findings are deliberately skipped here -
    #build_live_ports_rows() below reads them directly out of
    #current_state itself, since they need to appear FIRST within the
    #malicious_processes section (ahead of any real "process" findings),
    #not wherever categorize()'s generic module-name matching would
    #otherwise place them (which, having no "quickscan" entry in
    #SECTION_DEFS, would be the "other" catch-all - correct for every
    #OTHER thing quickscan logs, wrong just for this one).
    bucketed = {section_id: [] for section_id, _title, _modules in SECTION_DEFS}
    for finding in current_state:
        if finding.get("module") == "quickscan" and str(finding.get("key", "")).startswith("port:"):
            #Handled separately by build_live_ports_rows() - skip here.
            continue
        bucketed[categorize(finding)].append(finding)

    #Build the finished, ordered section list.
    sections = []
    for section_id, title, _modules in SECTION_DEFS:
        #The "ssh"/"ports" sections' rows are plain findings too, formatted
        #the same way as every other section - the only special case for
        #either is which findings land in it (categorize(), above).
        if section_id == "ports":
            #Pull in this section's own live-port rows too (see
            #build_live_ports_rows()'s own comment above for where these
            #actually come from now).
            live_rows = build_live_ports_rows(current_state)
        elif section_id == "tripwire":
            #Pull in this section's own live watched-folder rows too (see
            #build_live_tripwire_rows()'s own comment above) - tripwire's
            #watch list is state, not a finding, so it is read separately
            #from current_state, same reasoning as the ports case above.
            live_rows = build_live_tripwire_rows(config)
        elif section_id == "deception":
            #Pull in this section's own live seeded-location rows too,
            #the exact same reasoning as the tripwire case just above.
            live_rows = build_live_canary_rows(config)
        else:
            live_rows = []
        finding_rows = [format_finding_row(f) for f in bucketed[section_id]]
        #Sort by severity, worst (red/HIGH) first, then MEDIUM, then
        #info - a box with more than MAX_ROWS_PER_SECTION findings in one
        #section must never let a real HIGH finding get silently pushed
        #past the cap by a MEDIUM one that merely happened to log first;
        #red always earns a visible row before orange does. sorted() is
        #stable, so within the same severity tier this still preserves
        #bucketed[section_id]'s own newest-first order from latest_state()
        #above - only the severity tiers themselves get reordered.
        finding_rows.sort(key=lambda row: SEVERITY_ORDER.get(row[0], 0), reverse=True)
        #Real findings (something actually flagged - here, a brand new or
        #watch-listed port, via the "listen:" special case above) go
        #FIRST, ahead of the routine "every port currently open" listing -
        #a box with 8+ open ports and one genuinely new/suspicious one
        #must never let that one finding get silently pushed past
        #MAX_ROWS_PER_SECTION's cap by routine, nothing-wrong-here port
        #rows. This only matters for "ports" (every other section has no
        #live_rows at all), but is written generally so it stays correct
        #if that ever changes.
        all_rows = finding_rows + live_rows
        #Cap the rows actually shown, remembering how many were cut off.
        shown_rows = all_rows[:MAX_ROWS_PER_SECTION]
        more_count = max(0, len(all_rows) - len(shown_rows))
        #If there is truly nothing at all for this section, say so
        #plainly instead of leaving it looking broken or forgotten.
        if not shown_rows:
            shown_rows = [("info", "(nothing to report)")]
        sections.append({"id": section_id, "title": title, "rows": shown_rows, "more_count": more_count})
    #Hand back the finished, ordered section list.
    return sections


#Define SEVERITY_ORDER, used only to decide a section's own accent color
#(see DashboardView below): a section is drawn as urgently as its WORST
#row, not its most common one, so one real HIGH finding buried among
#several INFO lines still makes the whole card impossible to miss.
SEVERITY_ORDER = {"high": 2, "medium": 1, "info": 0}

#Define SEVERITY_COLORS, the Dashboard's own small, deliberate exception
#to the rest of the GUI's strict black-and-white theme (see theme.py's
#own top comment) - direct feedback asked for real color here
#specifically so "things that are important stick out" at an actual
#glance across a whole screen of cards, not just a slightly-brighter
#gray among several other grays. HIGH additionally gets a tinted row
#background and bold text, not just a different text color, since a
#color difference alone is easy to miss in peripheral vision - the
#whole point of this section.
SEVERITY_COLORS = {
    "high": {"accent": "#ff4d4d", "text": "#ff8080", "row_background": "#2a1414", "bold": True},
    "medium": {"accent": "#ffb347", "text": "#ffb347", "row_background": None, "bold": False},
    "info": {"accent": "#7f93a3", "text": "#9aa7af", "row_background": None, "bold": False},
}


#Define worst_severity, a tiny pure helper for the above.
def worst_severity(rows):
    #Fall back to "info" for an empty row list (should not happen, since
    #build_sections() above always inserts a placeholder row).
    if not rows:
        #Nothing to compare - default to the least urgent level.
        return "info"
    #Hand back whichever row's severity sorts highest.
    return max((severity for severity, _text in rows), key=lambda s: SEVERITY_ORDER.get(s, 0))



#Define DashboardView, the actual widget: one scrollable column of
#section "cards", each with a colored heading bar and its own list of
#rows, each row colored by its own severity - this is the Tkinter half
#of this file; everything above it is plain data in, plain data out.
#
#EVERY CARD AND ROW WIDGET IS BUILT EXACTLY ONCE, in __init__, and
#refresh() only ever reconfigures their text/color/visibility in place -
#this is a deliberate fix for a real, reported bug: the previous version
#destroyed and rebuilt every single widget on every refresh (every few
#seconds, via app.py's ambient poll loop), which is cheap for Tkinter to
#compute but visibly FLICKERS on screen, because the canvas briefly has
#nothing drawn in it between the destroy and the rebuild. SECTION_DEFS
#is a fixed, known-ahead-of-time list, so there is no need to ever
#create or destroy a card at all after startup - only its contents
#change. Each card pre-allocates MAX_ROWS_PER_SECTION row Labels (its
#worst case) and uses Tkinter's grid() geometry manager (not pack()) for
#them specifically because grid_remove()/grid() cleanly show/hide a
#widget AT ITS OWN FIXED ROW INDEX with no risk of it jumping to the
#wrong position - pack_forget() followed by pack() instead re-appends a
#widget to the END of its parent's packing order, which would silently
#reorder rows the first time a section's row count changed.
class DashboardView(ttk.Frame):
    #Define the constructor. palette/fonts are handed in rather than
    #imported directly, matching every other GUI widget in this project.
    def __init__(self, parent, palette, fonts):
        #Build the underlying ttk.Frame first.
        super().__init__(parent, style="TFrame")
        self.palette = palette
        self.fonts = fonts
        #A bold variant of the small mono font, used only for HIGH
        #severity rows (see SEVERITY_COLORS above) - built once here
        #rather than recomputed on every refresh.
        mono_family, mono_size = fonts["mono_small"][0], fonts["mono_small"][1]
        self._mono_bold = (mono_family, mono_size, "bold")
        #Build the same scrollable-canvas pattern app.py's own button
        #panel already uses (see _build_button_panel's own comments for
        #the full reasoning) - ttk has no built-in scrollable frame, and
        #a dashboard with eight sections will not always fit one screen.
        self.canvas = tk.Canvas(self, background=palette["bg"], highlightthickness=0)
        scrollbar = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=scrollbar.set)
        self.canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        #Build the inner frame everything actually gets drawn into.
        self.inner = ttk.Frame(self.canvas, style="TFrame")
        self._inner_window_id = self.canvas.create_window((0, 0), window=self.inner, anchor="nw")

        #Keep the scroll region and the inner frame's width in sync with
        #the canvas, exactly like _build_button_panel's own two handlers.
        def _on_inner_resized(event):
            self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        self.inner.bind("<Configure>", _on_inner_resized)

        def _on_canvas_resized(event):
            self.canvas.itemconfigure(self._inner_window_id, width=event.width)
        self.canvas.bind("<Configure>", _on_canvas_resized)

        #Define the mouse-wheel handler, same cross-platform approach
        #used everywhere else scrolling needs it in this project.
        def _on_mousewheel(event):
            #Windows/macOS report a signed delta; Linux reports a plain
            #Button-4/5 event instead, handled by the two binds below.
            self.canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
        self.canvas.bind("<MouseWheel>", _on_mousewheel)
        self.canvas.bind("<Button-4>", lambda e: self.canvas.yview_scroll(-1, "units"))
        self.canvas.bind("<Button-5>", lambda e: self.canvas.yview_scroll(1, "units"))

        #Build every card ONCE, keyed by section id, and never again -
        #see the class docstring above for why this is the whole point.
        self._cards = {}
        for section_id, _title, _modules in SECTION_DEFS:
            self._cards[section_id] = self._build_card_skeleton()

    #Define _build_card_skeleton, building exactly one section card's
    #widgets - empty of any real content yet (refresh() fills that in) -
    #and returning a small dict of references refresh() needs later.
    #Called exactly once per section, from __init__ only.
    def _build_card_skeleton(self):
        #Build this card's own frame, with a thin colored left border (a
        #4px-wide Frame, colored by refresh() to this section's current
        #worst severity) so a severity read is possible even at a
        #glance across a long scrolled page, without needing to read
        #any text at all.
        card = ttk.Frame(self.inner, style="TFrame")
        card.pack(fill="x", padx=10, pady=(0, 10), anchor="n")
        #Use grid() (not pack()) for everything inside this card - see
        #the class docstring for exactly why: it is the only Tkinter
        #geometry manager where hiding/showing a widget can never
        #silently reorder its siblings.
        total_grid_rows = 1 + MAX_ROWS_PER_SECTION + 1 + 1  # heading + rows + "+more" line + spacer
        accent_bar = tk.Frame(card, width=4)
        accent_bar.grid(row=0, column=0, rowspan=total_grid_rows, sticky="ns")
        body = tk.Frame(card, background=self.palette["panel"])
        body.grid(row=0, column=1, sticky="nsew")
        card.grid_columnconfigure(1, weight=1)
        body.grid_columnconfigure(0, weight=1)

        #The section heading - its text is fixed per section (set once,
        #right here), only its color ever changes in refresh().
        heading_label = tk.Label(body, font=self.fonts["heading"], background=self.palette["panel"], anchor="w")
        heading_label.grid(row=0, column=0, sticky="we", padx=10, pady=(6, 2))

        #Pre-allocate the full MAX_ROWS_PER_SECTION worth of row Labels -
        #refresh() below fills in however many are actually needed this
        #pass and grid_remove()s the rest, rather than ever creating or
        #destroying one.
        row_labels = []
        for row_index in range(MAX_ROWS_PER_SECTION):
            row_label = tk.Label(body, justify="left", wraplength=640, anchor="w", background=self.palette["panel"])
            row_label.grid(row=1 + row_index, column=0, sticky="we", padx=10, pady=1)
            row_labels.append(row_label)

        #A single "+N more" line, shown/hidden the same grid_remove()/
        #grid() way as a row label.
        more_label = tk.Label(body, font=self.fonts["mono_small"], background=self.palette["panel"],
                               foreground=self.palette["text_dim"], anchor="w")
        more_label.grid(row=1 + MAX_ROWS_PER_SECTION, column=0, sticky="we", padx=10, pady=(1, 6))

        #A fixed, always-visible spacer at the very bottom of every
        #card, so the card's bottom padding looks the same whether or
        #not the "+more" line above it happens to be showing right now.
        spacer = tk.Frame(body, background=self.palette["panel"], height=6)
        spacer.grid(row=1 + MAX_ROWS_PER_SECTION + 1, column=0, sticky="we")

        return {"accent_bar": accent_bar, "heading": heading_label, "row_labels": row_labels, "more_label": more_label}

    #Define refresh, called on whatever schedule app.py's poll loop
    #decides (same contract as FindingsView.refresh()). Reconfigures the
    #already-built cards' widgets in place - see the class docstring for
    #why this no longer destroys/rebuilds anything.
    def refresh(self, config):
        #Compute the current, deduplicated, bucketed section data.
        sections = build_sections(config)
        #Update one already-built card per section, in the fixed order
        #build_sections() returns them in (the same order SECTION_DEFS
        #itself defines, which is also the order the cards were built in
        #in __init__ - grid()'s fixed row positions make the actual
        #pack/grid order irrelevant here, but keeping the update order
        #matching the visual order is simply easier to reason about).
        for section in sections:
            self._update_card(self._cards[section["id"]], section)

    #Define _update_card, reconfiguring one already-built card's widgets
    #to match this refresh's current data for that section - no widget
    #is ever created or destroyed here, only reconfigured, shown, or
    #hidden.
    def _update_card(self, card, section):
        #Work out this section's own accent color from its worst row.
        accent = SEVERITY_COLORS[worst_severity(section["rows"])]["accent"]
        card["accent_bar"].configure(background=accent)
        card["heading"].configure(text=section["title"], foreground=accent)
        #Update each pre-built row label, in order, to match this
        #refresh's rows - any label beyond how many rows actually exist
        #this time is hidden (not destroyed) via grid_remove().
        rows = section["rows"]
        for row_index, row_label in enumerate(card["row_labels"]):
            if row_index < len(rows):
                severity, text = rows[row_index]
                colors = SEVERITY_COLORS.get(severity, SEVERITY_COLORS["info"])
                row_label.configure(
                    text=f"  {text}",
                    foreground=colors["text"],
                    background=colors["row_background"] or self.palette["panel"],
                    font=self._mono_bold if colors["bold"] else self.fonts["mono_small"],
                )
                #Restore this label at its own original grid position -
                #a no-op if it was already showing, and exactly reverses
                #a prior grid_remove() if it wasn't (see the class
                #docstring for why grid() is used instead of pack()).
                row_label.grid()
            else:
                #Nothing for this slot this time - hide it without
                #losing its grid position for next time.
                row_label.grid_remove()
        #Same show/hide approach for the single "+N more" line.
        if section["more_count"]:
            card["more_label"].configure(
                text=f"  + {section['more_count']} more - see the full Dashboard web page for history")
            card["more_label"].grid()
        else:
            card["more_label"].grid_remove()
