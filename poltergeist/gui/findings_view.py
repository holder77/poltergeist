#DESCRIPTION: This file is the GUI's live, in-window table of findings
#that replaces having to open a browser tab at all. It deliberately
#reuses the exact same "read findings.jsonl, sort newest first" logic
#dashboard.py and report.py already use, kept as its own local copy here
#(not imported from either of them) for the same reason logging_health.py,
#dashboard.py, and report.py each keep their own small copy of similar
#helpers: this file should stay self-contained and never depend on the
#web server module just to read a JSONL file. Every function down to
#format_row() is written to take plain data in and return plain data out,
#with NO Tkinter calls anywhere in them, so all of that logic can be
#unit-tested without a display. Only the FindingsView class at the bottom
#actually touches a real widget.

#import os so this table's own path-building (joining evidence_dir with
#findings.jsonl) works; the file is now read and parsed through
#evidence.load_findings_file() instead of a local copy (see below), so
#json is no longer needed directly in this file.
import os

#import tkinter and ttk for the actual Treeview widget at the bottom of
#this file. Every function ABOVE the FindingsView class avoids importing
#anything Tkinter-specific on purpose.
import tkinter as tk
from tkinter import ttk

#import format_ts_for_display so this table shows each finding's own
#timestamp in whoever's actually looking at THIS window's own local
#timezone, not the raw stored UTC - see evidence.py's own top comment
#on this function. This is a small, single-purpose import from
#evidence.py itself (not from dashboard.py/report.py), so it doesn't
#run against this file's own "stay self-contained, no dependency on
#the web server module" rule above - app.py already imports plenty
#directly from evidence.py for the exact same reason.
#
#Also import load_findings_file and latest_state for the same reason
#dashboard.py now does - this table used to print EVERY line ever
#written to findings.jsonl, newest first, with no collapsing at all,
#which meant an ongoing condition got a brand new row every single scan
#cycle, and a condition fixed by hand (a malicious process killed, a
#dropped file deleted) kept its last, already-stale row sitting in this
#table forever. latest_state() collapses that down to "the current state
#of each distinct thing being tracked" - see its own comment in
#evidence.py, and evidence.resolve_stale()'s, for the full picture.
from ..evidence import format_ts_for_display, load_findings_file, latest_state


#Define collect_all_findings, a pure function: given a config dict, return
#the CURRENT state of every distinct thing ever tracked for this target -
#collapsed to one row per (module, key) via latest_state() - capped to
#the most recent 200 (the same cap dashboard.py's web page uses, so the
#two views never disagree about how much history is "recent enough to
#show"). Each running install now ever points at ONE target - a remote
#target's findings are already synced back into THIS machine's own
#findings.jsonl by modules/remote.py's pull_evidence() the moment any
#action runs against it, so there is exactly one file to ever read here.
def collect_all_findings(config):
    #Load every finding ever logged for the currently configured target.
    local_path = os.path.join(config["evidence_dir"], "findings.jsonl")
    all_findings = load_findings_file(local_path)
    #Collapse the full history down to just the current state of each
    #distinct thing being tracked - already newest-first.
    all_findings = latest_state(all_findings)
    #Cap at the 200 most recent, same as the web dashboard.
    return all_findings[:200]


#Define severity_to_tag, a pure one-line lookup turning a finding's raw
#severity string into the Treeview tag name used to color its row. Kept
#as its own tiny function (rather than inlined where it's used) so the
#mapping itself - and what happens for an unexpected severity value - can
#be checked on its own.
def severity_to_tag(severity):
    #High and medium get their own named tags; anything else (including a
    #missing severity) falls back to the "info" tag rather than crashing
    #or leaving a row completely unstyled.
    return {"high": "sev_high", "medium": "sev_medium"}.get(severity, "sev_info")


#Define format_row, a pure function turning one finding dictionary into
#the exact tuple of display strings the Treeview below will show as one
#row's columns: (Time, Module, Severity, Message). There is no Host
#column - with exactly one target per running install, every row in this
#table is always about the same machine, so a repeated host name on every
#single line would just be clutter, not information. The suggested fix,
#if there is one, is appended to the message column on its own visual
#line so it's always visible without needing a second click.
def format_row(finding):
    #Pull each field out with a safe default, since a hand-edited or
    #partially-written findings.jsonl line should never crash the GUI.
    #Convert the raw stored UTC timestamp to THIS machine's own local
    #time before it's ever shown (see format_ts_for_display's comment).
    ts = format_ts_for_display(finding.get("ts", ""))
    module = finding.get("module", "")
    severity = finding.get("severity", "info")
    message = finding.get("message", "")
    fix = finding.get("fix")
    #If there's a suggested fix, show it directly under the message,
    #clearly marked, instead of hiding it somewhere the user has to go
    #looking for it.
    message_display = f"{message}\n  -> suggested: {fix}" if fix else message
    #Hand back the finished row tuple.
    return (ts, module, severity, message_display)


#Define FindingsView, the actual widget: a themed Treeview wrapped with
#its own scrollbar, plus the one refresh() method app.py's polling timer
#calls on a schedule. This class owns no polling loop itself - app.py
#decides how often to call refresh(), the same way it owns the decision
#for how often to drain the console queue, so there's exactly one place
#in the whole GUI that manages timers.
class FindingsView(ttk.Frame):
    #Define the constructor. palette is theme.PALETTE, handed in rather
    #than imported directly, so this file never needs to know anything
    #about theme.py beyond "here are some colors to use."
    def __init__(self, parent, palette, fonts):
        #Build the underlying ttk.Frame first.
        super().__init__(parent, style="TFrame")
        #Build the Treeview itself, with one column per field format_row()
        #produces (besides the tree's own implicit first column, which we
        #hide below since every row is a flat record, not a tree).
        self.tree = ttk.Treeview(self, columns=("time", "module", "severity", "message"), show="headings")
        #Hide the default leftmost "tree" column's indentation, since
        #there's no nesting here - every finding is its own flat row.
        self.tree.column("#0", width=0, stretch=False)
        #Label each column's header with a short, readable title. There is
        #no Host column (see format_row()'s comment above for why) - the
        #width that freed up goes straight to Message, the column that
        #actually matters most.
        for column_id, heading_text, width in (
            ("time", "Time", 150), ("module", "Module", 100),
            ("severity", "Severity", 90), ("message", "Message", 560),
        ):
            #Set this column's header text.
            self.tree.heading(column_id, text=heading_text)
            #Set this column's starting width; the message column stays
            #widest since that's where the actual content lives.
            self.tree.column(column_id, width=width, anchor="w")
        #Define one color tag per severity, matching the same palette
        #used everywhere else in the GUI - red for high, amber for
        #medium, and the ordinary text color for info (so info rows don't
        #fight for attention against the ones that actually matter).
        self.tree.tag_configure("sev_high", foreground=palette["blood_bright"])
        self.tree.tag_configure("sev_medium", foreground=palette["amber"])
        self.tree.tag_configure("sev_info", foreground=palette["text_dim"])
        #Build a vertical scrollbar wired to the tree's own yview, styled
        #to match the rest of the dark theme rather than a stock scrollbar.
        scrollbar = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        #Tell the tree to keep the scrollbar's thumb in sync as it scrolls.
        self.tree.configure(yscrollcommand=scrollbar.set)
        #Lay out the tree and its scrollbar side by side, with the tree
        #taking all the extra space as the window resizes.
        self.tree.grid(row=0, column=0, sticky="nsew")
        scrollbar.grid(row=0, column=1, sticky="ns")
        #Let the tree's row/column actually grow when this frame resizes.
        self.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)
        #Remember the last-seen row count, purely so refresh() can decide
        #whether to auto-scroll to the top (a brand new finding arrived)
        #without yanking the scrollbar out from under someone who has
        #deliberately scrolled down to read older history.
        self._last_row_count = 0

    #Define refresh, called on whatever schedule app.py sets up. Re-reads
    #everything from disk through collect_all_findings() (the same "never
    #trust a stale copy, just re-read every time" approach dashboard.py's
    #web page already uses) and repopulates every row from scratch - this
    #table is never expected to be large enough (capped at 200 rows) for
    #a full rebuild to be noticeably slow.
    def refresh(self, config):
        #Remember where the vertical scrollbar currently sits (0.0 means
        #already scrolled all the way to the top) before we rebuild
        #anything, so we can decide below whether to preserve the user's
        #own scroll position instead of always snapping back to the top.
        was_at_top = self.tree.yview()[0] == 0.0
        #Load the current findings list for the configured target.
        findings = collect_all_findings(config)
        #Remove every existing row before inserting the fresh set.
        self.tree.delete(*self.tree.get_children())
        #If there's nothing at all yet, show one friendly placeholder row
        #instead of leaving the table looking broken or empty by accident.
        if not findings:
            #Insert one explanatory row spanning the message column.
            self.tree.insert("", "end", values=("", "", "", "No findings yet."), tags=("sev_info",))
            #Remember that we showed zero real rows this time.
            self._last_row_count = 0
            #Nothing else to do.
            return
        #Insert one row per finding, in the already-newest-first order
        #collect_all_findings() returned them in.
        for finding in findings:
            #Turn this one finding into its display tuple.
            row = format_row(finding)
            #Insert it, tagged by severity so it picks up the right color.
            self.tree.insert("", "end", values=row, tags=(severity_to_tag(finding.get("severity")),))
        #If the user was already looking at the top of the list (which is
        #also where a brand new finding always appears, since the list is
        #newest-first), keep them pinned to the top so new findings are
        #immediately visible without them having to scroll up themselves.
        if was_at_top:
            #Jump the view back to the very top row.
            self.tree.yview_moveto(0.0)
        #Remember this pass's row count for next time.
        self._last_row_count = len(findings)
