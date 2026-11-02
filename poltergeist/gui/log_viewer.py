#DESCRIPTION: This file is the new "View System Logs" experience - the
#             direct answer to "be able to pull the logs on that
#             monitored machine even if ssh'd in and be able to select
#             the log you want to view and it opens... it scans for the
#             big things that could help you find IOC's but also lets
#             you go through them and look as well as a search bar
#             available." Before this file existed, "View System Logs"
#             (gui/app.py's old _handle_view_logs) worked for a LOCAL
#             target only, dumped EVERY log/channel into one giant
#             static window with no way to search it, and refused
#             outright for a remote target. view_logs() below replaces
#             all of that with: (1) a picker so the person chooses ONE
#             log/channel at a time (Windows Event Log channels when the
#             target is Windows, same as list_available_logs() already
#             worked out), (2) that one log opening in its own viewer
#             with the "WORTH A LOOK" IOC summary shown first, (3) the
#             full raw text below it, scrollable, and (4) a live search
#             box that highlights every match inside the raw text as you
#             type. Exactly like gui/folder_browser.py, this file never
#             talks to a log file or wevtutil/journalctl itself - every
#             real read comes from a pair of functions the CALLER hands
#             in (list_logs_fn/read_log_fn). gui/app.py builds those two
#             differently for a local target (calling
#             modules/log_review.py directly) versus a remote one
#             (calling modules/remote.py's list_remote_logs()/
#             read_remote_log(), which run the exact same log_review.py
#             code OVER SSH on the remote machine itself) - this file has
#             no idea which kind it got, and does not need to. Like
#             log_review.read_log_content() itself, this file only ever
#             READS logs - it never writes to findings.jsonl (check()
#             already does that on its own schedule) and never modifies
#             anything on either machine.

#import tkinter and ttk for the dialog window and its widgets.
import tkinter as tk
from tkinter import ttk

#import this package's own dialogs module, for its two private shared
#dialog-shell helpers - same reasoning as gui/folder_browser.py's own
#identical import: reusing dialogs.py's window chrome keeps every
#dialog in this project looking consistent instead of duplicating that
#styling code a second time here.
from . import dialogs

#import log_review only for its format_findings_summary() function - the
#"WORTH A LOOK" text renderer - so this file never has to know anything
#about how a finding's (severity, key, message) tuple is actually built,
#only how to display the already-sorted, already-worded summary text.
from ..modules import log_review


#Define _SEVERITY_TAG_COLORS, mapping each severity word to a palette
#key used to color that word inside the "WORTH A LOOK" summary text -
#reusing this project's existing color convention (high=blood/red,
#medium=amber, info=cyan) rather than inventing a new one just for this
#one summary box.
_SEVERITY_TAG_COLORS = {"HIGH": "blood_bright", "MEDIUM": "amber", "INFO": "cyan"}


#Define view_logs, the one function this file offers. list_logs_fn takes
#no arguments and returns a (list_of_{"id","label"}_dicts_or_None, error)
#pair; read_log_fn takes one log id and returns a
#({"name","raw_text","findings",...}_or_None, error) pair - both exactly
#matching modules/remote.py's own (result, error) convention, so
#gui/app.py can build either the local or the remote version of each
#without this file ever branching on which one it got. title is shown
#as the dialog's own window title (gui/app.py passes something like
#"View System Logs (local target)" or "...(remote target)" so the
#person always knows which machine they're actually looking at).
def view_logs(parent, palette, fonts, title, list_logs_fn, read_log_fn):
    #Ask for the list of logs/channels THIS machine actually has before
    #building any window at all - if that fails outright, there is
    #nothing to show a picker for.
    available_logs, list_error = list_logs_fn()
    if available_logs is None:
        dialogs.show_message(parent, palette, fonts, title,
                              f"Could not get the list of logs: {list_error}", kind="error")
        return
    if not available_logs:
        #Should not normally happen (list_available_logs() always offers
        #at least a journalctl fallback on Linux), but handled anyway
        #rather than assumed.
        dialogs.show_message(parent, palette, fonts, title, "No logs were found on this machine.")
        return

    #Build the shared dialog shell - same themed chrome as every other
    #dialog in this project.
    dialog, frame = dialogs._build_dialog_shell(parent, palette, fonts, title)
    #A log's raw text can run from a handful of lines to several
    #thousand - let this one be resized, the same reasoning
    #show_scrollable_text() already uses for exactly this kind of content.
    dialog.resizable(True, True)
    dialog.geometry("900x650")
    dialog.minsize(620, 420)

    #--- top row: the log/channel picker itself ---
    picker_row = tk.Frame(frame, background=palette["panel"])
    picker_row.pack(fill="x", pady=(0, 8))
    tk.Label(picker_row, text="Log:", font=fonts["body"], background=palette["panel"],
              foreground=palette["text"]).pack(side="left")
    #Map each picker label back to its own "id" (what read_log_fn()
    #actually expects), since the Combobox itself only ever shows/returns
    #the human-readable label text.
    id_by_label = {entry["label"]: entry["id"] for entry in available_logs}
    selected_label = tk.StringVar(value=available_logs[0]["label"])
    picker = ttk.Combobox(picker_row, textvariable=selected_label, state="readonly", width=56,
                           values=[entry["label"] for entry in available_logs])
    picker.pack(side="left", padx=(8, 8))
    #A small status label, reused both for "Loading..." while a (possibly
    #remote, over-SSH) read is in flight, and for a line-count/error
    #summary once it finishes.
    status_label = tk.Label(picker_row, text="", font=fonts["body"], background=palette["panel"],
                             foreground=palette["text_dim"])
    status_label.pack(side="left")

    #--- search row ---
    search_row = tk.Frame(frame, background=palette["panel"])
    search_row.pack(fill="x", pady=(0, 8))
    tk.Label(search_row, text="Search:", font=fonts["body"], background=palette["panel"],
              foreground=palette["text"]).pack(side="left")
    search_var = tk.StringVar()
    search_entry = tk.Entry(search_row, textvariable=search_var, font=fonts["mono"], width=36,
                             background=palette["panel_raised"], foreground=palette["text"],
                             insertbackground=palette["text"], highlightbackground=palette["border"],
                             highlightcolor=palette["glow"], highlightthickness=1, relief="flat")
    search_entry.pack(side="left", padx=(8, 8))
    match_label = tk.Label(search_row, text="", font=fonts["body"], background=palette["panel"],
                             foreground=palette["text_dim"])
    match_label.pack(side="left")

    #--- the "WORTH A LOOK" summary, above the raw text itself ---
    summary_heading = tk.Label(frame, text="WORTH A LOOK", font=fonts["heading"], anchor="w",
                                background=palette["panel"], foreground=palette["glow"])
    summary_heading.pack(fill="x", pady=(4, 0))
    summary_text_widget = tk.Text(frame, font=fonts["mono_small"], height=5, wrap="word",
                                   background=palette["panel_raised"], foreground=palette["text"],
                                   borderwidth=0, highlightthickness=1, highlightbackground=palette["border"])
    summary_text_widget.pack(fill="x", pady=(2, 10))
    #Color each severity WORD inside the summary - these tags are
    #created once, up front, and simply applied/re-applied to fresh text
    #every time a log is (re)loaded below.
    for severity_word, color_key in _SEVERITY_TAG_COLORS.items():
        summary_text_widget.tag_configure(severity_word, foreground=palette[color_key])
    #The summary is a read-only report, same as every other text area in
    #this project's dialogs - the person can select/copy it, never edit it.
    summary_text_widget.configure(state="disabled")

    #--- the raw log text itself, scrollable in both directions ---
    text_frame = tk.Frame(frame, background=palette["panel"])
    text_frame.pack(fill="both", expand=True, pady=(0, 10))
    v_scrollbar = ttk.Scrollbar(text_frame, orient="vertical")
    h_scrollbar = ttk.Scrollbar(text_frame, orient="horizontal")
    text_widget = tk.Text(text_frame, font=fonts["mono_small"], wrap="none",
                           background=palette["bg"], foreground=palette["text"],
                           insertbackground=palette["text"], borderwidth=0, highlightthickness=1,
                           highlightbackground=palette["border"],
                           yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
    v_scrollbar.configure(command=text_widget.yview)
    h_scrollbar.configure(command=text_widget.xview)
    text_widget.grid(row=0, column=0, sticky="nsew")
    v_scrollbar.grid(row=0, column=1, sticky="ns")
    h_scrollbar.grid(row=1, column=0, sticky="ew")
    text_frame.rowconfigure(0, weight=1)
    text_frame.columnconfigure(0, weight=1)
    #The raw text is read-only, same reasoning as everywhere else - this
    #is a report to read and search, not a document to edit.
    text_widget.configure(state="disabled")
    #A single search-highlight tag - applied to the (possibly many)
    #matches found by do_search() below, cleared and rebuilt on every
    #keystroke/log switch rather than left stale from a previous search.
    text_widget.tag_configure("search_hit", background=palette["glow_dim"], foreground=palette["bg"])

    #Define clear_search_highlights, removing every current search-hit
    #tag and resetting the match-count label - called both before a
    #fresh search runs and whenever the displayed log itself changes
    #(switching logs with an old highlight still showing would be
    #confusing, since it would no longer mean anything in the new text).
    def clear_search_highlights():
        text_widget.tag_remove("search_hit", "1.0", "end")
        match_label.configure(text="")

    #Define do_search, run on every keystroke in the search box - finds
    #and highlights EVERY occurrence of the typed text inside the
    #currently-shown raw log (case-insensitive, since an IOC like an IP
    #address or a username is just as relevant regardless of case), and
    #scrolls to the first match so the person doesn't have to go hunting
    #for where it landed.
    def do_search(event=None):
        clear_search_highlights()
        query = search_var.get()
        if not query:
            #An empty search box means "show nothing highlighted," not
            #"highlight everything" - there is nothing useful to find.
            return
        search_start = "1.0"
        match_count = 0
        first_match_position = None
        while True:
            #Text.search() returns the position of the next match at or
            #after search_start, or "" once there are no more - exactly
            #the loop shape needed to find every occurrence, not just
            #the first one.
            match_position = text_widget.search(query, search_start, stopindex="end", nocase=True)
            if not match_position:
                break
            match_end_position = f"{match_position}+{len(query)}c"
            text_widget.tag_add("search_hit", match_position, match_end_position)
            if first_match_position is None:
                first_match_position = match_position
            #Continue searching from right after this match, so
            #overlapping/adjacent occurrences are never skipped or
            #double-counted.
            search_start = match_end_position
            match_count += 1
        if first_match_position:
            #Scroll so the very first match is actually visible,
            #instead of leaving the person to scroll and hunt for it
            #themselves after typing a search term.
            text_widget.see(first_match_position)
        match_label.configure(text=f"{match_count} match{'es' if match_count != 1 else ''}")
    search_entry.bind("<KeyRelease>", do_search)

    #Define load_selected_log, which actually fetches (locally or, for a
    #remote target, over SSH) and displays whichever log is currently
    #chosen in the picker - the one function both the initial load and
    #every later picker selection funnel through, so the dialog's
    #displayed content always matches whatever is currently selected.
    def load_selected_log(event=None):
        log_id = id_by_label.get(selected_label.get())
        if log_id is None:
            #Should not be reachable (the picker only ever offers labels
            #from id_by_label's own keys), but guarded rather than assumed.
            return
        #Show a quick "working on it" status - a remote read round-trips
        #over SSH (and, for Windows Event Logs, runs wevtutil on the far
        #end), which can take a visible moment; a blank-looking dialog
        #during that pause would read as frozen rather than "waiting."
        status_label.configure(text="Loading...", foreground=palette["text_dim"])
        dialog.update_idletasks()
        result, error = read_log_fn(log_id)
        #Always clear any leftover search state from whatever log was
        #showing before - a highlight or match count from the PREVIOUS
        #log means nothing once the text underneath it has changed.
        search_var.set("")
        clear_search_highlights()
        if result is None or result.get("error"):
            #Either the read failed outright (error, with result=None),
            #or it succeeded but reported a specific problem (an
            #unrecognized Windows channel name, for instance, from
            #log_review.read_log_content()'s own "error" key) - either
            #way, say so plainly in place of the raw text, rather than
            #showing stale content from the last successfully loaded log.
            failure_reason = error or (result or {}).get("error", "could not load this log")
            text_widget.configure(state="normal")
            text_widget.delete("1.0", "end")
            text_widget.insert("end", f"(could not load this log: {failure_reason})")
            text_widget.configure(state="disabled")
            summary_text_widget.configure(state="normal")
            summary_text_widget.delete("1.0", "end")
            summary_text_widget.configure(state="disabled")
            status_label.configure(text="", foreground=palette["blood_bright"])
            return
        raw_text = result.get("raw_text", "")
        findings = result.get("findings", [])
        #Fill the raw-text area.
        text_widget.configure(state="normal")
        text_widget.delete("1.0", "end")
        text_widget.insert("end", raw_text if raw_text else "(nothing to show - this log is currently empty)")
        text_widget.configure(state="disabled")
        #Fill the "WORTH A LOOK" summary, coloring each severity word as
        #it's inserted - format_findings_summary() already sorts most-
        #severe first and renders each line as "[SEVERITY] message",
        #so the severity word is always the first bracketed token on
        #each line, which is what's searched for and tagged below.
        summary_text_widget.configure(state="normal")
        summary_text_widget.delete("1.0", "end")
        summary_text = log_review.format_findings_summary(findings)
        for line in summary_text.splitlines():
            line_start_index = summary_text_widget.index("end-1c")
            summary_text_widget.insert("end", line + "\n")
            for severity_word in _SEVERITY_TAG_COLORS:
                if line.startswith(f"[{severity_word}]"):
                    summary_text_widget.tag_add(severity_word, line_start_index,
                                                 f"{line_start_index} lineend")
        summary_text_widget.configure(state="disabled")
        #Show a quick line-count status, so the person has some sense of
        #how much raw text they're looking at.
        line_count = len(raw_text.splitlines())
        status_label.configure(text=f"{line_count} line{'s' if line_count != 1 else ''}",
                                 foreground=palette["text_dim"])
    picker.bind("<<ComboboxSelected>>", load_selected_log)

    #Build the bottom button row - just Close, since this dialog never
    #asks for confirmation of anything (it only ever reads).
    button_row = tk.Frame(frame, background=palette["panel"])
    button_row.pack(fill="x")
    ttk.Button(button_row, text="Close", command=dialog.destroy).pack(side="right")

    #Let Escape close the dialog the same way every other dialog in this
    #project treats it, EXCEPT while the search box itself has focus -
    #Escape there should clear the search instead of closing the whole
    #viewer, which is what most people expect from a search field.
    def on_escape(event=None):
        if dialog.focus_get() is search_entry and search_var.get():
            search_var.set("")
            clear_search_highlights()
            return
        dialog.destroy()
    dialog.bind("<Escape>", on_escape)
    dialog.protocol("WM_DELETE_WINDOW", dialog.destroy)

    #Load whichever log is selected first (always available_logs[0], the
    #very first picker entry) before the dialog is even shown, so the
    #person never sees a blank, unpopulated viewer for a moment.
    load_selected_log()

    #Center and show the dialog, then block until it's closed - same
    #blocking pattern every dialog in dialogs.py already uses.
    dialogs._center_over_parent(dialog, parent)
    dialog.grab_set()
    parent.wait_window(dialog)
