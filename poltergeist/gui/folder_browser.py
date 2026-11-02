#DESCRIPTION: This file is the interactive folder browser - the direct
#             answer to "I want the entire directory to be explored just
#             like if we did it on the host machine" for Tripwire's
#             "Watch a Folder" picker. Before this file existed, picking
#             a folder meant the OS's own native dialog for a LOCAL
#             target (filedialog.askdirectory(), which can only ever see
#             THIS machine's own filesystem) or blindly TYPING a path for
#             a REMOTE target (dialogs.prompt_text(), with no way to see
#             what's actually there first). browse_for_folder() below
#             replaces BOTH of those with one real, clickable, step-into/
#             step-up browser - and it works identically for either
#             target, because it never talks to the filesystem itself.
#             Every actual folder listing comes from a small function the
#             CALLER hands in (list_dir_fn) - gui/app.py passes one that
#             calls modules/fs_browse.py directly for a local target, or
#             one that calls modules/remote.py's list_remote_directory()
#             (which runs the exact same fs_browse.py code OVER SSH on
#             the remote machine itself) for a remote one. This file has
#             no idea which kind it got, and does not need to - the
#             "deploy & run as self" design already used everywhere else
#             in this project means a remote browse always shows the
#             REMOTE machine's own real folders, never the analyst's own
#             laptop's. This file only ever READS folder listings; it
#             never creates, deletes, or changes anything on either
#             machine.

#import tkinter and ttk for the dialog window and its widgets.
import tkinter as tk
from tkinter import ttk

#import this package's own dialogs module - not for one of its public
#prompt_*/confirm_*/show_* functions (none of those fit an interactive,
#step-into/step-up browser), but to reuse its two PRIVATE helpers,
#_build_dialog_shell and _center_over_parent, so this new, more complex
#dialog still gets the exact same window chrome (dark theme, centered
#title, centered over the main window) as every other dialog in this
#project, instead of duplicating that styling code a second time here.
#Reusing a leading-underscore helper from a sibling file in the SAME
#package is fine - "private" here means "not part of dialogs.py's own
#public API for other packages," not "every other file in this package
#must never call it."
from . import dialogs

#import fs_browse only for its one WINDOWS_DRIVE_LIST_SENTINEL constant -
#the special "" value meaning "show the list of Windows drives" rather
#than any real folder - so this file can recognize that exact screen
#(and, for instance, know that "Select This Folder" makes no sense while
#looking at it) without needing to know anything else about how
#fs_browse.py itself works.
from ..modules.fs_browse import WINDOWS_DRIVE_LIST_SENTINEL


#Define _child_path, a small private helper that works out the full
#path of stepping INTO one named entry from whatever folder is currently
#being shown. This never asks the operating system anything itself (it
#has no idea whether "current_path" is even on this machine) - it just
#looks at the TEXT of current_path to guess whether it is Windows-style
#(contains a backslash, something no real Linux/macOS path ever has) or
#Linux/macOS-style, then joins with whichever separator that implies.
#This works for a remote target exactly as well as a local one, because
#the path text itself always carries the REMOTE machine's own style,
#never the analyst's own OS's.
def _child_path(current_path, entry_name):
    #A Windows drive-list entry's own "name" (e.g. "C:\\") is already a
    #complete, ready-to-browse path on its own - stepping "into" one of
    #these just means browsing to that exact string, nothing to join.
    if current_path == WINDOWS_DRIVE_LIST_SENTINEL:
        return entry_name
    #A path that already ends in a separator (a drive root like "C:\\",
    #or the Linux/macOS root "/") needs no extra separator inserted.
    if current_path.endswith("\\") or current_path.endswith("/"):
        return current_path + entry_name
    #Otherwise, guess the separator from the path's own text: a
    #backslash anywhere means Windows-style (Linux/macOS paths never
    #contain one), a forward slash otherwise.
    separator = "\\" if "\\" in current_path else "/"
    return current_path + separator + entry_name


#Define browse_for_folder, the one function this file offers. list_dir_fn
#is a function taking one argument (a path, or "" for "the OS-
#appropriate starting point") and returning a (listing, error) pair,
#exactly like modules/remote.py's own list_remote_directory()/
#list_remote_logs()/read_remote_log() already do - a plain dictionary
#(fs_browse.list_directory()'s own {"path", "parent", "entries", "error"}
#shape) on success, or (None, "a readable error message") if the browse
#could not even be attempted at all (a dropped SSH connection, for
#instance - genuinely different from "that one folder itself could not
#be listed," which comes back as a normal dictionary with its own
#"error" key instead, so Up/navigating elsewhere can still continue).
#gui/app.py builds this one function differently for a local target
#(wrapping modules/fs_browse.list_directory() directly) versus a remote
#one (wrapping modules/remote.py's list_remote_directory(), which runs
#over SSH) - this file itself never has to know or care which.
#Returns the chosen folder's full path (a string) once "Select This
#Folder" is clicked, or None if the person backed out instead (closed
#the window, pressed Escape, or clicked Cancel).
def browse_for_folder(parent, palette, fonts, title, list_dir_fn):
    #Build the shared dialog shell - same themed chrome as every other
    #dialog in this project.
    dialog, frame = dialogs._build_dialog_shell(parent, palette, fonts, title)
    #Unlike the project's small, fixed-size prompt dialogs, a folder
    #browser's content can genuinely vary a lot (a folder with 3 items
    #versus one with hundreds) - let the person resize this one.
    dialog.resizable(True, True)
    dialog.geometry("560x480")
    dialog.minsize(420, 320)

    #A label showing exactly which folder is currently being looked at -
    #updated every time the browser navigates anywhere, so the person
    #always knows where they are, the same way a file manager's own
    #address bar does.
    path_label = tk.Label(frame, text="", font=fonts["mono_small"], anchor="w", justify="left",
                           wraplength=500, background=palette["panel"], foreground=palette["glow"])
    path_label.pack(fill="x", pady=(0, 8))

    #A row holding just the "Up" button, above the listing itself - the
    #one navigation action that is always either available or not,
    #regardless of which entry (if any) is currently selected below.
    up_row = tk.Frame(frame, background=palette["panel"])
    up_row.pack(fill="x", pady=(0, 6))
    up_button = ttk.Button(up_row, text="\u2191 Up")
    up_button.pack(side="left")

    #The listing itself: a Listbox (not one-button-per-entry like
    #prompt_choice() uses - a real folder can hold far too many entries
    #for that to stay scannable) with its own vertical scrollbar. Each
    #row shows a small marker for folders (so the person can tell at a
    #glance what they can step into) versus plain files (shown for
    #context only - the point of "explored just like on the host
    #machine" is seeing everything that's actually there, not just the
    #folders - but double-clicking a FILE row does nothing, since this
    #browser only ever picks a FOLDER).
    list_frame = tk.Frame(frame, background=palette["panel"])
    list_frame.pack(fill="both", expand=True, pady=(0, 10))
    scrollbar = ttk.Scrollbar(list_frame, orient="vertical")
    listbox = tk.Listbox(list_frame, font=fonts["mono_small"], activestyle="none",
                          background=palette["panel_raised"], foreground=palette["text"],
                          selectbackground=palette["glow_dim"], selectforeground=palette["text"],
                          highlightbackground=palette["border"], highlightthickness=1, borderwidth=0,
                          yscrollcommand=scrollbar.set)
    scrollbar.configure(command=listbox.yview)
    listbox.pack(side="left", fill="both", expand=True)
    scrollbar.pack(side="right", fill="y")

    #A small status label underneath the listing - used to show a
    #folder-level error (permission denied, etc.) or a connection-level
    #one (the remote browse call itself failed), without popping a
    #separate error dialog on top of this one for every bad click.
    status_label = tk.Label(frame, text="", font=fonts["body"], wraplength=500, justify="left",
                             background=palette["panel"], foreground=palette["blood_bright"])
    status_label.pack(fill="x", pady=(0, 10))

    #This mutable state is shared between every inner function below -
    #current_listing holds whatever list_dir_fn last returned (so the
    #entry currently highlighted can be looked up again on a double-
    #click), and result_holder is the same "hand a value back out of a
    #button callback" pattern every dialog in dialogs.py already uses.
    current_listing = {"path": "", "parent": None, "entries": []}
    result_holder = [None]

    #Define navigate_to, which actually calls list_dir_fn for a given
    #path and redraws the whole dialog (path label, Up button, listing,
    #status line) to match whatever came back - the one function every
    #navigation action (the initial open, Up, double-clicking a folder)
    #funnels through, so there is exactly one place that keeps the
    #dialog's displayed state in sync with the last real listing.
    def navigate_to(path):
        #Show a quick "working on it" status - a remote browse round-
        #trips over SSH, which can take a visible moment, and a blank-
        #looking dialog during that moment reads as frozen/broken rather
        #than "waiting on the network."
        status_label.configure(text="Loading...", foreground=palette["text_dim"])
        dialog.update_idletasks()
        listing, error = list_dir_fn(path)
        if listing is None:
            #The browse call itself failed outright (a dropped SSH
            #connection, for instance) - say so, but leave whatever was
            #already being shown in place rather than clearing it, so
            #one failed click doesn't also lose the person's place.
            status_label.configure(text=f"Could not browse there: {error}", foreground=palette["blood_bright"])
            return
        #A real listing came back - remember it and redraw everything.
        current_listing["path"] = listing.get("path", "")
        current_listing["parent"] = listing.get("parent")
        current_listing["entries"] = listing.get("entries", [])
        path_label.configure(
            text="Drives" if current_listing["path"] == WINDOWS_DRIVE_LIST_SENTINEL else current_listing["path"]
        )
        #The Up button only does anything when there is a real "parent"
        #to go to - disable it outright at the true top (Linux/macOS
        #"/", or - not applicable here, since the drive list's own
        #parent is already None too) rather than leaving it clickable
        #and having it silently do nothing.
        up_button.configure(state="normal" if current_listing["parent"] is not None else "disabled")
        #Rebuild the listbox's rows from scratch for the new folder.
        listbox.delete(0, "end")
        for entry in current_listing["entries"]:
            #A small, simple text marker - a folder icon character isn't
            #guaranteed to render on every font this project already
            #falls back through (see theme.py's own font list), so a
            #plain, always-renderable "[DIR]"/"    " prefix is used
            #instead of relying on any particular glyph being present.
            marker = "[DIR]  " if entry.get("is_dir") else "       "
            listbox.insert("end", f"{marker}{entry.get('name', '')}")
        #Show this folder's own error (could not be listed at all - a
        #permission-denied subfolder, for instance) if fs_browse.py
        #reported one, otherwise clear whatever status text was showing.
        if listing.get("error"):
            status_label.configure(text=listing["error"], foreground=palette["blood_bright"])
        else:
            status_label.configure(text="", foreground=palette["blood_bright"])
        #"Select This Folder" only makes sense for a real folder, never
        #for the Windows drive-list pseudo-screen (there is no single
        #real path "the drive list" itself names).
        select_button.configure(
            state="disabled" if current_listing["path"] == WINDOWS_DRIVE_LIST_SENTINEL else "normal"
        )

    #Define on_up, run when the Up button is clicked - simply navigates
    #to whatever "parent" the last listing reported.
    def on_up():
        if current_listing["parent"] is not None:
            navigate_to(current_listing["parent"])
    up_button.configure(command=on_up)

    #Define on_double_click, run when a listbox row is double-clicked -
    #steps INTO that entry if (and only if) it is itself a directory;
    #double-clicking a plain file row does nothing at all, since this
    #browser only ever picks a folder to watch, never a file.
    def on_double_click(event=None):
        selection = listbox.curselection()
        if not selection:
            return
        index = selection[0]
        if index >= len(current_listing["entries"]):
            #Defensive only - the listbox and current_listing["entries"]
            #are always rebuilt together in navigate_to, so this should
            #never actually happen, but a stale index should never be
            #allowed to look up the wrong entry.
            return
        entry = current_listing["entries"][index]
        if entry.get("is_dir"):
            navigate_to(_child_path(current_listing["path"], entry.get("name", "")))
    listbox.bind("<Double-Button-1>", on_double_click)
    #Let Enter on a highlighted row do the same thing a double-click
    #does, for anyone navigating by keyboard instead of a mouse.
    listbox.bind("<Return>", on_double_click)

    #Define on_select, run when "Select This Folder" is clicked - the
    #CURRENT folder being shown (not whatever row happens to be
    #highlighted) is the one that gets chosen, the same way a native
    #OS folder picker works: double-click to go deeper, but the button
    #confirms "this one, right here," not "whatever I last clicked on."
    def on_select():
        result_holder[0] = current_listing["path"]
        dialog.destroy()

    #Define on_cancel, run on Cancel/Escape/the window's own [X] - all
    #three leave result_holder as None, meaning "the person backed out."
    def on_cancel(event=None):
        dialog.destroy()

    #Build the bottom button row: Cancel on the right (familiar
    #position, matches every other dialog here), "Select This Folder"
    #just to its left.
    button_row = tk.Frame(frame, background=palette["panel"])
    button_row.pack(fill="x")
    ttk.Button(button_row, text="Cancel", command=on_cancel).pack(side="right", padx=(8, 0))
    select_button = ttk.Button(button_row, text="Select This Folder", command=on_select)
    select_button.pack(side="right")

    #Let Escape cancel, same as every other dialog in this project.
    dialog.bind("<Escape>", on_cancel)
    dialog.protocol("WM_DELETE_WINDOW", on_cancel)

    #Do the very first listing (an empty path means "the OS-appropriate
    #starting point" - fs_browse.py's own default_start_path()/Windows-
    #drive-list branch, whichever applies on whichever machine this
    #ends up actually running against) before the dialog is even shown,
    #so the person never sees a blank, unpopulated browser for a moment.
    navigate_to("")

    #Center and show the dialog, then block until it's answered - same
    #blocking pattern every dialog in dialogs.py already uses.
    dialogs._center_over_parent(dialog, parent)
    dialog.grab_set()
    parent.wait_window(dialog)
    #Hand back whichever folder was selected, or None.
    return result_holder[0]
