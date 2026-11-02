#DESCRIPTION: This file replaces Tkinter's stock popup dialogs (the
#             plain, light-gray simpledialog/messagebox boxes) with
#             small themed windows that actually match the rest of the
#             gothic GUI instead of looking like a totally different
#             program flashed on screen for a second. Three shapes cover
#             every place the GUI needs to ask something: a short typed
#             answer (a Shield rule, a folder path, an SSH key passphrase -
#             see mask= below), a TYPED confirmation word rather than a
#             single click (used for Shield: MUTE and Reset Baseline, on
#             purpose - the CLI menu already makes you type the exact
#             word instead of just clicking a button for both of those,
#             specifically because each one is hard to undo blind, and
#             this GUI keeps that exact same friction instead of quietly
#             making it easier to trigger by accident), and a
#             plain message popup for showing a result or an error. Every
#             one of these blocks (it waits for the person to answer
#             before the rest of the GUI continues), which is the right
#             behavior for a question that the next step actually depends
#             on the answer to.

#import tkinter and ttk for the actual dialog windows and buttons.
import tkinter as tk
from tkinter import ttk


#Define _build_dialog_shell, a small shared helper every function below
#uses so all three dialog shapes share the exact same window chrome
#(centered over the main window, themed background, a title label) and
#only differ in which input widget (if any) goes in the middle.
def _build_dialog_shell(parent, palette, fonts, title_text):
    #Build the dialog as a Toplevel - its own real window, not a widget
    #embedded in the main one.
    dialog = tk.Toplevel(parent)
    #Tie it to the main window so it minimizes/restores together with it
    #and always appears in front of it, not behind.
    dialog.transient(parent)
    #Paint the dialog itself with the same dark background as everywhere
    #else, so it never flashes up as a jarring plain gray box.
    dialog.configure(background=palette["bg"])
    #Give the dialog a real OS title bar caption too, for anyone tabbing
    #between windows or glancing at the taskbar.
    dialog.title(title_text)
    #Prevent the dialog from being resized - every one of these is a
    #small, fixed-purpose popup, not a window worth letting grow oddly.
    dialog.resizable(False, False)
    #Build the outer padded frame everything else sits inside.
    frame = tk.Frame(dialog, background=palette["panel"], padx=20, pady=16,
                      highlightbackground=palette["glow_dim"], highlightthickness=1)
    #Let the frame fill the whole dialog window.
    frame.pack(fill="both", expand=True)
    #Draw the title text itself, in the glow color, at the top of the frame.
    title_label = tk.Label(frame, text=title_text, font=fonts["heading"],
                            background=palette["panel"], foreground=palette["glow"])
    #Place it with a little breathing room below it before the next widget.
    title_label.pack(anchor="w", pady=(0, 10))
    #Hand back both the dialog window and the frame other widgets go into.
    return dialog, frame


#Define _center_over_parent, which moves a just-built dialog to sit
#centered over its parent window instead of wherever the OS happens to
#place a brand new window (often the screen's top-left corner).
def _center_over_parent(dialog, parent):
    #Force Tk to compute the dialog's actual requested size first, since
    #winfo_width()/height() report 0 before a window has been drawn once.
    dialog.update_idletasks()
    #Read the parent window's current position and size.
    parent_x, parent_y = parent.winfo_rootx(), parent.winfo_rooty()
    parent_w, parent_h = parent.winfo_width(), parent.winfo_height()
    #Read the dialog's own requested size.
    dialog_w, dialog_h = dialog.winfo_width(), dialog.winfo_height()
    #Compute the top-left corner that centers the dialog over the parent.
    x = parent_x + (parent_w - dialog_w) // 2
    y = parent_y + (parent_h - dialog_h) // 2
    #Move the dialog there, keeping its already-computed size.
    dialog.geometry(f"+{max(x, 0)}+{max(y, 0)}")


#Define prompt_text, which asks for one line of typed text and returns
#whatever the person typed, or None if they cancelled (closed the window
#or pressed Escape) instead of confirming. Used for a Shield rule, a
#Tripwire folder path, and (with mask=True) a mid-wizard SSH key
#passphrase retry - see modules/remote.py and the setup wizard's own
#docstring for why a passphrase is never written anywhere but held in
#memory for one typed answer at a time, same as here.
def prompt_text(parent, palette, fonts, title, message, initial_value="", mask=False):
    #Build the shared dialog shell.
    dialog, frame = _build_dialog_shell(parent, palette, fonts, title)
    #Show the explanatory message text above the input box, wrapped so a
    #longer explanation still fits.
    tk.Label(frame, text=message, font=fonts["body"], wraplength=360, justify="left",
              background=palette["panel"], foreground=palette["text"]).pack(anchor="w", pady=(0, 8))
    #Build the actual text entry, pre-filled with any given default. A
    #secret answer (mask=True) is never pre-filled regardless of whatever
    #initial_value was passed, for the same reason a secret field never
    #starts pre-filled anywhere else in this project - there is never a
    #saved value to show back, since one is never written to disk.
    entry_value = tk.StringVar(value="" if mask else initial_value)
    entry = tk.Entry(frame, textvariable=entry_value, font=fonts["mono"], width=42, show="*" if mask else "",
                      background=palette["panel_raised"], foreground=palette["text"],
                      insertbackground=palette["text"], highlightbackground=palette["border"],
                      highlightcolor=palette["glow"], highlightthickness=1, relief="flat")
    entry.pack(fill="x", pady=(0, 14))
    #Put the keyboard focus straight into the entry and select any
    #pre-filled text, so typing immediately replaces it.
    entry.focus_set()
    entry.select_range(0, "end")
    #This plain list is how the button callbacks below hand their answer
    #back out to the code that's about to block on wait_window() - a
    #mutable container is needed since a button's own click handler
    #can't simply "return" a value to whoever called prompt_text().
    result_holder = [None]

    #Define the inner function that runs when OK (or Enter) is pressed.
    def on_confirm(event=None):
        #Record whatever is currently typed as the result.
        result_holder[0] = entry_value.get()
        #Close the dialog, which lets wait_window() below return.
        dialog.destroy()

    #Define the inner function that runs when Cancel (or Escape) is pressed.
    def on_cancel(event=None):
        #Leave result_holder as None, meaning "the person cancelled."
        dialog.destroy()

    #Build a row to hold the two buttons, right-aligned.
    button_row = tk.Frame(frame, background=palette["panel"])
    button_row.pack(fill="x")
    #Build Cancel first so it sits to the left of OK, a familiar order.
    ttk.Button(button_row, text="Cancel", command=on_cancel).pack(side="right", padx=(8, 0))
    ttk.Button(button_row, text="OK", command=on_confirm).pack(side="right")
    #Let the Enter key confirm and the Escape key cancel, so a keyboard-
    #only user never has to reach for the mouse.
    dialog.bind("<Return>", on_confirm)
    dialog.bind("<Escape>", on_cancel)
    #Treat the window's own close button (the OS "X") the same as Cancel.
    dialog.protocol("WM_DELETE_WINDOW", on_cancel)
    #Now that every widget is built, center the dialog over the main window.
    _center_over_parent(dialog, parent)
    #Take the input focus for the WHOLE application, not just this
    #window, so the person can't click back into the main window and
    #leave this dialog open and forgotten behind it.
    dialog.grab_set()
    #Block right here until the dialog is closed one way or the other.
    parent.wait_window(dialog)
    #Hand back whatever on_confirm/on_cancel left in result_holder.
    return result_holder[0]


#Define prompt_choice, which shows one button per item in a short list of
#choices (never a dropdown/listbox - this project's watched-folder lists
#are capped at MAX_WATCHED_PATHS, 3, by tripwire.py itself, so one button
#per folder is always a short, scannable row, not an unbounded list that
#would need scrolling) and returns whichever one was clicked, or None if
#the person cancelled. Used for "Tripwire: Stop Watching a Folder" - the
#one case in this GUI where the person picks an EXISTING item rather than
#typing or browsing to a new one.
def prompt_choice(parent, palette, fonts, title, message, choices):
    #Build the shared dialog shell.
    dialog, frame = _build_dialog_shell(parent, palette, fonts, title)
    #Show the explanatory message above the list of choice buttons.
    tk.Label(frame, text=message, font=fonts["body"], wraplength=420, justify="left",
              background=palette["panel"], foreground=palette["text"]).pack(anchor="w", pady=(0, 10))
    #Same mutable-container pattern prompt_text() above uses to hand a
    #button click's answer back out to the wait_window() call below.
    result_holder = [None]

    #Define the inner function run when any one choice button is clicked.
    def on_choose(choice):
        #Record exactly which choice was clicked.
        result_holder[0] = choice
        #Close the dialog, which lets wait_window() below return.
        dialog.destroy()

    #Define the inner function that runs when Cancel (or Escape) is pressed.
    def on_cancel(event=None):
        #Leave result_holder as None, meaning "the person cancelled."
        dialog.destroy()

    #Build one full-width button per choice, stacked vertically - a
    #folder path is often too long to sit comfortably side-by-side with
    #its siblings, and there are never more than a handful of these.
    for choice in choices:
        ttk.Button(frame, text=choice, command=lambda c=choice: on_choose(c)).pack(fill="x", pady=(0, 6))
    #Build the Cancel button on its own row, below every choice.
    button_row = tk.Frame(frame, background=palette["panel"])
    button_row.pack(fill="x", pady=(4, 0))
    ttk.Button(button_row, text="Cancel", command=on_cancel).pack(side="right")
    #Let Escape cancel, same as every other dialog shape in this file -
    #there is no single "default" choice here for Enter to confirm.
    dialog.bind("<Escape>", on_cancel)
    #Treat the window's own close button (the OS "X") the same as Cancel.
    dialog.protocol("WM_DELETE_WINDOW", on_cancel)
    #Now that every widget is built, center the dialog over the main window.
    _center_over_parent(dialog, parent)
    #Take the input focus for the whole application, same reason as
    #every other dialog shape here.
    dialog.grab_set()
    #Block right here until the dialog is closed one way or the other.
    parent.wait_window(dialog)
    #Hand back whichever choice was clicked, or None.
    return result_holder[0]


#Define confirm_typed, the deliberately-stricter version of prompt_text
#used ONLY for Shield: MUTE. It still looks like an ordinary text prompt,
#but the Confirm button only actually confirms if the typed text matches
#required_word EXACTLY - anything else (including leaving it blank or
#just clicking Confirm with nothing typed) is treated as a cancel. This
#mirrors the text menu's own "type MUTE to confirm" behavior exactly.
def confirm_typed(parent, palette, fonts, title, message, required_word):
    #Build the shared dialog shell.
    dialog, frame = _build_dialog_shell(parent, palette, fonts, title)
    #Show the explanatory message, which should itself already tell the
    #person which word to type (the caller supplies that wording).
    tk.Label(frame, text=message, font=fonts["body"], wraplength=360, justify="left",
              background=palette["panel"], foreground=palette["text"]).pack(anchor="w", pady=(0, 8))
    #Build the entry the same way prompt_text does, but never pre-filled -
    #a dangerous confirmation should never start with the right answer
    #already sitting there to accidentally confirm.
    entry_value = tk.StringVar(value="")
    entry = tk.Entry(frame, textvariable=entry_value, font=fonts["mono"], width=42,
                      background=palette["panel_raised"], foreground=palette["text"],
                      insertbackground=palette["text"], highlightbackground=palette["blood"],
                      highlightcolor=palette["blood_bright"], highlightthickness=1, relief="flat")
    entry.pack(fill="x", pady=(0, 14))
    entry.focus_set()
    #This holds the final True/False result.
    result_holder = [False]

    #Define what happens when Confirm is pressed.
    def on_confirm(event=None):
        #Only succeed if the typed text matches the required word exactly -
        #no trimming, no case-insensitivity, same strictness as the CLI.
        result_holder[0] = (entry_value.get() == required_word)
        #Close the dialog either way; a wrong answer is just a "no."
        dialog.destroy()

    #Define what happens when Cancel is pressed.
    def on_cancel(event=None):
        #Leave result_holder as False.
        dialog.destroy()

    #Build the button row, using the Danger.TButton style for Confirm
    #specifically - purely a naming/plumbing choice at this point (see
    #theme.py's own apply_theme() comment on Danger.TButton), not a
    #visual one; this button now looks like any other.
    button_row = tk.Frame(frame, background=palette["panel"])
    button_row.pack(fill="x")
    ttk.Button(button_row, text="Cancel", command=on_cancel).pack(side="right", padx=(8, 0))
    ttk.Button(button_row, text="Confirm", style="Danger.TButton", command=on_confirm).pack(side="right")
    #Wire the same keyboard shortcuts as prompt_text.
    dialog.bind("<Return>", on_confirm)
    dialog.bind("<Escape>", on_cancel)
    dialog.protocol("WM_DELETE_WINDOW", on_cancel)
    #Center and show the dialog the same way prompt_text does.
    _center_over_parent(dialog, parent)
    dialog.grab_set()
    parent.wait_window(dialog)
    #Hand back the final True/False answer.
    return result_holder[0]


#Define confirm_yes_no, a plain "are you sure?" popup with just two
#buttons and no typed word to get right - used wherever a single click is
#enough friction for the warning to do its job (quitting the whole app,
#re-opening Setup and silently resetting the baseline lock), as opposed
#to confirm_typed() above, reserved for the handful of actions serious
#enough to need a WORD typed back (Shield: MUTE). Returns True only if
#the person actually clicked the confirm button; closing the window,
#pressing Escape, or clicking Cancel all return False the same way.
def confirm_yes_no(parent, palette, fonts, title, message, confirm_label="OK", cancel_label="Cancel", danger=False):
    #Build the shared dialog shell.
    dialog, frame = _build_dialog_shell(parent, palette, fonts, title)
    #Show the explanatory message, wrapped the same way every other
    #dialog's message text is.
    tk.Label(frame, text=message, font=fonts["body"], wraplength=380, justify="left",
              background=palette["panel"], foreground=palette["text"]).pack(anchor="w", pady=(0, 14))
    #This holds the final True/False result, exactly like confirm_typed's
    #own result_holder.
    result_holder = [False]

    #Define what happens when the confirm button is pressed.
    def on_confirm(event=None):
        result_holder[0] = True
        dialog.destroy()

    #Define what happens when Cancel (or Escape, or the window's own [X])
    #is pressed - all three count as "no", never as "yes by default".
    def on_cancel(event=None):
        #result_holder already starts as False; nothing to change.
        dialog.destroy()

    #Build the button row. The confirm button uses the Danger.TButton
    #style when danger=True (quitting, resetting a baseline) - visually
    #identical to the ordinary style now (see theme.py's own comment on
    #Danger.TButton), kept as a separate name/flag so a future danger
    #action can still be singled out visually again with one line
    #changed in theme.py alone.
    button_row = tk.Frame(frame, background=palette["panel"])
    button_row.pack(fill="x")
    ttk.Button(button_row, text=cancel_label, command=on_cancel).pack(side="right", padx=(8, 0))
    ttk.Button(button_row, text=confirm_label, style="Danger.TButton" if danger else "TButton",
               command=on_confirm).pack(side="right")
    #Enter confirms, Escape cancels, same as every other dialog here.
    dialog.bind("<Return>", on_confirm)
    dialog.bind("<Escape>", on_cancel)
    dialog.protocol("WM_DELETE_WINDOW", on_cancel)
    #Center and show the dialog, then block until it's answered.
    _center_over_parent(dialog, parent)
    dialog.grab_set()
    parent.wait_window(dialog)
    #Hand back the final True/False answer.
    return result_holder[0]


#Define show_message, a plain "here's some information, click OK" popup
#used for quick results and errors that don't need any typed input at
#all. kind picks which accent color the title uses - "error" shows up in
#the blood-red accent, anything else uses the ordinary glow color.
def show_message(parent, palette, fonts, title, message, kind="info"):
    #Build the shared dialog shell.
    dialog, frame = _build_dialog_shell(parent, palette, fonts, title)
    #If this is an error message, re-color the title label we just built
    #(the last widget packed into frame) to the alarming red accent
    #instead of the default glow color.
    if kind == "error":
        #The title label is always the first child packed into frame.
        frame.winfo_children()[0].configure(foreground=palette["blood_bright"])
    #Show the actual message text, wrapped for readability.
    tk.Label(frame, text=message, font=fonts["body"], wraplength=380, justify="left",
              background=palette["panel"], foreground=palette["text"]).pack(anchor="w", pady=(0, 14))
    #A single OK button closes the dialog; there's nothing to confirm or
    #cancel here, just something to acknowledge.
    button_row = tk.Frame(frame, background=palette["panel"])
    button_row.pack(fill="x")
    ttk.Button(button_row, text="OK", command=dialog.destroy).pack(side="right")
    #Let Enter or Escape both just close it, same as clicking OK.
    dialog.bind("<Return>", lambda event: dialog.destroy())
    dialog.bind("<Escape>", lambda event: dialog.destroy())
    dialog.protocol("WM_DELETE_WINDOW", dialog.destroy)
    #Center and show it, then block until it's closed.
    _center_over_parent(dialog, parent)
    dialog.grab_set()
    parent.wait_window(dialog)


#Define show_scrollable_text, a bigger, resizable sibling of
#show_message() above - used wherever the content itself is long enough
#to need scrolling rather than just a wrapped paragraph: the "View
#System Logs" button's raw log tail, and the "Upload Log" button's
#multi-line analysis summary. Unlike every other dialog shape in this
#file, this one IS resizable (a fixed-size popup makes no sense for
#content whose length varies from "a handful of lines" to "a few
#thousand"), and its text area is read-only (state="disabled") the same
#way the main window's own Output console pane is, for the same reason:
#this is a report to read, not a document to edit.
def show_scrollable_text(parent, palette, fonts, title, text, wrap="none"):
    #Build the shared dialog shell.
    dialog, frame = _build_dialog_shell(parent, palette, fonts, title)
    #Unlike every other dialog here, let this one be resized - log
    #content can run from a few lines to a few thousand.
    dialog.resizable(True, True)
    #Give it a sensible starting size; the person can grow it from here.
    dialog.geometry("820x520")
    #Build the scrollable text area itself: a monospace, read-only Text
    #widget with its own vertical scrollbar, matching the console pane's
    #own styling in app.py.
    #
    #wrap defaults to "none" (unwrapped, needing a horizontal scrollbar
    #to see the rest of a long line) because that is the right call for
    #this dialog's OTHER callers - raw log text and command/path-heavy
    #scan results, where mid-word wrapping would make a long path or
    #command harder to read, not easier, and a person already expects to
    #scroll sideways through "real log file" content. The Help dialog
    #("What does everything do?") is the one caller that wants prose-
    #style word wrapping instead - its own long, plain-English
    #descriptions were getting cut off flush against the right edge with
    #no horizontal scrollbar built for this dialog at all, which read as
    #the dialog being broken rather than just needing a sideways scroll -
    #so that one call passes wrap="word" explicitly (see app.py's
    #_show_help). Build the matching horizontal scrollbar only when
    #wrap="none" actually needs one; a word-wrapped widget has no
    #horizontal scroll position to offer and showing one anyway would
    #just be a second, permanently-useless scrollbar.
    text_frame = tk.Frame(frame, background=palette["panel"])
    text_frame.pack(fill="both", expand=True, pady=(0, 14))
    v_scrollbar = ttk.Scrollbar(text_frame, orient="vertical")
    text_widget = tk.Text(
        text_frame, font=fonts["mono_small"], wrap=wrap, background=palette["bg"],
        foreground=palette["text"], insertbackground=palette["text"], borderwidth=0,
        highlightthickness=1, highlightbackground=palette["border"], yscrollcommand=v_scrollbar.set,
    )
    v_scrollbar.configure(command=text_widget.yview)
    if wrap == "none":
        #Unwrapped text needs a way to actually reach whatever ran off
        #the right edge - add the horizontal scrollbar this dialog was
        #previously missing entirely.
        h_scrollbar = ttk.Scrollbar(text_frame, orient="horizontal")
        text_widget.configure(xscrollcommand=h_scrollbar.set)
        h_scrollbar.configure(command=text_widget.xview)
        h_scrollbar.pack(side="bottom", fill="x")
    text_widget.pack(side="left", fill="both", expand=True)
    v_scrollbar.pack(side="right", fill="y")
    #Fill it with the given text, then immediately lock it against
    #further edits - the person can select/copy, just never type into it.
    text_widget.insert("1.0", text)
    text_widget.configure(state="disabled")
    #A single Close button, same convention as show_message()'s OK.
    button_row = tk.Frame(frame, background=palette["panel"])
    button_row.pack(fill="x")
    ttk.Button(button_row, text="Close", command=dialog.destroy).pack(side="right")
    #Let Enter or Escape both just close it, same as show_message().
    dialog.bind("<Return>", lambda event: dialog.destroy())
    dialog.bind("<Escape>", lambda event: dialog.destroy())
    dialog.protocol("WM_DELETE_WINDOW", dialog.destroy)
    #Center and show it, then block until it's closed.
    _center_over_parent(dialog, parent)
    dialog.grab_set()
    parent.wait_window(dialog)
