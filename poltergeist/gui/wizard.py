#DESCRIPTION: This file is the clickable replacement for cli.py's
#             run_wizard() - the exact same questions, in the exact same
#             order, with the exact same "default to whatever was already
#             saved" behavior, but as real widgets with Back/Next buttons
#             instead of typed answers at a prompt. The very first page now
#             asks the same "which machine?" question the text wizard
#             asks first: THIS machine, or a remote one reached over SSH
#             with any of the three auth modes (SSH agent/default key, a
#             specific key file, or a username+password). A remote choice
#             means this page's Next click has to actually connect over
#             the network before anything else can happen - that is a
#             blocking call, so it runs on its own thread (reusing
#             console.py's BackgroundRunner, the exact same class the main
#             window uses to keep ITSELF responsive during a scan) while
#             this page shows a live "Connecting..." status instead of
#             freezing the window. Every later page then reads from
#             self.discovered exactly the same way regardless of whether
#             that dict came from probing this machine directly or from
#             the remote machine probing itself over that connection - see
#             discovery.py's discover(), which returns the identical shape
#             either way.
#
#             Just like the CLI wizard, a password or key passphrase typed
#             in here is held ONLY in this one running instance's memory
#             (self._secret) and handed back to on_complete() alongside
#             the config - it is NEVER written into self.collected, and
#             therefore never reaches save_config() or the config file on
#             disk. It must be re-typed every time this wizard runs again.
#
#             Every parsing/validation helper (turning "a,b,c" into a real
#             list, turning "80" into a float with a safe fallback) is
#             written as its own small, pure function with no Tkinter in
#             it, so each one can be unit-tested on its own; only the
#             WizardFrame class at the bottom actually builds widgets.

#import os for path handling (making the evidence dir absolute, checking
#it exists) and platform for this machine's own hostname, used as a
#suggested label for a LOCAL target the same way cli.py's wizard does.
import os
import platform

#import queue so this page can hand BackgroundRunner (below) somewhere to
#put a remote probe's live progress lines while it runs off the main
#thread, and tkinter/ttk/filedialog for the actual widgets.
import queue
import tkinter as tk
from tkinter import ttk, filedialog

#import discover() so a LOCAL target is probed exactly like the text
#wizard does - same interfaces, same VPN guesses, same gateway and
#listening-port detection, all from the one shared implementation.
from ..discovery import discover

#import the config functions so this wizard saves settings exactly the
#way the rest of the project expects them to be saved, plus REPO_ROOT,
#which a remote target's deploy step needs to know what to copy there.
from ..config import default_config, save_config, REPO_ROOT

#import the role profile helpers so this wizard can offer the same
#"what kind of machine is this" choices the text menu offers. Suggested
#PATHS for a role come from self.discovered["role_paths"] instead (see
#_build_page_paths below) - never computed locally in this file - since
#that dict is already filtered to what actually exists on whichever
#machine was actually probed, local or remote.
from .. import role_profiles

#import is_baseline_locked for the same gentle, non-blocking caution the
#text wizard prints if Finish is about to be clicked while an existing
#baseline is already locked in for this (or a different) target.
from ..exorcise import is_baseline_locked

#import the remote module for probe_target_remote/push_remote_config/
#remote_join - the exact same functions cli.py's own wizard calls, so a
#remote target set up from THIS wizard behaves identically to one set up
#from the text menu.
from ..modules import remote

#import BackgroundRunner so the remote probe (a blocking network call -
#deploy, then run --discover-json over SSH) runs off the main thread,
#the exact same way the main window will keep itself responsive during a
#scan (see console.py's own docstring for why a worker thread must never
#touch a Tkinter widget directly).
from .console import BackgroundRunner, drain_queue

#import the themed dialog helpers for the one popup this file needs
#mid-page (asking for a missing key passphrase) and the one it needs at
#the end (a failed connection, or the baseline-already-locked caution).
from .dialogs import prompt_text, show_message


#Define parse_comma_list, a pure function turning "a, b ,c" into a clean
#list of non-empty, whitespace-trimmed strings - the exact same splitting
#rule cli.py's ask_list() helper uses for the text menu's own questions.
def parse_comma_list(text):
    #Split on commas, strip whitespace from each piece, and drop any
    #empty strings caused by a trailing comma or extra spaces.
    return [piece.strip() for piece in text.split(",") if piece.strip()]


#Define parse_int_list, a pure function layering int conversion on top of
#parse_comma_list - any piece that isn't a plain digit string is quietly
#skipped rather than crashing the whole wizard over one typo, matching
#cli.py's own "[int(p) for p in raw if p.isdigit()]" behavior.
def parse_int_list(text):
    #Reuse parse_comma_list, then keep only the pieces that are digits,
    #converting each one to a real int.
    return [int(piece) for piece in parse_comma_list(text) if piece.isdigit()]


#Define parse_float_safe, a pure function that converts text to a float,
#falling back to the given default instead of raising if the text isn't
#a valid number at all. The CLI wizard trusts float() to just work; this
#GUI version is a little more forgiving, since a stray typo in a text box
#is much easier to make than deliberately typing garbage at a terminal
#prompt, and a popped error dialog over one bad character would be a
#needlessly harsh way to handle it when a sensible default is right there.
def parse_float_safe(text, default):
    #Try the straightforward conversion first.
    try:
        #Return the parsed float if the text is actually a valid number.
        return float(text)
    #Anything that isn't a valid number falls back to the default instead.
    except ValueError:
        #Return the fallback value.
        return default


#Define WizardFrame, the actual multi-step widget. It's built as a single
#ttk.Frame that app.py packs into the main window in place of the usual
#action panel, so the whole app stays one window rather than popping a
#separate wizard window on top of it.
#
#on_complete(config, secret) is called once the wizard finishes saving -
#secret is the in-memory-only dict (empty for a local target, or for a
#remote one using the SSH agent/default key) the main window must keep
#passing to cli.py's run_action()/do_check() for the rest of this session,
#exactly like the text menu keeps passing its own copy to those same
#functions. on_cancel(), if given, is called if the person explicitly
#backs out of this wizard run entirely (only shown as a button at all
#when a real callback is supplied) - what that means (fall back to a
#previous config, or close the app if there was never a working one) is
#app.py's decision, not this file's.
#
#previous_config, if given, seeds every question's default with whatever
#was already saved - "a clean restart every time we fire it up," but
#reconfirming an unchanged setup is still just clicking Next through
#every page - exactly mirroring cli.py's own run_wizard(previous_config).
class WizardFrame(ttk.Frame):
    #Define the constructor.
    def __init__(self, parent, palette, fonts, on_complete, on_cancel=None, previous_config=None):
        #Build the underlying frame.
        super().__init__(parent, style="TFrame", padding=20)
        #Remember the palette/fonts so every page-builder method below
        #can use them without re-importing theme.py directly.
        self.palette = palette
        self.fonts = fonts
        #Remember the callbacks this wizard reports back through.
        self.on_complete = on_complete
        self.on_cancel = on_cancel
        #Remember the previous config (if any) purely as a source of
        #defaults - never mutated, and never used as a reason to skip
        #asking a question outright.
        self.previous_config = previous_config or {}
        #Start the config dictionary we'll fill in as the person moves
        #through the wizard, seeded with ordinary defaults for anything
        #a page hasn't been visited yet.
        self.collected = default_config()
        #The in-memory-only secret for this run. Starts empty (correct
        #for local, and for "agent_or_default" remote); the target page
        #below is the only place that ever puts anything into it.
        self._secret = {}
        #Filled in once the target page successfully probes a machine -
        #local, this happens synchronously on that page's own Next click;
        #remote, only once the background probe below actually succeeds.
        self.discovered = None
        #A dedicated queue + BackgroundRunner for the remote probe step
        #ONLY - this wizard frame is normally gone (replaced by the main
        #action panel) long before the main window needs its own runner
        #for ordinary actions, so there is no good reason to share one.
        self._probe_queue = queue.Queue()
        self._probe_runner = BackgroundRunner(self._probe_queue)
        #Build the ordered list of page-builder methods - each one fills
        #a given content frame with that page's own widgets and returns
        #nothing; validation/saving happens in _go_next()/_finish() below
        #instead, so Back can always return to a page without losing
        #typed values. Page 0 is special-cased in _go_next (see
        #_handle_target_page_next) since advancing past it may require
        #an async SSH probe first, rather than the generic collect-and-
        #advance every other page uses.
        self._pages = [
            self._build_page_target,
            self._build_page_evidence,
            self._build_page_networks,
            self._build_page_ports,
            self._build_page_thresholds,
            self._build_page_role,
            self._build_page_paths,
        ]
        #Track which page is currently showing.
        self._page_index = 0
        #Build the header (title + page indicator), the scrolling content
        #area, and the Back/Next/Cancel button row, in that order.
        self._build_header()
        self._build_content_area()
        self._build_nav_buttons()
        #Show the very first page.
        self._render_current_page()

    #Define _build_header, the small fixed title strip at the top of the
    #wizard showing a heading and which step this is.
    def _build_header(self):
        #Build a label for the wizard's own title.
        self.header_label = ttk.Label(self, text="Setup Wizard", style="Heading.TLabel")
        self.header_label.pack(anchor="w")
        #Build a dimmed subtitle updated on every page to show progress.
        self.progress_label = ttk.Label(self, text="", style="Dim.TLabel")
        self.progress_label.pack(anchor="w", pady=(0, 12))

    #Define _build_content_area, the frame each individual page's widgets
    #actually get built into. It's cleared and rebuilt on every Next/Back
    #rather than keeping every page's worth of widgets alive at once.
    #
    #THIS IS NOW A REAL SCROLLABLE AREA (Canvas + Scrollbar + an inner
    #frame), not a plain fixed-height ttk.Frame - fixing a genuine bug: a
    #page whose questions add up to more vertical space than the window's
    #fixed size (set once in app.py, never auto-grown to fit content) used
    #to simply run off the bottom with NO way to reach it. This bit
    #hardest on the remote-target page: picking "A specific private key
    #file" or "Username + password" adds several more fields below an
    #already-tall page, and those fields - plus the "not saved to disk"
    #reassurance line, plus the Next button itself - could end up
    #entirely unreachable, which looked exactly like "the password option
    #doesn't work" (nothing was broken in the password logic itself -
    #there was simply no way to see the field to type a password into, or
    #confirm Next was even still clickable). Built as the exact same
    #canvas-window-plus-scrollbar pattern `gui/app.py`'s own button panel
    #and `gui/live_dashboard.py` both already use, so this is one
    #well-tested Tkinter idiom reused a third time, not a new one.
    def _build_content_area(self):
        #Build the outer frame this whole scrollable area lives in, given
        #a raised panel look so it stands out slightly from the wizard's
        #own outer background - the same visual role the old plain frame
        #played.
        outer = ttk.Frame(self, style="Raised.TFrame")
        outer.pack(fill="both", expand=True)
        #Build the canvas that actually makes this scrollable.
        self._content_canvas = tk.Canvas(outer, background=self.palette["panel_raised"], highlightthickness=0)
        scrollbar = ttk.Scrollbar(outer, orient="vertical", command=self._content_canvas.yview)
        self._content_canvas.configure(yscrollcommand=scrollbar.set)
        self._content_canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        #self.content_frame is the thing that actually scrolls, held
        #inside the canvas as a "window" - every page builder below packs
        #its widgets straight into this, completely unaware that it now
        #lives inside a canvas rather than directly in the wizard. Kept
        #the padding the old plain frame had, so nothing about a single
        #page's own layout needs to change.
        self.content_frame = ttk.Frame(self._content_canvas, style="Raised.TFrame", padding=16)
        self._content_window_id = self._content_canvas.create_window((0, 0), window=self.content_frame, anchor="nw")

        #Keep the canvas's scrollable region in sync with however tall
        #content_frame actually ends up being once a page's widgets are
        #packed into it.
        def _on_content_resized(event):
            self._content_canvas.configure(scrollregion=self._content_canvas.bbox("all"))
        self.content_frame.bind("<Configure>", _on_content_resized)

        #Keep content_frame exactly as wide as the canvas itself, so a
        #page's labels/entries still stretch to fill the available width
        #instead of staying a fixed width while the window resizes.
        def _on_canvas_resized(event):
            self._content_canvas.itemconfigure(self._content_window_id, width=event.width)
        self._content_canvas.bind("<Configure>", _on_canvas_resized)

        #Mouse-wheel scrolling, bound only while the pointer is actually
        #over this content area (not the whole window), so it never
        #fights with scrolling meant for something else. Covers both the
        #Windows/macOS <MouseWheel> delta style and X11's separate
        #Button-4/Button-5 wheel events.
        def _on_mousewheel(event):
            try:
                if hasattr(event, "delta") and event.delta:
                    self._content_canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
                elif event.num == 4:
                    self._content_canvas.yview_scroll(-1, "units")
                elif event.num == 5:
                    self._content_canvas.yview_scroll(1, "units")
            except tk.TclError:
                #The canvas can, in rare timing, already be gone (the
                #wizard finishing while the pointer is still over it) -
                #scrolling a destroyed widget raises TclError, ignored.
                pass

        def _on_enter(event):
            self._content_canvas.bind_all("<MouseWheel>", _on_mousewheel)
            self._content_canvas.bind_all("<Button-4>", _on_mousewheel)
            self._content_canvas.bind_all("<Button-5>", _on_mousewheel)

        def _on_leave(event):
            self._content_canvas.unbind_all("<MouseWheel>")
            self._content_canvas.unbind_all("<Button-4>")
            self._content_canvas.unbind_all("<Button-5>")

        outer.bind("<Enter>", _on_enter)
        outer.bind("<Leave>", _on_leave)

    #Define _build_nav_buttons, the fixed Cancel/Back/Next row at the
    #bottom. Cancel only actually appears if a real on_cancel callback was
    #given - a button that does nothing when clicked would be worse than
    #no button at all.
    def _build_nav_buttons(self):
        #Build a frame to hold the navigation buttons.
        nav_frame = ttk.Frame(self, style="TFrame")
        nav_frame.pack(fill="x", pady=(14, 0))
        #Cancel sits apart on the far left, away from Back, since it
        #abandons this whole wizard run rather than just one page.
        self.cancel_button = None
        if self.on_cancel is not None:
            #Build and pack it only when there's somewhere for it to go.
            self.cancel_button = ttk.Button(nav_frame, text="Cancel Setup", command=self.on_cancel)
            self.cancel_button.pack(side="left")
        #Back moves to the previous page, staying in place on page 0.
        self.back_button = ttk.Button(nav_frame, text="< Back", command=self._go_back)
        self.back_button.pack(side="left", padx=(8, 0) if self.cancel_button is not None else 0)
        #Next either advances a page or, on the final page, saves and
        #finishes - its exact label is updated in _render_current_page().
        self.next_button = ttk.Button(nav_frame, text="Next >", command=self._go_next)
        self.next_button.pack(side="right")

    #Define _set_nav_enabled, flipping every nav button's enabled state
    #together - used while a remote probe is actually in flight, since
    #there is nowhere sensible for Back/Next/Cancel to go until it
    #finishes (the background thread has no abort of its own to call).
    def _set_nav_enabled(self, enabled):
        #Pick the ttk state flag for the requested enabled-ness.
        state_flag = "!disabled" if enabled else "disabled"
        #Apply it to Back and Next, which always exist.
        self.back_button.state([state_flag])
        self.next_button.state([state_flag])
        #Apply it to Cancel too, but only if it actually exists.
        if self.cancel_button is not None:
            #Disable/enable the Cancel button the same way.
            self.cancel_button.state([state_flag])

    #Define _clear_content, wiping out whatever widgets the previous page
    #left in content_frame before the next page builds its own.
    def _clear_content(self):
        #Destroy every child widget currently inside the content frame.
        for child in self.content_frame.winfo_children():
            #Destroy this one child widget.
            child.destroy()

    #Define _scroll_content_to_top, resetting the content area's scroll
    #position back to the very top - called after rendering a whole new
    #page, and after the auth-mode radio buttons reveal new fields below
    #an already-tall remote-target page, so whatever just appeared is
    #immediately visible rather than requiring the person to already know
    #to scroll down and find it themselves.
    def _scroll_content_to_top(self):
        #yview_moveto(0.0) is safe to call even before the canvas has
        #recomputed its scrollregion for brand-new content - 0.0 ("the
        #very top") is always a valid position regardless.
        self._content_canvas.yview_moveto(0.0)

    #Define _labeled_entry, a small shared helper every question-page
    #below uses so each question looks and behaves the same way: a label
    #above a text entry, pre-filled with a given default value, returning
    #the StringVar so the page can read it back later.
    def _labeled_entry(self, parent, label_text, default_value, help_text=None):
        #Build the question's own label.
        ttk.Label(parent, text=label_text, style="TLabel").pack(anchor="w", pady=(10, 2))
        #If a short help line was given, show it dimmed just below the
        #label, so the explanation is always visible without a tooltip.
        if help_text:
            #Build and pack the dimmed help label.
            ttk.Label(parent, text=help_text, style="Dim.TLabel", wraplength=560).pack(anchor="w", pady=(0, 4))
        #Build the StringVar backing this entry's text.
        entry_value = tk.StringVar(value=default_value)
        #Build the entry itself, styled to match the dark theme (a plain
        #tk.Entry is used here instead of ttk.Entry specifically because
        #plain tk widgets accept direct background/foreground colors,
        #which some ttk themes otherwise fight to override).
        entry = tk.Entry(parent, textvariable=entry_value, font=self.fonts["mono"],
                          background=self.palette["panel"], foreground=self.palette["text"],
                          insertbackground=self.palette["text"], highlightbackground=self.palette["border"],
                          highlightcolor=self.palette["glow"], highlightthickness=1, relief="flat")
        entry.pack(fill="x")
        #Hand back the StringVar so the caller can read its value later.
        return entry_value

    #Define _labeled_secret_entry, the exact same shape as _labeled_entry
    #above, except the typed characters are masked on screen - used for
    #an SSH password or key passphrase, since a plain visible text box
    #would otherwise show it to anyone glancing at the screen. There is no
    #default_value parameter on purpose: a secret field should never
    #start pre-filled with a previous run's value, since that value was
    #never saved anywhere for this page to read back in the first place.
    def _labeled_secret_entry(self, parent, label_text, help_text=None):
        #Build the question's own label, the same way _labeled_entry does.
        ttk.Label(parent, text=label_text, style="TLabel").pack(anchor="w", pady=(10, 2))
        #If a short help line was given, show it dimmed just below the label.
        if help_text:
            #Build and pack the dimmed help label.
            ttk.Label(parent, text=help_text, style="Dim.TLabel", wraplength=560).pack(anchor="w", pady=(0, 4))
        #Build the StringVar backing this entry's text, always starting blank.
        entry_value = tk.StringVar(value="")
        #Build the entry itself, identical to _labeled_entry's styling
        #except for show="*", which masks every typed character.
        entry = tk.Entry(parent, textvariable=entry_value, font=self.fonts["mono"], show="*",
                          background=self.palette["panel"], foreground=self.palette["text"],
                          insertbackground=self.palette["text"], highlightbackground=self.palette["border"],
                          highlightcolor=self.palette["glow"], highlightthickness=1, relief="flat")
        entry.pack(fill="x")
        #Hand back the StringVar so the caller can read its value later.
        return entry_value

    #--- Page 0: which machine, and (if remote) how to reach it ---
    def _build_page_target(self, container):
        #Ask the same first question the text wizard asks first.
        ttk.Label(container, text="Which machine should this install monitor?",
                  style="TLabel", wraplength=560).pack(anchor="w", pady=(0, 10))
        #Default to whichever mode was already set up, so reconfirming
        #the same target is just clicking Next here too.
        previous_target = self.previous_config.get("target") or {}
        self._target_mode_var = tk.StringVar(value=previous_target.get("mode", "local"))
        #Build the two machine-choice radio buttons. A plain tk.Radiobutton
        #is used (rather than ttk) so its background can be forced to
        #match the dark theme directly - ttk's own Radiobutton style is
        #one of the few that some platforms render with a native,
        #non-themeable background no matter what style is applied.
        mode_frame = ttk.Frame(container, style="TFrame")
        mode_frame.pack(anchor="w", fill="x")
        for mode_value, mode_label in (("local", "This machine (local)"), ("remote", "A remote machine over SSH")):
            #Build one radio button; picking either one rebuilds the
            #fields below it live, via the command= callback.
            tk.Radiobutton(mode_frame, text=mode_label, value=mode_value, variable=self._target_mode_var,
                           command=self._rebuild_target_subfields,
                           background=self.palette["panel_raised"], foreground=self.palette["text"],
                           selectcolor=self.palette["panel"], activebackground=self.palette["panel_raised"],
                           activeforeground=self.palette["glow"], highlightthickness=0,
                           font=self.fonts["body"], anchor="w").pack(anchor="w", pady=2, fill="x")
        #A dedicated sub-frame the fields below get rebuilt into,
        #separate from the radios above so changing the mode never has
        #to rebuild (and lose focus on) the radios themselves.
        self._target_subfields_frame = ttk.Frame(container, style="TFrame")
        self._target_subfields_frame.pack(fill="x", pady=(14, 0))
        #Build whichever sub-fields match the currently-selected mode.
        self._rebuild_target_subfields()

    #Define _rebuild_target_subfields, called once when page 0 is first
    #built and again every time the local/remote radio choice changes.
    def _rebuild_target_subfields(self):
        #Wipe out whatever sub-fields were showing before.
        for child in self._target_subfields_frame.winfo_children():
            #Destroy this one child widget.
            child.destroy()
        previous_target = self.previous_config.get("target") or {}
        #Local mode only needs a friendly label - everything else about
        #a local target is fixed (see _handle_target_page_next below).
        if self._target_mode_var.get() == "local":
            #Only reuse the previous label if the previous target was
            #ALSO local - a remote machine's label is not a sensible
            #suggestion for "this machine"'s own name.
            previous_local_label = previous_target.get("label") if previous_target.get("mode") == "local" else ""
            self._local_label_var = self._labeled_entry(
                self._target_subfields_frame, "Friendly label for this machine",
                previous_local_label or platform.node() or "this machine",
            )
            #Nothing else to show for a local target.
            return
        #Remote mode: a Linux-only target for now, exactly like the text
        #wizard - say so plainly rather than silently assuming otherwise.
        ttk.Label(self._target_subfields_frame, text="(remote targets are Linux-only for now - a Windows "
                  "box over SSH may come later)", style="Dim.TLabel", wraplength=560).pack(anchor="w", pady=(0, 8))
        #Only reuse previous remote-specific defaults if the previous
        #target was ALSO remote.
        remote_defaults = previous_target if previous_target.get("mode") == "remote" else {}
        self._host_var = self._labeled_entry(self._target_subfields_frame, "Remote host/IP", remote_defaults.get("host", ""))
        self._port_var = self._labeled_entry(self._target_subfields_frame, "SSH port", str(remote_defaults.get("port") or 22))
        self._user_var = self._labeled_entry(self._target_subfields_frame, "SSH username", remote_defaults.get("user", ""))
        self._remote_path_var = self._labeled_entry(
            self._target_subfields_frame, "Remote install folder (relative to that user's home)",
            remote_defaults.get("remote_path") or "poltergeist",
        )
        self._remote_label_var = self._labeled_entry(
            self._target_subfields_frame, "Friendly label for this machine",
            remote_defaults.get("label") or remote_defaults.get("host", ""),
        )
        #Ask which of the three ways in this connection should use.
        ttk.Label(self._target_subfields_frame, text="How do you log in?", style="TLabel").pack(anchor="w", pady=(14, 4))
        self._auth_mode_var = tk.StringVar(value=remote_defaults.get("auth_mode", "agent_or_default"))
        auth_options = (
            ("agent_or_default", "SSH agent / default key (~/.ssh) - the normal case"),
            ("key_file", "A specific private key file"),
            ("password", "Username + password"),
        )
        for auth_value, auth_label in auth_options:
            #Build one radio button; picking any of them rebuilds the
            #auth-specific fields below it live.
            tk.Radiobutton(self._target_subfields_frame, text=auth_label, value=auth_value, variable=self._auth_mode_var,
                           command=self._rebuild_auth_subfields,
                           background=self.palette["panel_raised"], foreground=self.palette["text"],
                           selectcolor=self.palette["panel"], activebackground=self.palette["panel_raised"],
                           activeforeground=self.palette["glow"], highlightthickness=0,
                           font=self.fonts["body"], anchor="w").pack(anchor="w", pady=1, fill="x")
        #A dedicated sub-frame for whichever auth-specific fields apply.
        self._auth_subfields_frame = ttk.Frame(self._target_subfields_frame, style="TFrame")
        self._auth_subfields_frame.pack(fill="x", pady=(8, 0))
        self._rebuild_auth_subfields()

    #Define _rebuild_auth_subfields, called once from above and again
    #every time the auth-mode radio choice changes.
    def _rebuild_auth_subfields(self):
        #Wipe out whatever auth-specific fields were showing before.
        for child in self._auth_subfields_frame.winfo_children():
            #Destroy this one child widget.
            child.destroy()
        auth_mode = self._auth_mode_var.get()
        previous_target = self.previous_config.get("target") or {}
        if auth_mode == "key_file":
            #A row holding the path entry and its Browse button together.
            key_row = ttk.Frame(self._auth_subfields_frame, style="TFrame")
            key_row.pack(fill="x")
            self._key_path_var = self._labeled_entry(key_row, "Path to the private key file", previous_target.get("key_path", ""))
            ttk.Button(key_row, text="Browse...", command=self._browse_key_file).pack(anchor="w", pady=(4, 0))
            #A key MIGHT need a passphrase; blank means it does not,
            #exactly like the text wizard's own ask_secret() question.
            self._passphrase_var = self._labeled_secret_entry(
                self._auth_subfields_frame, "Key passphrase (leave blank if it has none)",
            )
        elif auth_mode == "password":
            #A plain username + password login needs exactly one secret.
            self._password_var = self._labeled_secret_entry(self._auth_subfields_frame, "SSH password")
        #Make the no-secrets-saved promise visible right where the
        #secret is actually typed in, not just in a help document
        #somewhere else the person may never open.
        if auth_mode in ("key_file", "password"):
            #Show the same reassurance ask_secret()'s own prompt text gives.
            ttk.Label(self._auth_subfields_frame, text="Not saved to disk - you'll re-enter this every "
                      "time Poltergeist launches.", style="Dim.TLabel", wraplength=500).pack(anchor="w", pady=(6, 0))

    #Define _browse_key_file, the Key file page's Browse button handler.
    def _browse_key_file(self):
        #Open a native file-picker dialog, starting wherever the OS
        #thinks is sensible (usually the user's home directory).
        chosen_path = filedialog.askopenfilename(parent=self, title="Select private key file")
        #Only update the field if the person actually picked something -
        #cancelling the picker must never blank out a path they'd already
        #typed in by hand.
        if chosen_path:
            #Fill the key-path entry with the chosen path.
            self._key_path_var.set(chosen_path)

    #Define _browse_and_add_critical_path, the Critical paths page's own
    #Browse button handler - only ever built for a local target (see
    #_build_page_paths above). Appends whatever folder is picked onto
    #the existing comma-separated list rather than replacing it, since
    #the whole point is to build up a set of watched paths one folder
    #at a time, on top of whatever role-based suggestions already
    #pre-filled the field.
    def _browse_and_add_critical_path(self):
        #Open a native folder-picker dialog, starting wherever the OS
        #thinks is sensible.
        chosen_folder = filedialog.askdirectory(parent=self, title="Select a folder to hash and protect")
        #Cancelling the picker must never touch the existing field value.
        if not chosen_folder:
            #Nothing was chosen - leave the field exactly as it was.
            return
        #Read whatever is already typed in the field, splitting it the
        #same way parse_comma_list() will when this page is collected,
        #so a stray blank entry doesn't turn into a leading comma.
        existing_paths = [p.strip() for p in self._critical_paths_var.get().split(",") if p.strip()]
        #Only add it if it is not already in the list - clicking Browse
        #twice on the same folder should not duplicate it.
        if chosen_folder not in existing_paths:
            #Append the newly chosen folder and write the combined,
            #comma-joined list straight back into the entry's own
            #StringVar, so the person sees it land immediately.
            existing_paths.append(chosen_folder)
            self._critical_paths_var.set(",".join(existing_paths))

    #Define _handle_target_page_next, page 0's own special Next handler -
    #called instead of the generic _collect_current_page()-then-advance
    #path every other page uses, since a remote target needs an actual
    #network round-trip (and possibly a passphrase retry) before this
    #wizard can honestly say it knows anything about the machine it will
    #go on to ask the rest of its questions about.
    def _handle_target_page_next(self):
        #Local mode: nothing to connect to, so this can all happen right
        #here, synchronously, exactly like the text wizard's own
        #"Probing this machine..." step (discover() only ever looks at
        #this machine's own interfaces/sockets, which is already fast).
        if self._target_mode_var.get() == "local":
            #Build this target's dict directly - every field except mode
            #and label is fixed and meaningless for a local target.
            target = dict(default_config()["target"])
            target["mode"] = "local"
            target["label"] = self._local_label_var.get().strip() or platform.node() or "this machine"
            #A local target never needs a secret.
            self._secret = {}
            self.collected["target"] = target
            #Probe this machine directly, in-process.
            self.discovered = discover()
            #Record which OS this target actually runs, straight from the
            #real probe above - purely for the GUI's own dynamic OS-aware
            #taskbar icon (see gui/icon.py) to read back later. target is
            #the same dict object already stored in self.collected above,
            #so this mutation is visible there too.
            target["os"] = "windows" if self.discovered.get("is_windows") else "linux"
            #Advance straight to the next page - no connection to wait on.
            self._page_index = 1
            self._render_current_page()
            return
        #Remote mode: collect everything typed on this page into a
        #pending target/secret pair first - NOT yet into self.collected
        #or self._secret, since the connection attempt below might fail
        #and need a retry (or a full return to this page) without having
        #already committed a half-working answer.
        target = {
            "mode": "remote",
            "host": self._host_var.get().strip(),
            "port": int(parse_float_safe(self._port_var.get(), 22)),
            "user": self._user_var.get().strip(),
            "remote_path": self._remote_path_var.get().strip() or "poltergeist",
            "label": self._remote_label_var.get().strip() or self._host_var.get().strip(),
            "auth_mode": self._auth_mode_var.get(),
            "key_path": "",
        }
        secret = {}
        if target["auth_mode"] == "key_file":
            #Record the key path, and the passphrase only if one was
            #actually typed (an unprotected key needs none at all).
            target["key_path"] = self._key_path_var.get().strip()
            typed_passphrase = self._passphrase_var.get()
            if typed_passphrase:
                #Only record it if something was actually typed.
                secret["passphrase"] = typed_passphrase
        elif target["auth_mode"] == "password":
            #A password login needs exactly one secret.
            secret["password"] = self._password_var.get()
        #Remember these as "pending" until the probe actually succeeds.
        self._pending_remote_target = target
        self._pending_remote_secret = secret
        #Kick off the actual connection attempt on its own thread.
        self._start_remote_probe()

    #Define _start_remote_probe, which swaps the page into a live
    #"Connecting..." status view, disables navigation (there is nowhere
    #sensible for Back/Next/Cancel to go until this finishes - the
    #background thread has no abort of its own to call), and starts the
    #actual deploy-and-probe call on a background thread via the shared
    #BackgroundRunner, exactly the way the main window will later keep
    #itself responsive during an ordinary scan.
    def _start_remote_probe(self):
        #Build the live status view in place of the normal page content.
        self._render_connecting_view()
        #Nothing to click until this resolves one way or the other.
        self._set_nav_enabled(False)

        #This plain dict is how the background thread hands its actual
        #return value back out - BackgroundRunner's start() only runs a
        #zero-argument callable and does not capture a return value of
        #its own, so the closure below stores it here instead.
        self._probe_result = {}

        #Define the actual zero-argument callable BackgroundRunner runs.
        def do_probe():
            #Use whatever evidence_dir was already configured (or the
            #ordinary default) purely as somewhere to cache this host's
            #trusted key during setup - exactly like cli.py's own
            #probe_scratch_config. The REAL evidence_dir question comes
            #on the very next page, local or remote alike.
            probe_scratch_config = {"evidence_dir": self.previous_config.get("evidence_dir") or default_config()["evidence_dir"]}
            #Actually attempt deploy + remote probe.
            discovered, error = remote.probe_target_remote(
                probe_scratch_config, self._pending_remote_target, self._pending_remote_secret, REPO_ROOT,
            )
            #Hand the result back through the shared dict.
            self._probe_result["discovered"] = discovered
            self._probe_result["error"] = error

        #Start it; this project's BackgroundRunner refuses to double-start,
        #but nothing else could already be running here since navigation
        #is disabled for the whole time one probe is in flight.
        self._probe_runner.start(do_probe)
        #Begin polling for progress/completion from the main thread.
        self.after(150, self._poll_probe)

    #Define _render_connecting_view, the temporary content shown while a
    #remote probe is in flight. It is NOT one of the pages in self._pages
    #- it is a transient state the target page moves through, never
    #something Back/Next would ever land on directly.
    def _render_connecting_view(self):
        #Wipe out whatever the target page was showing.
        self._clear_content()
        #Update the progress label to make clear this isn't a numbered step.
        self.progress_label.configure(text="Connecting...")
        target = self._pending_remote_target
        #Say exactly what it's doing and to where.
        ttk.Label(self.content_frame, text=f"Connecting to {target['user']}@{target['host']}:{target['port']}...",
                  style="Heading.TLabel", wraplength=560).pack(anchor="w", pady=(0, 10))
        #A small read-only text area that live progress lines (straight
        #from remote.py's own print() calls - "deploying...", a clear
        #error if something goes wrong) get appended into as they arrive,
        #so this never looks like a frozen, silent spinner.
        self._connecting_text = tk.Text(self.content_frame, height=14, font=self.fonts["mono_small"],
                                         background=self.palette["bg"], foreground=self.palette["text"],
                                         insertbackground=self.palette["text"], relief="flat", wrap="word")
        self._connecting_text.pack(fill="both", expand=True)
        #Read-only from the user's own keyboard - this page only ever
        #writes into it itself, via _append_connecting_text below.
        self._connecting_text.configure(state="disabled")

    #Define _append_connecting_text, the only thing allowed to put text
    #into the connecting view's Text widget - toggling it briefly out of
    #its normal read-only state to do so, same pattern the eventual
    #findings console pane will use for the exact same reason.
    def _append_connecting_text(self, chunk):
        #Briefly allow edits just long enough to insert this one chunk.
        self._connecting_text.configure(state="normal")
        self._connecting_text.insert("end", chunk)
        #Scroll to show the newest line, same as a real terminal would.
        self._connecting_text.see("end")
        #Lock it back down immediately afterward.
        self._connecting_text.configure(state="disabled")

    #Define _poll_probe, called repeatedly via self.after() while a
    #remote probe is in flight. Drains whatever progress text has
    #arrived since the last poll into the connecting view, then either
    #reschedules itself (still running) or handles the finished result.
    def _poll_probe(self):
        #Pull out everything the background thread has printed so far.
        for chunk in drain_queue(self._probe_queue):
            #Append each chunk to the live status view.
            self._append_connecting_text(chunk)
        #Still running - check again shortly rather than blocking.
        if self._probe_runner.busy:
            #Reschedule another poll; 150ms keeps the view feeling live
            #without redrawing so often it wastes CPU on a long deploy.
            self.after(150, self._poll_probe)
            return
        #The probe thread has finished one way or another.
        self._handle_probe_finished()

    #Define _handle_probe_finished, called once _poll_probe notices the
    #background probe thread is no longer busy. Mirrors cli.py's own
    #run_wizard() exactly: a key that needed a passphrase we did not
    #supply is a specific, recoverable case worth one retry; anything
    #else that failed stops here and lets the person fix something on
    #the target page; success moves on to the next page.
    def _handle_probe_finished(self):
        discovered = self._probe_result.get("discovered")
        error = self._probe_result.get("error")
        target = self._pending_remote_target
        secret = self._pending_remote_secret
        #The one specific, recoverable failure: a key file that needs a
        #passphrase we did not already try. Ask for it and retry once,
        #instead of failing the whole wizard over a detail that's still
        #fixable right now.
        if (discovered is None and target["auth_mode"] == "key_file"
                and "passphrase" not in secret and "passphrase" in (error or "").lower()):
            #Ask for the missing passphrase in a themed, masked popup.
            typed_passphrase = prompt_text(
                self, self.palette, self.fonts, "Passphrase needed",
                "That key needs a passphrase - enter it:", mask=True,
            )
            if typed_passphrase:
                #Record it and try the whole connect-and-probe step again.
                secret["passphrase"] = typed_passphrase
                self._pending_remote_secret = secret
                self._start_remote_probe()
                #Don't fall through to the generic failure handling below -
                #a fresh attempt is already under way.
                return
            #The person cancelled the passphrase prompt - fall through to
            #ordinary failure handling with the original error message.
        if discovered is None:
            #Re-enable navigation and show the target page again so the
            #person can fix whatever is wrong and try again.
            self._set_nav_enabled(True)
            self._page_index = 0
            self._render_current_page()
            #Explain exactly what went wrong, in its own themed popup.
            show_message(
                self, self.palette, self.fonts, "Could not connect",
                f"Could not set up {target.get('label') or target.get('host')}: {error}\n\n"
                "Fix the issue above and click Next to try again.",
                kind="error",
            )
            return
        #Success: remember the target, the secret, and what was
        #discovered about it, then move on to the next page.
        self.discovered = discovered
        #Record which OS this target actually runs, straight from the
        #real probe above - same reasoning as the local branch above.
        target["os"] = "windows" if discovered.get("is_windows") else "linux"
        self.collected["target"] = target
        self._secret = secret
        self._set_nav_enabled(True)
        self._page_index = 1
        self._render_current_page()

    #--- Page 1: connection summary + evidence directory ---
    def _build_page_evidence(self, container):
        target = self.collected.get("target") or {}
        #Show a short summary of what was just found, local or remote.
        if target.get("mode") == "remote":
            #Say what kind of machine it turned out to be, same
            #confirmation line the text wizard prints right after connecting.
            machine_kind = "Windows" if self.discovered.get("is_windows") else "Linux"
            ttk.Label(container, text=f"Connected. {target.get('label')} is a {machine_kind} machine.",
                      style="TLabel", wraplength=560).pack(anchor="w", pady=(0, 12))
        else:
            #List every discovered interface, one per line, exactly like
            #the text wizard's own "found interface ..." lines.
            ttk.Label(container, text="Poltergeist just probed this machine. Here's what it found - "
                      "the next few pages let you confirm or change any of it.",
                      style="TLabel", wraplength=560).pack(anchor="w", pady=(0, 12))
            for interface in self.discovered.get("interfaces", []):
                #Build one dimmed line per interface.
                ttk.Label(container, text=f"  found interface {interface['name']}: {interface['ip']} ({interface['net']})",
                          style="Dim.TLabel", font=self.fonts["mono_small"]).pack(anchor="w")
            #If a default gateway was found, show it too.
            if self.discovered.get("gateway"):
                #Show the gateway as a likely trusted IP.
                ttk.Label(container, text=f"  default gateway: {self.discovered['gateway']}",
                          style="Dim.TLabel", font=self.fonts["mono_small"]).pack(anchor="w", pady=(0, 8))
        #Ask where evidence should be stored, on THIS (analyst's) machine -
        #true for a remote target too, since pull_evidence() always syncs
        #a remote target's findings back here.
        self._evidence_dir_var = self._labeled_entry(
            container, "Evidence directory (on THIS machine, where reports/logs are kept)",
            self.previous_config.get("evidence_dir") or default_config()["evidence_dir"],
        )

    #--- Page 2: Networks / VPN / trusted IPs ---
    def _build_page_networks(self, container):
        #Ask which networks are being defended, defaulting to whatever
        #was previously saved, falling back to fresh discovery only when
        #nothing was saved yet - exactly like cli.py's own wizard.
        self._networks_var = self._labeled_entry(
            container, "Networks you are defending (comma-separated CIDRs)",
            ",".join(self.previous_config.get("networks") or sorted(set(self.discovered["subnets"]))),
            "These came from probing the monitored machine's own network interfaces.",
        )
        #Ask which ranges are VPN/red-team-access ranges.
        self._vpn_var = self._labeled_entry(
            container, "VPN / red-team-access ranges (comma-separated, blank if none)",
            ",".join(self.previous_config.get("vpn_networks") or sorted(set(self.discovered["vpn_subnets"]))),
        )
        #Ask which external IPs should always be trusted - deliberately
        #NOT pre-filled with the discovered gateway any more. "Trusted"
        #here means network.py SILENTLY skips a connection's plain
        #listing entirely, and on a flat, single-subnet lab/competition
        #box the gateway address is exactly where a C2 pivot can sit (the
        #page above still shows it, for reference - type it in here
        #yourself if you are sure traffic through it is routine). The
        #beacon-timing check still watches every destination regardless
        #of this list, trusted or not - see network.py's own comment.
        self._trusted_var = self._labeled_entry(
            container, "Trusted external IPs (scoring engine, teammates - not auto-filled with the gateway)",
            ",".join(self.previous_config.get("trusted_ips") or []),
        )

    #--- Page 3: Ports ---
    def _build_page_ports(self, container):
        #Show exactly what's listening right now, the same information
        #the text wizard prints before asking this same question.
        listening_summary = ", ".join(f"{item['port']}/{item['proc']}" for item in self.discovered["listening"]) or "none"
        ttk.Label(container, text=f"Listening right now: {listening_summary}",
                  style="Dim.TLabel", wraplength=560).pack(anchor="w", pady=(0, 6))
        #Ask which ports should be considered expected/normal, defaulting
        #to whatever was previously saved, or everything currently
        #listening if nothing was saved yet - only safe to accept blindly
        #on a clean box, same warning the text wizard gives.
        expected_default = self.previous_config.get("expected_ports") or sorted(item["port"] for item in self.discovered["listening"])
        self._expected_ports_var = self._labeled_entry(
            container, "Ports that SHOULD be listening", ",".join(str(p) for p in expected_default),
            "Default = what's listening right now (or your previous answer). Only accept this blindly on a box you trust is clean.",
        )
        #Ask which ports should always be treated as suspicious.
        watch_default = self.previous_config.get("watch_ports") or [4444, 1337, 31337, 5555, 6666, 9001, 1234]
        self._watch_ports_var = self._labeled_entry(
            container, "Always-suspicious ports", ",".join(str(p) for p in watch_default),
        )

    #--- Page 4: Thresholds + monitor interval ---
    def _build_page_thresholds(self, container):
        #Ask for the CPU percent that should trigger a finding.
        self._cpu_var = self._labeled_entry(container, "Flag a process above this CPU %", str(self.previous_config.get("cpu_threshold", 80)))
        #Ask for the memory percent that should trigger a finding.
        self._mem_var = self._labeled_entry(container, "Flag a process above this memory %", str(self.previous_config.get("mem_threshold", 50)))
        #Ask how often the main view's automatic scan should repeat.
        self._interval_var = self._labeled_entry(
            container, "How often the main view auto-scans, in seconds", str(self.previous_config.get("interval", 15)),
        )

    #--- Page 5: Role ---
    def _build_page_role(self, container):
        #Explain what this question actually changes, same wording as
        #the text wizard uses.
        ttk.Label(container, text="What kind of machine is this (the one being MONITORED)? This only "
                  "changes which files get suggested as 'critical' on the next page.",
                  style="TLabel", wraplength=560).pack(anchor="w", pady=(0, 10))
        #Remember the ordered list of role keys so _collect_current_page()
        #and the paths page below can both use it.
        self._role_keys = role_profiles.list_roles()
        #Default to whatever role was previously saved, falling back to
        #the first (generic) role if nothing valid was saved yet.
        previous_role = self.previous_config.get("role")
        default_role = previous_role if previous_role in self._role_keys else self._role_keys[0]
        self._role_var = tk.StringVar(value=default_role)
        #Build one radio button per role, each labeled with its own
        #plain-English description from role_profiles.py.
        for role_key in self._role_keys:
            #Look up this role's human-readable label.
            role_label = role_profiles.ROLE_PROFILES[role_key]["label"]
            #Build the radio button itself. A plain tk.Radiobutton is used
            #here (rather than ttk) so its background can be forced to
            #match the dark theme directly.
            tk.Radiobutton(container, text=role_label, value=role_key, variable=self._role_var,
                           background=self.palette["panel_raised"], foreground=self.palette["text"],
                           selectcolor=self.palette["panel"], activebackground=self.palette["panel_raised"],
                           activeforeground=self.palette["glow"], highlightthickness=0,
                           font=self.fonts["body"], anchor="w").pack(anchor="w", pady=2, fill="x")

    #--- Page 6: Critical paths and auto-restore ---
    def _build_page_paths(self, container):
        #Figure out which role was picked on the previous page, so this
        #page's suggested paths reflect that choice.
        role_key = self._role_var.get() if hasattr(self, "_role_var") else self._role_keys[0]
        #Both of these come straight out of self.discovered - computed on
        #whichever machine is actually being monitored, local or remote -
        #so a remote target's suggestions are never checked against the
        #analyst's OWN filesystem by mistake (see discovery.py's own
        #comments on why role_paths/default_critical_paths live there).
        role_suggested_paths = self.discovered["role_paths"].get(role_key, [])
        combined_default = self.previous_config.get("critical_paths") or sorted(set(role_suggested_paths + self.discovered["default_critical_paths"]))
        #Ask which files/folders should be hashed and protected.
        self._critical_paths_var = self._labeled_entry(
            container, "Files/dirs to hash and protect (on the monitored machine)", ",".join(combined_default),
        )
        #A native folder-picker button, ONLY for a local target - this is
        #the user's explicit ask ("a way where we can select directories
        #on the current machine we are monitoring... to put the
        #tripwires or make the hash to monitor") answered directly,
        #instead of making them type every path by hand. A remote
        #target gets no Browse button here: this picker can only ever
        #browse the analyst's OWN filesystem, and showing it for a
        #remote target would silently suggest paths from the wrong
        #machine - the typed comma-list entry above is the only way to
        #set a remote target's critical paths, same as it always was.
        target_mode = self.collected.get("target", {}).get("mode", "local")
        if target_mode == "local":
            ttk.Button(container, text="Browse and add a folder...",
                       command=self._browse_and_add_critical_path).pack(anchor="w", pady=(6, 0))
        #Ask whether tampered critical files should be auto-restored. A
        #plain tk.Checkbutton, for the same theming reason as the role
        #page's radio buttons above.
        self._auto_restore_var = tk.BooleanVar(value=bool(self.previous_config.get("auto_restore", False)))
        tk.Checkbutton(container, text="Auto-restore tampered files (the tampered copy is ALWAYS saved first)",
                       variable=self._auto_restore_var, background=self.palette["panel_raised"],
                       foreground=self.palette["text"], selectcolor=self.palette["panel"],
                       activebackground=self.palette["panel_raised"], highlightthickness=0,
                       font=self.fonts["body"]).pack(anchor="w", pady=(14, 0))

    #Define _render_current_page, which clears the content area and
    #builds whichever page _page_index currently points at, then updates
    #the progress label and the Back/Next buttons' enabled state and text.
    def _render_current_page(self):
        #Wipe out the previous page's widgets.
        self._clear_content()
        #Build the current page's widgets fresh.
        self._pages[self._page_index](self.content_frame)
        #Scroll a freshly-built page back to the top - without this, a
        #page rendered after scrolling partway down the previous one
        #would start the person off in the middle of unfamiliar content.
        self._scroll_content_to_top()
        #Update the "Step X of N" progress label.
        self.progress_label.configure(text=f"Step {self._page_index + 1} of {len(self._pages)}")
        #Disable the Back button on the very first page - there's
        #nowhere earlier to go.
        self.back_button.state(["disabled"] if self._page_index == 0 else ["!disabled"])
        #Relabel the Next button to "Finish" on the last page, so it's
        #clear that clicking it actually saves and ends the wizard.
        is_last_page = self._page_index == len(self._pages) - 1
        self.next_button.configure(text="Finish" if is_last_page else "Next >")

    #Define _collect_current_page, which reads whatever is currently
    #typed/selected on the CURRENT page into self.collected, converting
    #each field the same way cli.py's own wizard does (comma lists, int
    #lists, floats). Called every time Next or Back is pressed on any
    #page EXCEPT page 0, so a value is never lost even if the person goes
    #Back and changes it. Page 0 (the target page) is deliberately not
    #handled here at all - see _handle_target_page_next, which collects
    #its own fields itself since advancing past it may require an async
    #SSH probe first.
    def _collect_current_page(self):
        if self._page_index == 1:
            #Collect the evidence directory from page 1.
            self.collected["evidence_dir"] = os.path.abspath(self._evidence_dir_var.get())
        elif self._page_index == 2:
            #Collect the three network-related fields from page 2.
            self.collected["networks"] = parse_comma_list(self._networks_var.get())
            self.collected["vpn_networks"] = parse_comma_list(self._vpn_var.get())
            self.collected["trusted_ips"] = parse_comma_list(self._trusted_var.get())
        elif self._page_index == 3:
            #Collect the two port-list fields from page 3.
            self.collected["expected_ports"] = parse_int_list(self._expected_ports_var.get())
            self.collected["watch_ports"] = parse_int_list(self._watch_ports_var.get())
        elif self._page_index == 4:
            #Collect the threshold/interval fields from page 4.
            self.collected["cpu_threshold"] = parse_float_safe(self._cpu_var.get(), 80.0)
            self.collected["mem_threshold"] = parse_float_safe(self._mem_var.get(), 50.0)
            self.collected["interval"] = int(parse_float_safe(self._interval_var.get(), 15))
        elif self._page_index == 5:
            #Collect the chosen role key from page 5.
            self.collected["role"] = self._role_var.get()
        elif self._page_index == 6:
            #Collect the final page's fields: critical paths and the
            #auto-restore checkbox.
            self.collected["critical_paths"] = parse_comma_list(self._critical_paths_var.get())
            self.collected["auto_restore"] = bool(self._auto_restore_var.get())

    #Define _go_back, the Back button's click handler.
    def _go_back(self):
        #Do nothing if already on the first page.
        if self._page_index == 0:
            #There's nowhere to go.
            return
        #Save whatever is currently typed before leaving this page, so
        #coming back to it later (by going forward again) still shows it.
        self._collect_current_page()
        #Step back one page.
        self._page_index -= 1
        #Redraw the now-current page.
        self._render_current_page()

    #Define _go_next, the Next/Finish button's click handler. Page 0 is
    #special-cased since advancing past it may require an async SSH
    #probe (see _handle_target_page_next) rather than the generic
    #collect-then-advance every other page uses.
    def _go_next(self):
        if self._page_index == 0:
            #Hand off entirely to the target page's own handler.
            self._handle_target_page_next()
            return
        #Always collect the page we're leaving first.
        self._collect_current_page()
        #If this was the last page, we're done: save and finish instead
        #of trying to advance to a page that doesn't exist.
        if self._page_index == len(self._pages) - 1:
            #Hand off to _finish(), below.
            self._finish()
            return
        #Otherwise, advance to the next page and redraw.
        self._page_index += 1
        self._render_current_page()

    #Define _finish, called once the final page's Next ("Finish") is
    #clicked. Mirrors cli.py's own run_wizard() tail exactly: a gentle,
    #non-blocking caution if a baseline is already locked in, then save,
    #then (for a remote target) push the real final config up to it, and
    #finally hand everything back to on_complete().
    def _finish(self):
        #Make sure the evidence directory actually exists before we finish.
        os.makedirs(self.collected["evidence_dir"], exist_ok=True)
        #A gentle, non-blocking caution if a baseline is already locked in
        #- this wizard never clears that lock itself (see exorcise.py's
        #reset_baseline for the only way to do that), but it is worth
        #saying plainly that pointing at a different target makes an old
        #baseline meaningless.
        if is_baseline_locked(self.collected):
            #Work out the current target's label for the message.
            target_label = (self.collected.get("target") or {}).get("label") or "this target"
            #Show the same caution the text wizard prints, as a popup.
            show_message(
                self, self.palette, self.fonts, "Baseline already locked",
                f"A baseline is already locked in for {target_label}. This wizard will not clear it, but "
                "pointing at a DIFFERENT target makes that baseline meaningless until you reset it.",
                kind="info",
            )
        #Save the completed config to disk through config.py's save
        #function, so it's written in exactly the same shape/location the
        #text menu's wizard would have used.
        save_config(self.collected)
        #For a remote target, push the REAL final config up to it now
        #that every question has been answered, replacing the bare
        #placeholder written during the connect/probe step.
        if (self.collected.get("target") or {}).get("mode") == "remote":
            #Hand off to the small helper below.
            self._push_final_remote_config()
        #Tell whoever created this wizard (app.py) that it's done,
        #handing back the finished config AND this run's in-memory secret
        #so the main window can keep using both for the rest of this
        #session without ever writing the secret to disk.
        self.on_complete(self.collected, self._secret)

    #Define _push_final_remote_config, a small helper so _finish() above
    #stays readable. Mirrors cli.py's own equivalent block exactly - the
    #remote side needs its OWN evidence_dir (inside where it was
    #deployed) and sees itself as a plain "local" target, same as during
    #probing.
    def _push_final_remote_config(self):
        target = self.collected["target"]
        remote_final_config = dict(self.collected)
        #BARE "evidence", not remote_join(remote_root, "evidence") - see
        #probe_target_remote()'s own long comment on minimal_remote_config
        #in modules/remote.py for exactly why prefixing this with
        #remote_root double-nests it one directory too deep for
        #pull_evidence() to ever find (every remote command already `cd`s
        #into remote_root before running poltergeist.py, so the remote
        #process's cwd IS remote_root by the time this value is read).
        remote_final_config["evidence_dir"] = "evidence"
        remote_final_config["target"] = {"mode": "local"}
        #This is a small, one-file push over an already-proven connection -
        #left synchronous, exactly like cli.py's own wizard, rather than
        #adding a second background-thread step for what is normally a
        #sub-second write.
        pushed, push_error = remote.push_remote_config(self.collected, target, self._secret, remote_final_config)
        #This is a late, rare failure - the exact same connection just
        #worked moments ago to deploy and probe - but staying silent about
        #it would leave the remote side quietly running on its bare
        #probe-time placeholder config, with nothing telling the person
        #that happened.
        if not pushed:
            show_message(
                self, self.palette, self.fonts, "Could not send final settings",
                f"The final settings could not be sent to {target.get('label')}: {push_error}\n\n"
                "It is still running on its placeholder setup from the connection test - run Setup again to retry.",
                kind="error",
            )
