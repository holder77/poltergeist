#DESCRIPTION: This file is Poltergeist's "look." Every color the GUI uses
#             comes from the PALETTE dictionary below, and nowhere else -
#             if the gothic theme ever needs adjusting (the user asked for
#             "gothic badass... creepy horror... not cartoony"), this is
#             the one file to edit. It also picks which fonts to use (a
#             sharper serif for the big title if the machine actually has
#             one installed, a monospace for the findings/console text,
#             both with safe fallbacks so the app never crashes just
#             because a font isn't on this particular box), and defines a
#             reusable hover-tooltip popup, since Tkinter has no built-in
#             one. The font-PICKING logic is written as a plain function
#             that takes a list of installed font names as an argument
#             (pick_font below) instead of asking Tkinter for that list
#             itself, specifically so it can be unit-tested without a
#             real display - only apply_theme() and the Tooltip class
#             below actually need a live Tk window.

#import tkinter's font helper so apply_theme() can ask Tcl/Tk what fonts
#are actually installed on THIS machine before picking one.
import tkinter.font as tkfont

#import tkinter itself for the Tooltip popup window and the ttk styling
#engine used by apply_theme().
import tkinter as tk
from tkinter import ttk


#Define PALETTE, the ONE place every color in the GUI comes from. The
#design is STRICT black-and-white - every single value below is a pure
#shade of gray (equal R, G, and B), with no hue anywhere, matching the
#"gothic badass... not cartoony" brief taken as literally as possible: an
#old monochrome terminal rather than a Halloween-purple theme. Every
#value is part of one deliberately ordered brightness ramp from pure
#black ("bg") to pure white ("glow"/"blood"), and several files outside
#this one depend on specific PAIRS of these staying correctly ordered
#relative to each other, not just "looking dark" in isolation - see the
#note on each key below for which comparisons actually matter.
#
#The one real design problem strict monochrome creates: HIGH severity
#findings used to be called out with actual red. There is no color left
#to do that job, so this palette answers it with the brightest plain
#gray short of pure white instead ("blood_bright" below) - the nearest
#thing left to "alarming" once red is gone. Destructive BUTTONS (Shield:
#MUTE, Medium: Revert a Folder) used to get the same treatment as
#inverted video - a solid white fill with black text - but direct
#feedback asked for those to look exactly like every other button
#instead, since the real safety net for a destructive action is its own
#typed-confirmation dialog, not a different button color - see apply_
#theme()'s own Danger.TButton style below. "blood"/"blood_bright" are
#still used elsewhere (see each key's own note).
#
#One deliberate, narrow exception to "strict monochrome": "accent_blue"
#below, used only for the word "Blue team" at the very start of the
#header's own tagline, by explicit request - everything else in this
#palette stays a pure shade of gray.
PALETTE = {
    #The window's own background - pure black, nothing softened into it.
    "bg": "#000000",
    #A hair above pure black, for panels/cards - just enough to separate
    #a card from the window behind it without introducing a real color.
    "panel": "#0d0d0d",
    #A step lighter again, for the findings table's alternating rows and
    #hovered buttons. Must stay visibly lighter than "panel" (the hover/
    #alternating-row effect IS that one-step difference) but nowhere
    #near "border" yet.
    "panel_raised": "#1b1b1b",
    #Thin separators and borders - a clearly visible mid-dark gray, for
    #an "etched" look against the near-black panels.
    "border": "#3c3c3c",
    #A dim, muted gray used to fake a soft halo behind the ghost's eyes
    #(layering progressively darker/smaller shapes) and as the thin
    #border highlight on every themed dialog in dialogs.py. Must stay
    #clearly dimmer than "text_dim" below - it is meant to recede, not
    #to be read as text.
    "glow_dim": "#585858",
    #Secondary / helper / dimmed text - suggested-fix lines, timestamps,
    #and (via findings_view.py's "sev_info" tag) the color for ordinary,
    #not-urgent findings. Must stay the DIMMEST of the three severity
    #colors (dimmer than "amber", which must in turn stay dimmer than
    #"blood_bright") so a glance at the findings table still shows
    #severity by brightness alone, the same way red/amber/dim-gray used to.
    "text_dim": "#868686",
    #MEDIUM severity findings (findings_view.py's "sev_medium" tag).
    #Deliberately between "text_dim" and "blood_bright" - see the note on
    #"text_dim" above for why that ordering is load-bearing, not cosmetic.
    "amber": "#a8a8a8",
    #Reserved for a success/confirmation state - not currently read by
    #any file, kept for whatever next needs one. Sits above "amber" in
    #the ramp on the assumption that "success" should read as at least as
    #prominent as a medium-severity warning, should something start using it.
    "cyan": "#c2c2c2",
    #HIGH severity findings (findings_view.py's "sev_high" tag), the
    #typed-confirmation entry's outline highlight in dialogs.py, and an
    #error popup's title color in show_message(). The brightest plain
    #(non-inverted) gray on purpose - the nearest thing left to
    #"alarming" once red is gone - but deliberately short of pure white
    #so an error dialog's title still reads as distinct from an ordinary
    #info dialog's "glow"-colored one, even though both are now shades
    #of the same gray family.
    "blood_bright": "#d6d6d6",
    #Primary readable text - a near-white, not pure white, the same way
    #the old palette avoided clinical white for warmth; here it is purely
    #about contrast comfort, not color.
    "text": "#efefef",
    #The one color reserved for "this is a solid white fill, not text" -
    #the typed-confirmation entry's outline color in dialogs.py.
    #Deliberately identical to "glow" below; the two are never adjacent
    #in a way that would make them ambiguous (one is always a small
    #filled shape, the other always text on a dark panel). No longer
    #used by Danger.TButton - see apply_theme()'s own comment on that
    #style for why.
    "blood": "#ffffff",
    #The one deliberate splash of real color in this whole palette - used
    #ONLY for the word "Blue team" at the start of the header's own
    #tagline ("Blue team audit tool - never kills a process, never
    #deletes evidence."), by explicit request, nowhere else. A clean,
    #legible blue that still reads calmly against pure black, not a
    #neon/saturated tone that would clash with the rest of the gothic,
    #monochrome theme around it.
    "accent_blue": "#4a9eff",
    #The brightest value in the whole palette - titles, the ghost's eyes,
    #and headings. Used sparingly, same as the old spectral-violet glow
    #was, so pure white still reads as "the one thing meant to stand out"
    #rather than becoming the default color of everything.
    "glow": "#ffffff",
}


#Define FONT_PREFERENCES, ordered lists of font family names to try, most
#atmospheric first, ending in a family that ships on every OS Poltergeist
#targets. "title" is for the big POLTERGEIST wordmark and section
#headers - a sharper serif reads a little more old/carved-in-stone than
#the default UI sans-serif. "mono" is for the findings table and the
#output console - a monospace face is both more "hacker terminal" and
#easier to line up columns in.
FONT_PREFERENCES = {
    "title": ["Georgia", "Palatino Linotype", "Times New Roman", "DejaVu Serif", "Serif"],
    "mono": ["Consolas", "Cascadia Mono", "DejaVu Sans Mono", "Courier New", "Courier"],
    "body": ["Segoe UI", "Helvetica Neue", "DejaVu Sans", "Arial", "Sans"],
}


#Define pick_font, a pure function: given an ordered wishlist and the set
#of family names actually installed on this machine, return the first
#wishlist entry that's really there, or the wishlist's own last entry (by
#design, always a safe, near-universal fallback) if none of them are.
#Kept separate from apply_theme() below so this exact decision logic can
#be unit-tested with a fake "installed fonts" list, no real display needed.
def pick_font(preferred_names, installed_names):
    #Normalize the installed names once for a case-insensitive comparison,
    #since font name casing can vary oddly between operating systems.
    installed_lower = {name.lower() for name in installed_names}
    #Walk the wishlist in priority order.
    for candidate in preferred_names:
        #The first one that is actually installed wins.
        if candidate.lower() in installed_lower:
            #Return the real family name (not our lowercased copy).
            return candidate
    #Nothing on the wishlist was found - fall back to its last entry,
    #which every list above deliberately ends with a near-universal font.
    return preferred_names[-1]


#Define apply_theme, which configures a live Tk root and its ttk styling
#engine to use the palette and fonts above. Returns a small dict of the
#actual font tuples chosen, so app.py can reuse the exact same fonts on
#plain tk widgets (like the Canvas-based ghost's title) that don't go
#through ttk styling at all.
def apply_theme(root):
    #Ask Tcl/Tk which font families actually exist on this machine.
    installed = tkfont.families()
    #Pick the best available font for each role, falling back safely.
    title_family = pick_font(FONT_PREFERENCES["title"], installed)
    mono_family = pick_font(FONT_PREFERENCES["mono"], installed)
    body_family = pick_font(FONT_PREFERENCES["body"], installed)
    #Build the actual font tuples (family, size, weight) once, so every
    #caller uses the exact same sizes instead of picking their own.
    fonts = {
        "title": (title_family, 28, "bold"),
        "subtitle": (title_family, 12, "italic"),
        "heading": (body_family, 11, "bold"),
        "body": (body_family, 10, "normal"),
        "mono": (mono_family, 10, "normal"),
        "mono_small": (mono_family, 9, "normal"),
        "button": (body_family, 10, "bold"),
        #Smaller than "body" - used for the one-line version/copyright/
        #GitHub-link row under the header's tagline, which is meant to
        #read as a quiet footnote, not compete with the tagline above it.
        "small": (body_family, 8, "normal"),
    }
    #Paint the root window itself with our darkest background color.
    root.configure(background=PALETTE["bg"])
    #Grab (or create) the one shared ttk.Style object for this app.
    style = ttk.Style(root)
    #Start from the "clam" built-in theme as our base - it's the one
    #stock ttk theme that actually honors custom background/foreground
    #colors consistently across Windows and Linux, unlike the native
    #Windows theme, which ignores most color overrides.
    style.theme_use("clam")
    #Style plain frames/panels to use our panel background color.
    style.configure("TFrame", background=PALETTE["panel"])
    #A second, named style for the slightly-raised panel look.
    style.configure("Raised.TFrame", background=PALETTE["panel_raised"])
    #Style ordinary labels to sit on the panel background with bone text.
    style.configure("TLabel", background=PALETTE["panel"], foreground=PALETTE["text"], font=fonts["body"])
    #A dimmed label style for secondary/help text.
    style.configure("Dim.TLabel", background=PALETTE["panel"], foreground=PALETTE["text_dim"], font=fonts["body"])
    #A heading label style for section titles above each button group.
    style.configure("Heading.TLabel", background=PALETTE["panel"], foreground=PALETTE["glow"], font=fonts["heading"])
    #A big title label style for the "POLTERGEIST" wordmark itself.
    style.configure("Title.TLabel", background=PALETTE["bg"], foreground=PALETTE["glow"], font=fonts["title"])
    #Style ordinary buttons: dark, bone text, a visible border, and a
    #slightly raised color on hover/press so clicks still feel tactile.
    style.configure("TButton", background=PALETTE["panel_raised"], foreground=PALETTE["text"],
                     font=fonts["button"], borderwidth=1, focusthickness=0, padding=8)
    #Map hover/pressed states to slightly lighter shades, since a flat
    #color with no hover feedback reads as "broken," not "gothic."
    style.map("TButton", background=[("active", PALETTE["border"]), ("pressed", PALETTE["border"])],
              foreground=[("disabled", PALETTE["text_dim"])])
    #A second, named style for dangerous actions (Shield: MUTE, Medium:
    #Revert a Folder) - this USED to be inverted video (a solid white
    #fill with black text) to visually stand apart from every other
    #button. Direct feedback asked for that to go away: these buttons
    #should look exactly like every ordinary one (same dark background,
    #same light text), since the actual safety net for a destructive
    #action is already its own typed-confirmation dialog (dialogs.py's
    #confirm_typed, requiring the exact word MUTE/RESTORE be typed, not
    #just clicked) - a different button color was never the thing
    #standing between a person and an accidental click. Kept as its own
    #named style anyway (identical to "TButton" below, not literally
    #reusing it) purely so a future danger action could still be singled
    #out visually again later with one line changed here, without
    #touching app.py's own "danger"-flag plumbing (menu_actions.py's
    #"danger" field, app.py's own button_style = "Danger.TButton" if
    #action["danger"] else "TButton") at all.
    style.configure("Danger.TButton", background=PALETTE["panel_raised"], foreground=PALETTE["text"],
                     font=fonts["button"], borderwidth=1, focusthickness=0, padding=8)
    #Same hover/pressed behavior as ordinary buttons too, for the same reason.
    style.map("Danger.TButton", background=[("active", PALETTE["border"]), ("pressed", PALETTE["border"])],
              foreground=[("disabled", PALETTE["text_dim"])])
    #Style the findings Treeview: dark rows, bone text, and a heading row
    #that uses the panel-raised color so it reads as a distinct header.
    style.configure("Treeview", background=PALETTE["panel"], fieldbackground=PALETTE["panel"],
                     foreground=PALETTE["text"], font=fonts["mono_small"], borderwidth=0, rowheight=22)
    style.configure("Treeview.Heading", background=PALETTE["panel_raised"], foreground=PALETTE["glow"],
                     font=fonts["heading"], borderwidth=1)
    #Keep the selected-row highlight readable against the dark background
    #instead of ttk's default (often a bright, theme-clashing blue).
    style.map("Treeview", background=[("selected", PALETTE["border"])], foreground=[("selected", PALETTE["text"])])
    #Style scrollbars to stay dark instead of defaulting to a bright
    #native scrollbar that would otherwise be the single lightest thing
    #on the whole screen.
    style.configure("Vertical.TScrollbar", background=PALETTE["panel_raised"], troughcolor=PALETTE["bg"],
                     bordercolor=PALETTE["border"], arrowcolor=PALETTE["text_dim"])
    #Hand back the chosen font tuples for plain tk widgets to reuse.
    return fonts


#Define the Tooltip class: a small popup that appears near the mouse a
#short moment after it hovers over a widget, and disappears the instant
#the mouse leaves. Tkinter has no built-in equivalent, so every button's
#"what does this actually do" hint in the GUI goes through this one class.
class Tooltip:
    #Define the constructor: bind the show/hide behavior onto one widget.
    def __init__(self, widget, text, delay_ms=450):
        #Remember which widget this tooltip is attached to.
        self.widget = widget
        #Remember the plain-English text to show.
        self.text = text
        #Remember how long the mouse has to sit still before it appears -
        #short enough to feel responsive, long enough not to flash on
        #every mouse movement that merely passes over a button.
        self.delay_ms = delay_ms
        #Track the scheduled "show" timer, so we can cancel it if the
        #mouse leaves before the delay finishes.
        self._after_id = None
        #Track the actual popup window once it exists, so we can destroy it.
        self._popup = None
        #Show the tooltip (after the delay) when the mouse enters the widget.
        widget.bind("<Enter>", self._on_enter, add="+")
        #Hide it immediately when the mouse leaves.
        widget.bind("<Leave>", self._on_leave, add="+")
        #Also hide it the instant the widget is clicked, so the tooltip
        #never lingers on top of whatever the click just opened.
        widget.bind("<ButtonPress>", self._on_leave, add="+")

    #Define _on_enter, called the moment the mouse enters the widget.
    def _on_enter(self, event=None):
        #Schedule _show to actually run after the configured delay.
        self._after_id = self.widget.after(self.delay_ms, self._show)

    #Define _on_leave, called the moment the mouse leaves the widget.
    def _on_leave(self, event=None):
        #If a show was scheduled but hasn't fired yet, cancel it.
        if self._after_id is not None:
            #Cancel the pending timer.
            self.widget.after_cancel(self._after_id)
            #Clear it so we don't try to cancel it again later.
            self._after_id = None
        #If the popup is currently showing, destroy it.
        if self._popup is not None:
            #Destroy the popup window.
            self._popup.destroy()
            #Clear the reference now that it's gone.
            self._popup = None

    #Define _show, which actually builds and places the tooltip popup.
    def _show(self):
        #Figure out where the widget currently is on screen, so the
        #tooltip appears right next to it rather than at a fixed spot.
        x = self.widget.winfo_rootx() + 20
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 6
        #Build a borderless top-level window for the tooltip itself -
        #overrideredirect(True) strips the OS's usual title bar/frame,
        #since this should read as a hint bubble, not a real window.
        self._popup = tk.Toplevel(self.widget)
        self._popup.overrideredirect(True)
        #Keep it above the main window so it's never hidden behind it.
        self._popup.attributes("-topmost", True)
        #Position it at the coordinates computed above.
        self._popup.geometry(f"+{x}+{y}")
        #Build the label that actually holds the tooltip's text, styled
        #to match the gothic theme - dark background, bone text, a thin
        #glow-colored border so it reads as "part of this app," not a
        #stock OS tooltip.
        label = tk.Label(
            self._popup, text=self.text, justify="left", wraplength=320,
            background=PALETTE["panel_raised"], foreground=PALETTE["text"],
            highlightbackground=PALETTE["glow_dim"], highlightthickness=1,
            padx=8, pady=6, font=("TkDefaultFont", 9),
        )
        #Let the label fill the whole popup window.
        label.pack()
