#DESCRIPTION: This file builds Poltergeist's window/titlebar/taskbar icon
#             entirely in code - no bundled image file of any kind. Two
#             reasons for that, both deliberate: (1) this project ships as
#             plain Python source with no build step, so an icon that has
#             to survive being copied, zipped, and deployed to a remote
#             box over SFTP (see modules/remote.py) is one less binary
#             asset that can go missing or get mangled in transit; (2) the
#             window icon and the taskbar icon are deliberately DIFFERENT
#             images now (see below), which means building both from
#             plain geometry is simpler than juggling two bundled files.
#
#             WINDOW/TITLEBAR icon: just the ghost mascot, alone, full
#             size - see build_window_icon_photoimages().
#
#             TASKBAR icon: the ghost confined to the top-left corner, a
#             diagonal slash, and the first 3 characters of whatever
#             "friendly name" the user gave this target in the wizard
#             (config["target"]["label"] - "sent1", "DC01", whatever they
#             typed) in the bottom-right corner - by request, specifically
#             so running several Poltergeist instances against several
#             different machines at once is easy to tell apart at a
#             glance in the taskbar, without having to hover or click
#             each one first. See build_taskbar_icon_photoimages().
#
#             THE HONEST LIMITATION: plain, portable Tkinter has no way
#             to set a genuinely different icon for "the titlebar" versus
#             "the taskbar button" - root.iconphoto() sets ONE icon (or
#             one SET of the same icon at different sizes) for the whole
#             window, and the operating system itself decides which size
#             to pull from that set for which UI spot. The one place this
#             actually works the way it sounds like it should is Windows,
#             which has a genuine, long-standing convention of using the
#             SMALLEST icon in the set for the titlebar/Alt-Tab-small slot
#             and a LARGER one for the taskbar button/Alt-Tab-large slot -
#             which is exactly what build_icon_photoimages() below relies
#             on: the smallest size (16px) gets the plain ghost, the two
#             larger sizes (32px/48px) get the new taskbar design. Most
#             Linux desktop environments do NOT make that same size-based
#             distinction - a typical GNOME/KDE panel just picks one
#             image from the set (usually whichever is closest to its own
#             preferred panel-icon size) and uses it everywhere, titlebar
#             included - so on Linux, this is best-effort: it still shows
#               a sensible icon everywhere, it just may not split cleanly
#             between "plain ghost in the titlebar" and "ghost+slash+name
#             in the taskbar" the way it reliably does on Windows. This
#             is a limitation of the desktop environment, not a bug here.
#
#             Both the ghost and the diagonal-slash taskbar layout are
#             drawn from plain geometry (circles/ellipses, a hand-picked
#             scalloped-hem formula for the ghost, and a tiny hand-built
#             3x5 pixel font - FONT_3X5 below - for the friendly-name
#             label), not copied from, or made to resemble, any real
#             logo, mascot, or trademark.
#
#             Strict monochrome throughout (plain white on plain black),
#             matching gui/theme.py's own "bg"/"glow" colors exactly, so
#             the icon reads as part of the same gothic theme rather than
#             a colorful sticker bolted onto a black-and-white window.

#import tkinter so this module can build a real tk.PhotoImage - the only
#format root.iconphoto() accepts.
import tkinter as tk

#The icon's own two-color palette - deliberately the EXACT same two hex
#values as theme.py's PALETTE["bg"] and PALETTE["glow"], so the icon never
#drifts out of sync with the rest of the window if that palette ever
#changes. (Not imported directly from theme.py, to keep this module usable
#completely standalone, with zero dependency on anything else in gui/ -
#the same reasoning theme.py's own pick_font() already follows.)
ICON_BG = "#000000"
ICON_FG = "#ffffff"

#Below this icon size, the taskbar design's diagonal slash and 3-letter
#label have no room left to read as anything but noise (this was checked
#by eye against an actual rendered mockup before implementing - a 16px
#icon trying to hold a ghost, a slash, AND three letters all at once just
#turns to static). Below this size, build_icon_photoimage() falls back to
#the plain ghost instead of attempting the full taskbar layout.
TASKBAR_LAYOUT_MIN_SIZE = 24

#A tiny, hand-built 3-pixel-wide by 5-pixel-tall bitmap font, covering
#every character a "friendly name" realistically contains (A-Z, 0-9, a
#hyphen, and an underscore) - deliberately NOT full typography (some
#letters, M/N/W especially, are close approximations rather than
#faithful letterforms; there simply aren't enough pixels at 3-wide to
#draw them exactly), just enough for a short label like "SNT1" or "DC01"
#to be told apart from another at a glance, which is the actual goal
#here (telling several running instances apart in the taskbar), not
#legibility as a general-purpose font. "#" = a lit pixel, "." = unlit.
#Every entry is exactly 5 rows of exactly 3 characters each.
FONT_3X5 = {
    "0": ["###", "#.#", "#.#", "#.#", "###"],
    "1": [".#.", "##.", ".#.", ".#.", "###"],
    "2": ["###", "..#", "###", "#..", "###"],
    "3": ["###", "..#", "###", "..#", "###"],
    "4": ["#.#", "#.#", "###", "..#", "..#"],
    "5": ["###", "#..", "###", "..#", "###"],
    "6": ["###", "#..", "###", "#.#", "###"],
    "7": ["###", "..#", "..#", "..#", "..#"],
    "8": ["###", "#.#", "###", "#.#", "###"],
    "9": ["###", "#.#", "###", "..#", "###"],
    "A": [".#.", "#.#", "###", "#.#", "#.#"],
    "B": ["##.", "#.#", "##.", "#.#", "##."],
    "C": [".##", "#..", "#..", "#..", ".##"],
    "D": ["##.", "#.#", "#.#", "#.#", "##."],
    "E": ["###", "#..", "##.", "#..", "###"],
    "F": ["###", "#..", "##.", "#..", "#.."],
    "G": [".##", "#..", "#.#", "#.#", ".##"],
    "H": ["#.#", "#.#", "###", "#.#", "#.#"],
    "I": ["###", ".#.", ".#.", ".#.", "###"],
    "J": ["..#", "..#", "..#", "#.#", ".#."],
    "K": ["#.#", "#.#", "##.", "#.#", "#.#"],
    "L": ["#..", "#..", "#..", "#..", "###"],
    #Approximate - see this font's own top comment for why.
    "M": ["#.#", "###", "#.#", "#.#", "#.#"],
    #Approximate - see this font's own top comment for why.
    "N": ["#.#", "##.", "###", ".##", "#.#"],
    "O": [".#.", "#.#", "#.#", "#.#", ".#."],
    "P": ["##.", "#.#", "##.", "#..", "#.."],
    "Q": [".#.", "#.#", "#.#", ".#.", "..#"],
    "R": ["##.", "#.#", "##.", "#.#", "#.#"],
    "S": [".##", "#..", ".#.", "..#", "##."],
    "T": ["###", ".#.", ".#.", ".#.", ".#."],
    "U": ["#.#", "#.#", "#.#", "#.#", "###"],
    "V": ["#.#", "#.#", "#.#", "#.#", ".#."],
    #Approximate - see this font's own top comment for why.
    "W": ["#.#", "#.#", "#.#", "###", "#.#"],
    "X": ["#.#", "#.#", ".#.", "#.#", "#.#"],
    "Y": ["#.#", "#.#", ".#.", ".#.", ".#."],
    "Z": ["###", "..#", ".#.", "#..", "###"],
    "-": ["...", "...", "###", "...", "..."],
    "_": ["...", "...", "...", "...", "###"],
    #Fallback glyph for any character the font above has no entry for
    #(punctuation other than "-"/"_", non-ASCII letters, etc) - a small,
    #clearly-deliberate solid dot, so an odd character in a friendly
    #name reads as "something is here" rather than a silent gap that
    #could be mistaken for a rendering bug.
    "?": ["...", ".#.", "###", ".#.", "..."],
}


#Define _in_ellipse, a tiny pure-math helper used by every shape below:
#true if the point (x, y) falls inside (or on) an ellipse centered at
#(cx, cy) with radii (rx, ry). A circle is just the special case rx == ry.
def _in_ellipse(x, y, cx, cy, rx, ry):
    #Avoid a division by zero for a degenerate zero-radius ellipse.
    if rx <= 0 or ry <= 0:
        #Nothing is ever "inside" a shape with no size.
        return False
    #The standard normalized ellipse membership test.
    return ((x - cx) / rx) ** 2 + ((y - cy) / ry) ** 2 <= 1.0


#Define _ghost_pixel_on, the ghost mascot's own shape, confined to the
#rectangular box [x0, x1) horizontally and [y0, y1) vertically - so the
#exact same function draws a FULL-SIZE ghost (the window/titlebar icon)
#or a smaller, QUADRANT-CONFINED ghost (the taskbar design's top-left
#corner), just by changing the box it's asked to fill.
def _ghost_pixel_on(x, y, x0, x1, y0, y1):
    #Work out this box's width/height and this pixel's own position
    #inside it, normalized to 0.0-1.0 either way - every shape constant
    #below is written in these normalized units so the whole glyph scales
    #cleanly to any icon size without a single hardcoded pixel count.
    box_w, box_h = x1 - x0, y1 - y0
    nx = (x - x0 + 0.5) / box_w
    ny = (y - y0 + 0.5) / box_h
    cx = 0.5
    #--- The rounded head, the straight-sided body, and the wavy hem ---
    head_cy, head_r = 0.40, 0.38
    body_half_width = 0.36
    #Where the straight sides give way to the scalloped hem below.
    hem_top = 0.68
    if ny <= head_cy:
        #Above the head's own center line: must fall inside the circle.
        if not _in_ellipse(nx, ny, cx, head_cy, head_r, head_r):
            return False
    elif ny <= hem_top:
        #The straight-sided body, directly below the head.
        if abs(nx - cx) > body_half_width:
            return False
    else:
        #The scalloped hem: four triangular "legs". abs() of how far this
        #column sits from the body's own centerline, same width check as
        #the straight body above, applies here too.
        if abs(nx - cx) > body_half_width:
            return False
        #Map this column's position across the body width to 0.0-1.0.
        leg_count = 4
        t = (nx - (cx - body_half_width)) / (2 * body_half_width)
        #Which fraction of ONE leg's own width this column falls at.
        phase = (t * leg_count) % 1.0
        #A triangle wave peaking (=1.0, deepest point) at the center of
        #each leg and bottoming out (=0.0, shallowest) at the boundary
        #between two legs - exactly the scalloped silhouette a ghost's
        #hem is drawn with.
        leg_depth = 1.0 - abs(phase - 0.5) * 2.0
        local_bottom = hem_top + (1.0 - hem_top) * leg_depth
        if ny > local_bottom:
            return False
    #--- The two eyes: dark circular cutouts punched through the head ---
    eye_r, eye_cy = 0.07, 0.38
    if (_in_ellipse(nx, ny, cx - 0.15, eye_cy, eye_r, eye_r)
            or _in_ellipse(nx, ny, cx + 0.15, eye_cy, eye_r, eye_r)):
        #An eye pixel is a cutout, not part of the ghost's own silhouette.
        return False
    #Every other test passed - this pixel is part of the ghost.
    return True


#Define _slash_pixel_on, the taskbar design's diagonal divider - a
#straight line from the icon's top-right corner to its bottom-left
#corner (the classic "x + y = size" diagonal), thickened slightly so it
#stays visible even at a small icon size instead of vanishing to a
#single, easy-to-miss pixel.
def _slash_pixel_on(x, y, size):
    #How far this pixel sits from the ideal diagonal line, in "fatness"
    #units perpendicular-ish to it - close enough at pixel scale without
    #needing real perpendicular-distance trigonometry.
    distance_from_line = abs((x + y) - (size - 1))
    #Scale the line's thickness with the icon's own size, with a floor of
    #1 pixel, so it reads as a clean stroke rather than a hairline at
    #larger sizes or an overly fat bar at smaller ones.
    thickness = max(1, size // 24)
    return distance_from_line <= thickness


#Define _label_pixel_on, which renders `label` (already uppercased and
#truncated by the caller) using FONT_3X5 above, anchored to the icon's
#own bottom-right corner with a small margin - the taskbar design's
#"which target is this" text.
def _label_pixel_on(x, y, size, label, scale):
    #Every glyph is 3 pixels wide, 5 tall, at the font's native (1x)
    #resolution, with 1 native pixel of space between characters.
    char_w, char_h, spacing = 3, 5, 1
    total_native_w = len(label) * char_w + max(0, len(label) - 1) * spacing
    total_w, total_h = total_native_w * scale, char_h * scale
    #Margin scales gently with icon size too, so it never looks cramped
    #against the corner at 48px or disproportionately large at 32px.
    margin = max(1, size // 16)
    start_x = size - margin - total_w
    start_y = size - margin - total_h
    #Outside the label's own bounding box entirely.
    if x < start_x or y < start_y or x >= start_x + total_w or y >= start_y + total_h:
        return False
    rel_x, rel_y = x - start_x, y - start_y
    char_stride = (char_w + spacing) * scale
    char_index = rel_x // char_stride
    #Guards against floating past the last character into rounding slack.
    if char_index >= len(label):
        return False
    within_char_x = rel_x - char_index * char_stride
    #Inside the 1-native-pixel gap between two characters, not the glyph.
    if within_char_x >= char_w * scale:
        return False
    col, row = within_char_x // scale, rel_y // scale
    glyph_rows = FONT_3X5.get(label[char_index], FONT_3X5["?"])
    return glyph_rows[row][col] == "#"


#Define build_icon_photoimage, the one function app.py actually calls
#per size. mode is "window" (plain ghost, always, any size) or "taskbar"
#(ghost top-left + diagonal slash + friendly-name label, falling back to
#plain ghost below TASKBAR_LAYOUT_MIN_SIZE - see this module's own top
#comment for why). friendly_name is only used in "taskbar" mode; pass
#None/"" for "window" mode. invert=True swaps the two colors (black
#ghost/slash/label on a solid white square instead of white-on-black) -
#used only for the "flash" frame of app.py's own new-critical-finding
#notification (alternating normal/inverted icons on a timer is what
#actually produces the blink - see app.py's own _start_icon_flash()),
#never shown as this icon's resting state. Returns a ready-to-use
#tk.PhotoImage; the CALLER is responsible for keeping a reference to it
#for as long as the window exists (see app.py's own comment on this -
#Tkinter does not keep its own reference, and a garbage-collected
#PhotoImage silently goes blank).
def build_icon_photoimage(size, mode, friendly_name=None, invert=False):
    use_taskbar_layout = mode == "taskbar" and size >= TASKBAR_LAYOUT_MIN_SIZE
    on_color, off_color = (ICON_BG, ICON_FG) if invert else (ICON_FG, ICON_BG)
    if use_taskbar_layout:
        #Uppercase and truncate to the first 3 characters ONCE, up front,
        #rather than recomputing it for every single pixel below.
        label = (friendly_name or "").strip().upper()[:3]
        half = size // 2
        scale = max(1, half // 12)
    #Build one grid of hex colors in one shot, instead of calling .put()
    #once per pixel (which works, but is dramatically slower - put() has
    #to process a whole new argument on every single call).
    #
    #IMPORTANT: this is handed to PhotoImage.put() as a native Python list
    #of lists (one inner list per row, one hex string per pixel) rather
    #than a hand-built Tcl brace-string like "{{#fff #000} {#000 #fff}}".
    #An earlier version of this function built that brace-string by hand
    #and joining it itself - it was only ever exercised against a fake,
    #string-recording PhotoImage stub in this sandbox (which has no real
    #Tk to test against at all), and it turned out NOT to be valid input
    #once run against a real Tk interpreter, which raised during
    #App.__init__() and made the whole GUI silently fall back to the
    #terminal text menu (see cli.py's broad except around launch_gui()).
    #Real tkinter's PhotoImage.put() directly accepts a nested list/tuple
    #of color strings - letting Tk's own C implementation build the
    #correct Tcl list instead of hand-rolling brace syntax - which is the
    #documented, version-safe way to pass a full grid in one call.
    rows = []
    for y in range(size):
        row_colors = []
        for x in range(size):
            if not use_taskbar_layout:
                #Plain window/titlebar icon, OR a taskbar icon too small
                #for the full layout: ghost alone, full size.
                on = _ghost_pixel_on(x, y, 0, size, 0, size)
            else:
                #The full taskbar design: ghost confined to the top-left
                #quadrant, the diagonal slash over the whole icon, and
                #the friendly-name label anchored to the bottom-right.
                on = ((x < half and y < half and _ghost_pixel_on(x, y, 0, half, 0, half))
                      or _slash_pixel_on(x, y, size)
                      or _label_pixel_on(x, y, size, label, scale))
            row_colors.append(on_color if on else off_color)
        rows.append(row_colors)
    image = tk.PhotoImage(width=size, height=size)
    image.put(rows)
    return image


#Define build_icon_photoimages, the convenience wrapper app.py actually
#calls - builds every size this icon ships at in one go, automatically
#choosing which design each size gets (see TASKBAR_LAYOUT_MIN_SIZE and
#this module's own top comment on why the smallest size always stays
#plain-ghost: Windows' own titlebar-vs-taskbar size convention, and
#"too small to read" either way). root.iconphoto() accepts multiple
#images and lets the OS pick whichever fits a given context best, which
#reads noticeably crisper than handing it one size and letting Tk scale it.
def build_icon_photoimages(friendly_name, sizes=(48, 32, 16), invert=False):
    #Build and return one PhotoImage per requested size, largest first -
    #each one gets the taskbar layout if it's large enough to hold it,
    #plain ghost otherwise (build_icon_photoimage() itself decides that).
    return [build_icon_photoimage(size, "taskbar", friendly_name, invert=invert) for size in sizes]
