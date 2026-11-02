#DESCRIPTION: Windows-build-only helper. Renders Poltergeist's own ghost
#             mascot - using the EXACT same pure-geometry math that lives
#             in poltergeist/gui/icon.py (_ghost_pixel_on), not a second
#             hand-drawn copy of it - into a real multi-size .ico file
#             that PyInstaller can embed as the .exe's own FILE icon (the
#             icon Explorer shows on the .exe itself and in its taskbar
#             button before/while it's running). That's a different thing
#             from the LIVE titlebar/taskbar icon icon.py already builds
#             once the window is actually open - PyInstaller's own
#             --icon flag needs one real .ico file sitting on disk at
#             BUILD time; there is no way to hand it a function instead,
#             so this script exists purely to produce that one file.
#
#             Each requested size is rendered FRESH from the same
#             resolution-independent pixel math icon.py's own
#             build_icon_photoimage() uses (not resized/resampled down
#             from one big image), so even the small 16x16 frame stays
#             crisp instead of blurry.
#
#             Needs Pillow at BUILD TIME ONLY - this script, and the .ico
#             file it produces, are never imported or read by the actual
#             running program, so Pillow is deliberately NOT added to
#             requirements.txt. build_exe.bat runs this automatically; it
#             only needs to be run by hand if you're doing something
#             custom:
#
#                 pip install pillow
#                 python generate_icon.py
#
#             Produces poltergeist.ico (16/32/48/256px) right next to
#             this script, which poltergeist.spec then points PyInstaller
#             at via --icon / the EXE()'s own icon= argument.

#import sys/os to locate the real project package two folders up from
#this script (packaging/windows/generate_icon.py -> repo root) and add it
#to the import path, the same way poltergeist.py's own launcher does.
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")))

#Pillow is the one dependency this build-time-only script needs - not a
#runtime dependency of the shipped program at all (see this file's own
#top comment).
from PIL import Image

#Import icon.py's own pure pixel-math function directly, rather than
#re-deriving the ghost's shape by hand here - this script's whole point
#is that the .exe's file icon and the window's own live-built icon are
#drawn from the exact same geometry and can never visually drift apart.
#icon.py's own top-level "import tkinter as tk" is harmless here even
#though this script never opens a window - it only needs tkinter to be
#INSTALLED, which it will be on any machine set up to build/run the GUI
#at all.
from poltergeist.gui import icon as icon_module

#Where the finished .ico lands - right next to this script, which is
#exactly where poltergeist.spec (in this same folder) expects to find it.
OUT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "poltergeist.ico")

#The standard Windows icon sizes worth including - 16/32/48 cover the
#titlebar/taskbar/Alt-Tab sizes icon.py's own runtime icon already
#targets, and 256 is what Explorer and the "large icons" view use.
ICO_SIZES = [16, 32, 48, 256]


#Define render_ghost_at_size, which renders ONE square RGBA image of just
#the plain ghost mascot (no diagonal slash, no friendly-name label - this
#is the .exe's own static file icon, not the live per-target taskbar
#design) at the given pixel size, by asking icon_module's own
#_ghost_pixel_on() whether each individual pixel is lit, exactly the same
#way build_icon_photoimage() does for the live runtime icon.
def render_ghost_at_size(size):
    #Start fully opaque black, matching ICON_BG, then punch in white
    #ghost pixels - the exact same two-color palette the live icon uses.
    image = Image.new("RGBA", (size, size), (0, 0, 0, 255))
    pixels = image.load()
    for y in range(size):
        for x in range(size):
            #Ask the real, shared ghost-shape function - the whole box is
            #the full icon here, same as icon.py's own "window" mode.
            if icon_module._ghost_pixel_on(x, y, 0, size, 0, size):
                pixels[x, y] = (255, 255, 255, 255)
    return image


#Define main, which renders every requested size and writes them all into
#one real multi-resolution .ico file.
def main():
    #Render every size independently (not by resizing a single big
    #image), so every frame in the finished .ico is crisp pixel art, not
    #a blurrily-resampled copy of a different size.
    images_by_size = [render_ghost_at_size(size) for size in ICO_SIZES]
    #Pillow's ICO writer only keeps a frame from append_images AS-IS
    #(instead of resampling it from the base image) when the base image
    #is the LARGEST one in the set - handing it a smaller base and
    #"bigger" sizes in append_images silently drops everything except
    #the base's own size instead (confirmed directly against this exact
    #Pillow version while building this script - not documented clearly
    #enough to just trust). ICO_SIZES is already smallest-to-largest, so
    #the base image is deliberately the LAST one rendered, not the first.
    base_image = images_by_size[-1]
    base_image.save(OUT_PATH, format="ICO", sizes=[(size, size) for size in ICO_SIZES],
                     append_images=images_by_size[:-1])
    print(f"Wrote {OUT_PATH} ({', '.join(str(s) + 'x' + str(s) for s in ICO_SIZES)})")


if __name__ == "__main__":
    main()
