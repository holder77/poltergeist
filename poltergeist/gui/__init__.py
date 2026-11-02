#DESCRIPTION: This file marks poltergeist/gui/ as its own sub-package,
#             separate from the text-based CLI in poltergeist/cli.py. It
#             deliberately does nothing but re-export launch_gui() - every
#             real GUI module (theme, dialogs, console, wizard,
#             findings_view, app) is imported from inside app.py's own
#             function bodies, NOT at the top of this file, because this
#             file must stay importable even on a machine that has no
#             Tkinter at all. If this file tried "from .app import App" up
#             top, just importing poltergeist.gui to check whether a GUI
#             is possible would itself crash with ModuleNotFoundError on a
#             box missing Tkinter - exactly the situation launch_gui() is
#             supposed to detect and report cleanly instead.

#Define launch_gui as a thin wrapper that only imports app.py's real
#launch_gui function at call time, once we actually need it.
def launch_gui():
    #Import here, not at module load time, so a missing Tkinter only ever
    #surfaces the moment someone actually tries to launch the GUI.
    from .app import launch_gui as _launch_gui
    #Call through to the real implementation and hand back its result.
    return _launch_gui()
