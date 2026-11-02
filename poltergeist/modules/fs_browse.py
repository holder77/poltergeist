#DESCRIPTION: This module answers one question: "what's inside this one
#             folder, right now?" - a small, self-contained, read-only
#             directory listing, used to let a person EXPLORE a machine's
#             filesystem interactively (one folder at a time, picking a
#             subfolder to step into, or stepping back up to the parent)
#             instead of typing a full path blind. The exact same
#             list_directory() function here runs in TWO different
#             places depending on the target: directly, in-process, for a
#             LOCAL target (gui/app.py calls it straight); or on the
#             REMOTE machine, invoked through "poltergeist.py --list-dir"
#             over SSH and its JSON result parsed back (modules/remote.py's
#             list_remote_directory()) for a remote target - so a remote
#             browse always sees the REMOTE machine's own real folders,
#             never the analyst's own laptop's, the exact same "deploy &
#             run as self" idea every other remote feature in this
#             project already uses. This module never writes, deletes, or
#             changes anything - it only ever reads directory entries.

#import os for every actual filesystem call this module makes.
import os

#import platform so this module knows whether to offer a Windows-style
#drive list or a Linux-style single root when no specific path is given.
import platform

#import string for Windows' own A-Z drive-letter range, used only when
#building the "list every drive" pseudo-folder below.
import string

#Store whether we are on Windows once for the whole module to reuse.
IS_WINDOWS = platform.system() == "Windows"

#A fixed, special path value meaning "show the Windows drive list"
#rather than any one real folder - the Windows equivalent of "/" on
#Linux/macOS, since Windows has no single filesystem root of its own.
#Never a real path on disk, so it can never collide with one.
WINDOWS_DRIVE_LIST_SENTINEL = ""


#Define default_start_path, worked out once per call so list_directory()
#below always has SOME real path to start from when the caller passes
#nothing in particular (the very first folder a browse dialog opens to).
def default_start_path():
    #On Windows, start from the current user's own profile folder (same
    #starting point Explorer itself defaults new windows to) - a real,
    #always-readable folder, unlike "list every drive" which is a
    #reasonable BACK target but a slightly odd first screen to land on.
    if IS_WINDOWS:
        return os.environ.get("USERPROFILE") or "C:\\"
    #On Linux/macOS, start from the current user's own home directory -
    #almost always readable, and the most useful default starting point
    #for picking a folder to watch.
    return os.path.expanduser("~") or "/"


#Define list_windows_drives, returning every real, currently-reachable
#Windows drive letter as its own pseudo-folder entry - used both as the
#top-level listing when the caller explicitly asks for
#WINDOWS_DRIVE_LIST_SENTINEL, and as the "go up" target from any real
#drive root (C:\'s own parent is "the drive list", not another folder).
def list_windows_drives():
    #Check every possible drive letter - os.path.isdir on a "<letter>:\\"
    #that does not exist (no disk in that drive, nothing mapped there)
    #simply returns False, with no exception to handle.
    return [f"{letter}:\\" for letter in string.ascii_uppercase if os.path.isdir(f"{letter}:\\")]


#Define list_directory, the one real entry point this module offers:
#given a path (or "" for the OS-appropriate default/top level), return a
#plain dictionary describing what's there and how to navigate further -
#{"path": the real, normalized path this listing is actually FOR (or the
#drive-list sentinel), "parent": the path "go up" should lead to, or None
#if there is nowhere further up to go, "entries": a list of
#{"name", "is_dir"} dictionaries, directories first then files, both
#alphabetically, and "error": a short, human-readable string instead of
#"entries" if this folder could not be listed at all (permission denied,
#it no longer exists, etc.) Every field here is plain data - JSON-
#serializable with no further work, so cli.py's --list-dir flag can just
#json.dumps() this function's own return value directly for the remote
#case, and gui/app.py's folder browser dialog can use the exact same
#dictionary shape for the local case.
def list_directory(path=None):
    #On Windows, an explicit request for the drive list (either nothing
    #was given at all, or the caller is stepping BACK UP from a drive
    #root) returns the pseudo-folder of every real drive instead of
    #trying to list an actual filesystem path.
    if IS_WINDOWS and (not path or path == WINDOWS_DRIVE_LIST_SENTINEL):
        #Build one directory-shaped entry per real drive letter.
        drive_entries = [{"name": drive, "is_dir": True} for drive in list_windows_drives()]
        #The drive list itself has no further "up" to go to.
        return {"path": WINDOWS_DRIVE_LIST_SENTINEL, "parent": None, "entries": drive_entries}
    #Off Windows, nothing given at all means "start from the default".
    if not path:
        path = default_start_path()
    #Normalize the path: expand "~"/environment variables, then resolve
    #it to a real, absolute, no-".."-segments form - this is what makes
    #"go up one level" (parent, below) always land somewhere sane rather
    #than drifting through redundant "a/b/../c" segments over repeated
    #navigation.
    normalized_path = os.path.abspath(os.path.expandvars(os.path.expanduser(path)))
    #Try to actually list this folder's contents.
    try:
        raw_names = os.listdir(normalized_path)
    #Anything that goes wrong (permission denied, the folder vanished,
    #it was never a real folder in the first place) is reported back as
    #a plain, readable error rather than letting an exception reach the
    #caller - this function is read-only exploration, so a dead end
    #should be explained, not crash a browse dialog or a remote command.
    except Exception as exc:
        return {"path": normalized_path, "parent": _parent_of(normalized_path), "entries": [], "error": str(exc)}
    #Build one entry per item actually found, noting whether each one is
    #itself a folder (so the caller can show a different icon/let the
    #person step INTO it) - skip anything os.path.isdir itself cannot
    #even stat (a broken symlink, a permission-denied single item) rather
    #than letting one bad entry fail the whole listing.
    entries = []
    for name in raw_names:
        full_path = os.path.join(normalized_path, name)
        try:
            is_dir = os.path.isdir(full_path)
        except Exception:
            #Could not even stat this one entry - skip it, not the rest.
            continue
        entries.append({"name": name, "is_dir": is_dir})
    #Sort directories first, then files, both alphabetically (case-
    #insensitively, so "Downloads" and "downloads" sort together) - the
    #familiar file-manager ordering, and the one that puts what a person
    #browsing for a folder to watch actually wants to see right at the top.
    entries.sort(key=lambda entry: (not entry["is_dir"], entry["name"].lower()))
    return {"path": normalized_path, "parent": _parent_of(normalized_path), "entries": entries}


#Define _parent_of, a small private helper working out what "go up one
#level" from a given, already-normalized path should lead to - None once
#there is truly nowhere further up to go (Linux/macOS "/"), or
#WINDOWS_DRIVE_LIST_SENTINEL once a Windows browse has reached a real
#drive root (its own parent is "the drive list", not another folder).
def _parent_of(normalized_path):
    #Work out this path's own parent the normal way.
    parent = os.path.dirname(normalized_path.rstrip(os.sep) or os.sep)
    #Linux/macOS: dirname("/") is itself "/" - that is the real
    #filesystem root, with nowhere further up to go.
    if not IS_WINDOWS and parent == normalized_path:
        return None
    #Windows: dirname("C:\\") is itself "C:\\" (a drive root has no
    #folder "above" it on the same drive) - from there, "up" means back
    #to the drive list, not nowhere at all.
    if IS_WINDOWS and (parent == normalized_path or not parent):
        return WINDOWS_DRIVE_LIST_SENTINEL
    return parent
