#DESCRIPTION: This module answers "has any of our critical configuration
#             been changed?" It hashes exactly the files and folders the
#             user listed as "critical_paths" during the setup wizard
#             (things like sshd_config, a web server config, or a database
#             config). It is deliberately simple: the wizard decides WHAT
#             to protect, and this module just hashes whatever it is told.

#import os and glob so we can expand wildcard paths and walk folders.
import os
import glob

#import the sha256_of helper so every file here is hashed exactly the same
#way as persistence.py and users.py, keeping the whole baseline consistent.
from ..evidence import sha256_of


#Define list_files_under again locally (a small, intentional duplicate of
#the one in persistence.py) so this module has no import dependency on
#another check module; two check modules should never depend on each
#other, only on the shared evidence.py helpers.
def list_files_under(path_or_pattern, cap=3000):
    #Start with an empty list of discovered file paths.
    found_files = []
    #Expand environment variables and "~" before globbing.
    expanded = os.path.expandvars(os.path.expanduser(path_or_pattern))
    #Match the pattern, falling back to the literal path if there is no
    #wildcard in it at all.
    matches = glob.glob(expanded) or [expanded]
    #Loop over every match the glob found.
    for matched_path in matches:
        #If the match is a folder, walk every file underneath it.
        if os.path.isdir(matched_path):
            #os.walk automatically recurses into every subfolder.
            for root, _, file_names in os.walk(matched_path):
                #Loop over every file name in this subfolder.
                for file_name in file_names:
                    #Record the full path to this one file.
                    found_files.append(os.path.join(root, file_name))
                    #Stop early once we hit the safety cap.
                    if len(found_files) >= cap:
                        #Return immediately to avoid hanging on a huge tree.
                        return found_files
        #If the match is a single file, record it directly.
        elif os.path.isfile(matched_path):
            #Add this one file path to the results.
            found_files.append(matched_path)
    #Hand back every file path discovered.
    return found_files


#Define collect, the function modules/__init__.py registers for this
#module's STATE_MODULES entry.
def collect(config):
    #Start with an empty dictionary to fill in below.
    state = {}
    #Loop over every critical path the user configured in the wizard.
    for critical_path in config.get("critical_paths", []):
        #Expand that path into every real file sitting under it.
        for file_path in list_files_under(critical_path):
            #Record this file's hash under a "file:" prefixed key, the
            #exact same convention persistence.py uses, so cli.py's diff
            #and restore logic can treat every module's files the same way.
            state[f"file:{file_path}"] = sha256_of(file_path)
    #Hand back the completed state dictionary.
    return state
