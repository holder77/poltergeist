#DESCRIPTION: This module answers "who has an account on this machine, and
#             who is an administrator?" A red team that gets a foothold
#             will very often create a new user or add an existing one to
#             the administrators/sudo group, because it is a quiet way to
#             keep access even if their original shell gets closed.

#import platform so this module knows whether to read Windows or Linux
#user account information.
import platform

#import subprocess so we can run "net user" and "net localgroup" on
#Windows to list accounts and administrators.
import subprocess

#import the sha256_of helper so the shadow file (if readable) is tracked
#the same consistent way as every other hash in this project.
from ..evidence import sha256_of

#Store whether we are on Windows once for the whole module to reuse.
IS_WINDOWS = platform.system() == "Windows"


#Define run_command as a small local wrapper, matching the pattern used in
#the other modules, so this file has no dependency on anything outside
#the standard library plus our own evidence.py helpers.
def run_command(command):
    #Try to run the command and capture its text output.
    try:
        #Give the command 15 seconds before giving up.
        result = subprocess.run(command, capture_output=True, text=True, timeout=15)
        #Return the standard output text.
        return result.stdout
    #If the command fails or is missing, do not crash the scan.
    except Exception:
        #Return an empty string, treated as "no output" by the caller.
        return ""


#Define collect, the function modules/__init__.py registers for this
#module's STATE_MODULES entry.
def collect(config):
    #Start with an empty dictionary to fill in below.
    state = {}
    #Branch based on which operating system we are auditing.
    if IS_WINDOWS:
        #Run "net user" to list every local account on the machine.
        user_output = run_command(["net", "user"])
        #TODO: parse the real column layout of "net user" output here
        #instead of a naive split; the current pass is a first cut and
        #should be tightened before relying on it in a real competition.
        for line in user_output.splitlines()[4:]:
            #Split the line on whitespace to pull out individual names.
            for name in line.split():
                #Skip the boilerplate "The command..." footer lines.
                if not name.startswith(("The", "---")):
                    #Record this account under a "user:" prefixed key.
                    state[f"user:{name}"] = ""
        #Run "net localgroup Administrators" to list every local admin.
        admin_output = run_command(["net", "localgroup", "Administrators"])
        #Loop over the relevant lines of that output.
        for line in admin_output.splitlines()[6:]:
            #Skip blank lines and the trailing "The command..." footer.
            if line.strip() and not line.startswith("The command"):
                #Record this administrator under an "admin:" prefixed key.
                state[f"admin:{line.strip()}"] = ""
    else:
        #Try to read /etc/passwd, which lists every local account on Linux.
        try:
            #Open the file and read it one line at a time.
            with open("/etc/passwd") as passwd_file:
                #Loop over every account entry in the file.
                for line in passwd_file:
                    #Skip any blank lines.
                    if line.strip():
                        #Record this account line under a "passwd:" key.
                        state[f"passwd:{line.strip()}"] = ""
        #If the file cannot be read for any reason, skip it quietly.
        except Exception:
            #Deliberately do nothing and continue with the rest of collect.
            pass
        #Try to read /etc/group to find who belongs to privileged groups.
        try:
            #Open the group file and read it one line at a time.
            with open("/etc/group") as group_file:
                #Loop over every group entry in the file.
                for line in group_file:
                    #Only keep entries for groups that grant elevated access.
                    if line.split(":")[0] in ("sudo", "wheel", "admin", "root"):
                        #Record this privileged group's membership line.
                        state[f"group:{line.strip()}"] = ""
        #If the file cannot be read for any reason, skip it quietly.
        except Exception:
            #Deliberately do nothing and continue with the rest of collect.
            pass
        #Hash the shadow file as a whole rather than reading passwords out
        #of it, since a changed hash alone is enough to prove it was
        #touched without this tool ever needing to see anyone's hash.
        state["shadow:hash"] = sha256_of("/etc/shadow")
    #Hand back the completed state dictionary.
    return state
