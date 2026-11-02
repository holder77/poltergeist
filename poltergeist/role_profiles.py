#DESCRIPTION: This file holds a small, hand-maintained list of "this kind
#             of machine usually cares about these files/ports" profiles.
#             The wizard asks the user one question - "what is this
#             machine's role?" - and uses the matching profile here to
#             pre-fill the critical_paths and expected service hints it
#             suggests, instead of showing the same generic list to a
#             Windows Domain Controller and a Linux web server. The user
#             can still edit anything the wizard suggests.

#import os so profile entries can be filtered down to paths that actually
#exist on this machine before they are suggested.
import os

#Define ROLE_PROFILES as the single source of truth for every known role.
#Each entry is a short, human label plus a list of candidate critical
#paths worth hashing and protecting for that kind of machine.
ROLE_PROFILES = {
    #A generic Linux server with no special role, the safe fallback.
    "linux_generic": {
        "label": "Linux - generic server",
        "critical_paths": ["/etc/ssh/sshd_config", "/etc/passwd", "/etc/sudoers", "/etc/hosts"],
    },
    #A Linux box mainly running a web server (Apache, nginx, PHP).
    "linux_web": {
        "label": "Linux - web server",
        "critical_paths": [
            "/etc/ssh/sshd_config", "/etc/passwd", "/etc/sudoers", "/var/www",
            "/etc/nginx", "/etc/apache2", "/etc/httpd", "/etc/php",
        ],
    },
    #A Linux box mainly running a database (MySQL/MariaDB/Postgres).
    "linux_db": {
        "label": "Linux - database server",
        "critical_paths": [
            "/etc/ssh/sshd_config", "/etc/passwd", "/etc/sudoers",
            "/etc/mysql", "/etc/postgresql", "/var/lib/mysql",
        ],
    },
    #A generic Windows server with no special role, the safe fallback.
    "windows_generic": {
        "label": "Windows - generic server",
        "critical_paths": [r"C:\Windows\System32\drivers\etc\hosts"],
    },
    #A Windows Domain Controller, where account/auth files matter most.
    "windows_dc": {
        "label": "Windows - Domain Controller",
        "critical_paths": [r"C:\Windows\System32\drivers\etc\hosts", r"C:\Windows\NTDS", r"C:\Windows\SYSVOL"],
    },
    #A Windows box mainly running IIS as a web server.
    "windows_web": {
        "label": "Windows - IIS web server",
        "critical_paths": [r"C:\Windows\System32\drivers\etc\hosts", r"C:\inetpub\wwwroot", r"C:\inetpub\temp\appPools"],
    },
    #The explicit "I don't want a profile, just ask me everything plainly"
    #option, which falls back to no suggested critical paths at all.
    "custom": {
        "label": "Custom / not listed (no extra suggestions)",
        "critical_paths": [],
    },
}


#Define list_roles, used by the wizard to print the menu of role choices
#in a stable, predictable order.
def list_roles():
    #Return the dictionary's keys as a plain list, in definition order.
    return list(ROLE_PROFILES.keys())


#Define suggested_paths_for_role, which filters a role's candidate paths
#down to only the ones that actually exist on this machine right now, so
#the wizard never suggests protecting a folder that is not even there.
def suggested_paths_for_role(role_key):
    #Look up the profile, falling back to the generic one if the given
    #role_key is not recognized for any reason.
    profile = ROLE_PROFILES.get(role_key, ROLE_PROFILES["linux_generic"])
    #Keep only the candidate paths that exist on this machine right now.
    return [path for path in profile["critical_paths"] if os.path.exists(path)]
