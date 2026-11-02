#DESCRIPTION: This file is the registry of every check module Poltergeist
#             knows about. cli.py and exorcise.py import STATE_MODULES and
#             LIVE_MODULES from here instead of listing modules themselves,
#             so adding a brand new check is a two-step process: write the
#             module file, then add one line to one of the two dictionaries
#             below. Nothing else in the program needs to change.

#import each state module, the kind that gets baselined once and diffed
#against later (did something new appear, disappear, or change).
from . import persistence
from . import users
from . import integrity
from . import packages
from . import logging_health

#import each live module, the kind that checks the CURRENT moment every
#time it runs, with no baseline needed (is anything suspicious right now).
from . import processes
from . import network
from . import deception
from . import lockdown
from . import tripwire
from . import log_review

#Build the dictionary of state modules. The key is the short name used in
#findings and in the baseline file; the value is the function that returns
#a dictionary of {unique_key: hash_or_value} for that module's state.
STATE_MODULES = {
    "persistence": persistence.collect,
    "users": users.collect,
    "integrity": integrity.collect,
    "packages": packages.collect,
}

#Build the dictionary of live modules. The key is the short name used in
#findings; the value is the function that takes (config, log) and reports
#anything suspicious directly through the Log object, with no return value.
LIVE_MODULES = {
    "processes": processes.check,
    "network": network.check,
    "logging": logging_health.check,
    "tripwire": tripwire.check,
    #persistence.check is the evasive-persistence content/hidden-file
    #heuristic (see that module's own big comment on check() for the
    #full reasoning) - registered here under the exact same "persistence"
    #key persistence.collect already uses in STATE_MODULES above, so
    #every finding either one reports lands under module="persistence"
    #and shows up in the SAME Dashboard section ("EVASIVE PERSISTENCE"),
    #whether it came from a baseline diff or from this live content scan.
    "persistence": persistence.check,
    #log_review.check is the brute-force / successful-login-after-
    #brute-force heuristic over the monitored machine's own real auth
    #log - see that module's own big comment for the full reasoning.
    "logs": log_review.check,
}
