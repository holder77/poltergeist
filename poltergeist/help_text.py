#DESCRIPTION: This file is the tool's own in-app documentation. Every
#             cutesy module name used elsewhere (Sentinel, Shield, Oracle,
#             Haunting, Tripwire, Medium, Scribe) gets one plain-English
#             paragraph here saying exactly what it does, with no jargon.
#             print_glossary() is called from the "Help" menu item and
#             the --glossary flag, so the explanation is always one
#             keypress away instead of living only in the README.

#import the colorize helper so section names stand out here too.
from .color import colorize

#Define GLOSSARY as a list of (cutesy name, plain description) pairs, in
#the same order they appear in the main menu, so reading top to bottom
#here matches reading top to bottom there.
GLOSSARY = [
    ("Setup wizard", "Asks a handful of questions about this machine - what networks it's on, what role it plays - and probes the machine itself to suggest sensible defaults for each answer."),
    ("Sentinel", "The baseline-and-watch system. 'Baseline' hashes every startup location, account, and protected file ONCE, on a box you trust is clean. 'Monitor' or 'One-shot check' then compares the current state back against that baseline, forever, and flags anything new, missing, or changed."),
    ("Quick Scan", "One command, one report: runs the process, network, logging, and SSH-key checks right now and prints them all together under clear headers. No baseline required - good for a fast first look at an unfamiliar box."),
    ("Haunting", "Plants fake 'bait' files (honeytokens) with tempting names like scoring_credentials.txt, in up to 3 REAL folders you pick (a web root, a shared drive - 'Canary: Choose a Bait Location'). If anyone opens one, you get an alert. Different from Tripwire: this catches someone OPENING a fake file, not a real file changing. It never locks out or punishes whoever touched it - it only tells you."),
    ("Tripwire", "Lets you start watching any ONE folder on the fly, without re-running the whole Sentinel baseline. Hashes that folder right now, then flags any file added, changed, or removed in it on every future check."),
    ("Shield", "Manages the host firewall without you needing to remember iptables or netsh syntax. Type a plain-English rule ('block ip 10.0.0.5') or hit MUTE to drop everything except your trusted IPs."),
    ("Oracle", "Checks what you're actually running - both live service banners and installed package versions - against a small, offline list of known-risky versions. It cannot reach the internet during a competition. 'Refresh OSINT Hints' is the one way to update that list - run it BEFORE the competition, on a machine with real internet access, and it pulls in CISA's own feed of actively-exploited vulnerabilities."),
    ("Medium", "A best-effort whole-volume snapshot (Windows Volume Shadow Copy or Linux LVM), on top of Sentinel's regular file-by-file backups. 'Take Snapshot' only works if the box was actually set up to support it. 'Revert a Folder' rolls ONE chosen folder back to that snapshot - this does overwrite live files, so it asks you to type RESTORE first."),
    ("Scribe", "Turns everything logged so far into one clean Markdown incident report, grouped by severity, with every suggested command included - ready to hand to judges."),
    ("Dashboard", "A live, auto-refreshing web page showing every finding as it happens. Only reachable from this machine (127.0.0.1) - never exposed to the network."),
]


#Define print_glossary, the single function the "Help" menu item and the
#--glossary flag both call.
def print_glossary():
    #Print a clear top banner for the glossary.
    print(colorize("\n=== What do these names mean? ===", "header"))
    #One reminder, up front, of the rule that applies to every single one
    #of these: nothing here acts on its own.
    print("Every module below only ever ALERTS and SUGGESTS. Nothing in Poltergeist kills a\nprocess, deletes a file, or runs a suggested command by itself - a human decides.\n")
    #Loop over every (name, description) pair in order.
    for name, description in GLOSSARY:
        #Print the cutesy name in bold-ish color, then its plain description.
        print(colorize(f"{name}:", "ok"))
        #Print the description, indented, on its own line.
        print(f"  {description}\n")
