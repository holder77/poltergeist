#DESCRIPTION: This module holds the "break glass" commands: things a human
#             on the team decides to run on purpose when something has
#             clearly gone wrong. mute() rewrites the host firewall to
#             drop everything except the IPs the wizard was told to trust.
#             watch_for_isolation() is the dead-man's-switch: if THIS
#             machine loses all contact with the rest of the team's
#             network, it is safer to assume the worst and lock itself
#             down than to assume the best and do nothing. Both of these
#             only ever act on firewall rules on the local machine; they
#             never touch another machine or anyone else's account.

#import platform so we know whether to write iptables/nftables rules
#(Linux) or netsh advfirewall rules (Windows).
import platform

#import subprocess so we can actually run the firewall commands.
import subprocess

#import socket so the dead-man's-switch can do a basic reachability check
#against the team's own trusted IPs.
import socket

#Store whether we are on Windows once for the whole module to reuse.
IS_WINDOWS = platform.system() == "Windows"

#Windows-only fix for a real bug report: this module shells out to real
#console commands (netsh advfirewall) for Shield actions - without this,
#each one briefly flashes a console window open and closed. See
#modules/users.py's own copy of this exact fix for the full explanation;
#the short version is CREATE_NO_WINDOW tells Windows not to allocate a
#console for the child process at all, and the ternary keeps this safe
#to import on Linux too.
_HIDE_CONSOLE_KWARGS = {"creationflags": subprocess.CREATE_NO_WINDOW} if IS_WINDOWS else {}


#Define run_command as the same small wrapper pattern used across every
#other module, so every OS command call in this project behaves the same.
def run_command(command):
    #Try to run the command and capture its output.
    try:
        #Give the command 10 seconds before giving up on it.
        #**_HIDE_CONSOLE_KWARGS suppresses the flashing console window
        #this would otherwise pop open on Windows.
        result = subprocess.run(command, capture_output=True, text=True, timeout=10, **_HIDE_CONSOLE_KWARGS)
        #Return the combined stdout text.
        return result.stdout
    #If the command fails or is missing, do not crash the whole tool.
    except Exception:
        #Return an empty string so the caller can detect "nothing happened".
        return ""


#Define parse_rule, which turns a plain-English line the user types - like
#"block ip 192.168.1.55" or "block port 4444" or "allow ip 10.0.0.5" -
#into the matching native firewall command for this OS. This is the
#"Shield" feature: nobody has to remember iptables or netsh syntax.
def parse_rule(rule_text):
    #Lowercase and split the typed rule into individual words.
    words = rule_text.strip().lower().split()
    #A valid rule always has exactly three words: action, kind, value.
    if len(words) != 3:
        #Return None so the caller knows this text could not be parsed.
        return None
    #Unpack the three words into their meaning.
    action, kind, value = words
    #Only "block" and "allow" are recognized actions.
    if action not in ("block", "allow"):
        #Return None for anything else so the caller can show an error.
        return None
    #Only "ip" and "port" are recognized rule kinds.
    if kind not in ("ip", "port"):
        #Return None for anything else so the caller can show an error.
        return None
    #Hand back a clean dictionary describing exactly what was asked for.
    return {"action": action, "kind": kind, "value": value}


#Define apply_rule, which takes one parsed rule from parse_rule() and
#actually runs the matching native OS firewall command for it.
def apply_rule(rule, log):
    #Pull the three pieces of the rule back out for readability below.
    action, kind, value = rule["action"], rule["kind"], rule["value"]
    #Decide the native firewall action keyword for this OS and action.
    if IS_WINDOWS:
        #Windows uses the words "block" and "allow" directly.
        native_action = action
        #Build the right netsh command depending on whether this rule is
        #about an IP address or a port number.
        if kind == "ip":
            #Build a netsh rule blocking/allowing a specific remote IP.
            command = ["netsh", "advfirewall", "firewall", "add", "rule",
                       f"name=Poltergeist_{action}_{value}", "dir=out", f"action={native_action}", f"remoteip={value}"]
        else:
            #Build a netsh rule blocking/allowing a specific local port.
            command = ["netsh", "advfirewall", "firewall", "add", "rule",
                       f"name=Poltergeist_{action}_{value}", "dir=in", f"action={native_action}", f"localport={value}", "protocol=TCP"]
    else:
        #iptables uses -j DROP or -j ACCEPT as the target.
        native_action = "DROP" if action == "block" else "ACCEPT"
        #Build the right iptables command for an IP-based rule.
        if kind == "ip":
            #This single rule covers traffic going out to that IP.
            command = ["iptables", "-A", "OUTPUT", "-d", value, "-j", native_action]
        else:
            #This single rule covers inbound traffic on that port.
            command = ["iptables", "-A", "INPUT", "-p", "tcp", "--dport", value, "-j", native_action]
    #Actually run the native command we just built.
    run_command(command)
    #Log this single-rule change at high severity, since firewall changes
    #are exactly the kind of thing you want a timestamped record of later
    #when writing the incident report.
    log.add("lockdown", "high", f"rule:{action}:{kind}:{value}:{len(log.seen)}", f"Shield rule applied: {action} {kind} {value}", quiet_dupes=False)


#Define mute, the "drop everything except trusted IPs" command. This is a
#deliberate, human-triggered action, never called automatically.
def mute(config, log):
    #Pull the list of IPs we must keep allowed even during a lockdown,
    #since cutting off the scoring engine would be a self-inflicted loss.
    trusted_ips = config["trusted_ips"]
    #Log that a lockdown is starting, before we actually touch the firewall,
    #so there is a clear record even if the firewall commands fail partway.
    log.add("lockdown", "high", "mute_start", f"MUTE requested, allowing only: {trusted_ips}")
    #Branch based on which operating system's firewall syntax we need.
    if IS_WINDOWS:
        #Set the default inbound action to block everything by default.
        run_command(["netsh", "advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,blockoutbound"])
        #Loop over every trusted IP and add a specific allow rule for it.
        for trusted_ip in trusted_ips:
            #Add a rule allowing inbound traffic from this one trusted IP.
            run_command(["netsh", "advfirewall", "firewall", "add", "rule", f"name=Poltergeist_Allow_{trusted_ip}", "dir=in", "action=allow", f"remoteip={trusted_ip}"])
    else:
        #Flush any existing iptables rules so we start from a clean slate.
        run_command(["iptables", "-F"])
        #Set the default policy for new inbound connections to DROP.
        run_command(["iptables", "-P", "INPUT", "DROP"])
        #Set the default policy for outbound connections to DROP too.
        run_command(["iptables", "-P", "OUTPUT", "DROP"])
        #Always allow the loopback interface, since many local services
        #(like a database talking to its own web app) rely on it.
        run_command(["iptables", "-A", "INPUT", "-i", "lo", "-j", "ACCEPT"])
        run_command(["iptables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"])
        #Loop over every trusted IP and add a specific allow rule for it.
        for trusted_ip in trusted_ips:
            #Allow inbound traffic from this trusted IP.
            run_command(["iptables", "-A", "INPUT", "-s", trusted_ip, "-j", "ACCEPT"])
            #Allow outbound traffic to this trusted IP.
            run_command(["iptables", "-A", "OUTPUT", "-d", trusted_ip, "-j", "ACCEPT"])
    #Log that the lockdown finished, so there is a clear end marker too.
    log.add("lockdown", "high", "mute_done", "Firewall lockdown applied")


#Define check_reachable, a small helper that tests whether we can still
#open a TCP connection to at least one trusted IP, used by the dead-man's
#switch below to decide whether this machine has been isolated.
def check_reachable(ip, port=443, timeout=2):
    #Try to open a short-lived TCP connection to the given IP and port.
    try:
        #socket.create_connection raises an exception on any failure.
        socket.create_connection((ip, port), timeout=timeout).close()
        #If no exception was raised, the IP is reachable.
        return True
    #Catch any connection failure (timeout, refused, unreachable, etc).
    except Exception:
        #Return False to signal this IP could not be reached.
        return False


#Define watch_for_isolation, meant to be called once per monitor loop
#iteration. If every trusted IP becomes unreachable, it treats that as a
#sign the network has been cut and calls mute() to lock the box down
#rather than leaving it wide open while blind to the rest of the team.
def watch_for_isolation(config, log):
    #If there are no trusted IPs configured, this check cannot run safely,
    #since we would have no way to tell "isolated" from "normal".
    if not config["trusted_ips"]:
        #Return immediately without doing anything.
        return
    #Check every trusted IP and remember if ANY of them was reachable.
    any_reachable = any(check_reachable(ip) for ip in config["trusted_ips"])
    #If literally none of them could be reached, something is very wrong.
    if not any_reachable:
        #Log this as the highest priority event this tool can raise.
        log.add("lockdown", "high", "isolated", "Lost contact with ALL trusted IPs, this looks like network isolation")
        #TODO: make automatic dead-man's-switch lockdown an explicit opt-in
        #setting in the wizard (default OFF) before calling mute() here,
        #since locking yourself out automatically is a real risk and
        #should always be something the team consciously turned on.
