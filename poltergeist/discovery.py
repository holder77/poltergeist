#DESCRIPTION: This file is what lets the setup wizard suggest real settings
#             instead of asking the user to type raw IP ranges and port
#             numbers from memory. It probes the machine it is running on
#             and hands back interfaces, subnets, anything that looks like
#             a VPN adapter, the default gateway, and whatever is currently
#             listening. The wizard in cli.py takes these as DEFAULTS, not
#             final answers, so the human always gets to confirm or edit
#             them before they are saved.

#import psutil because it gives us one cross-platform way to read network
#interfaces, addresses, and connections on both Windows and Linux.
import psutil

#import ipaddress so we can turn a raw IP and netmask into a proper CIDR
#network string like "10.0.1.0/24" instead of doing that math by hand.
import ipaddress

#import platform so we can tell whether we are running on Windows or Linux
#and choose the right shell command for finding the default gateway.
import platform

#import subprocess so we can run the small handful of OS commands we still
#need (route print on Windows, ip route on Linux) and read their output.
import subprocess

#import os so default_critical_paths() can check which candidate paths
#actually exist on this machine before suggesting them.
import os

#import role_profiles so discover() can fold in every role's suggested
#paths, pre-filtered to what actually exists here. This matters for a
#REMOTE target: discover() runs wherever it is called from (locally in
#this process, or on the far end over SSH via --discover-json), so an
#os.path.exists() check inside it is always checking the RIGHT machine's
#filesystem. If the wizard instead called role_profiles directly after
#the fact, a remote target's suggestions would silently be checked
#against the analyst's own laptop instead of the box actually being set up.
from . import role_profiles

#Store whether we are on Windows once, so every function below can just
#check this constant instead of calling platform.system() repeatedly. For
#a remote probe (run over SSH on the target itself), this correctly
#reflects the TARGET's OS, not the analyst's own machine, since the whole
#point of --discover-json is that it runs wherever it is asked to.
IS_WINDOWS = platform.system() == "Windows"

#Define a list of substrings that tend to show up in VPN or tunnel adapter
#names, so the wizard can guess which interfaces are VPN-related.
VPN_NAME_HINTS = ("tun", "tap", "wg", "ppp", "utun", "vpn", "wireguard", "openvpn", "zerotier", "tailscale")


#Define run_command as a tiny wrapper so every OS command call in this file
#handles timeouts and errors the exact same way.
def run_command(command):
    #Try to run the command and capture its text output.
    try:
        #Run the command, waiting at most 10 seconds so a hung command
        #never freezes the whole discovery step.
        result = subprocess.run(command, capture_output=True, text=True, timeout=10)
        #Return just the standard output text.
        return result.stdout
    #Catch anything that goes wrong (missing command, timeout, etc).
    except Exception:
        #Return an empty string so callers can treat "nothing found" the
        #same way whether the command failed or simply printed nothing.
        return ""


#Define find_interfaces, which lists every real (non-loopback) network
#interface on the machine along with its IP address and CIDR subnet.
def find_interfaces():
    #Start with an empty list to collect interface dictionaries into.
    interfaces = []
    #Ask psutil for every network interface and all of its addresses.
    for interface_name, addresses in psutil.net_if_addrs().items():
        #Loop over each address assigned to this one interface.
        for address in addresses:
            #Skip anything that is not a normal IPv4 address.
            if address.family.name != "AF_INET":
                #Move on to the next address without recording this one.
                continue
            #Skip the loopback address since it is never a real subnet.
            if address.address.startswith("127."):
                #Move on to the next address without recording this one.
                continue
            #Try to build a proper CIDR network from the IP and netmask.
            try:
                #strict=False allows host bits to be set, which is normal
                #for a machine's own address inside its subnet.
                network = str(ipaddress.ip_network(f"{address.address}/{address.netmask}", strict=False))
            #If the netmask is missing or malformed, skip this address.
            except Exception:
                #Move on to the next address without recording this one.
                continue
            #Add a dictionary describing this interface to our results.
            interfaces.append({"name": interface_name, "ip": address.address, "net": network})
    #Hand back the full list of discovered interfaces.
    return interfaces


#Define classify_interfaces, which splits discovered interfaces into
#"normal" subnets and "probably VPN" subnets based on the adapter name.
def classify_interfaces(interfaces):
    #Start two empty lists: one for normal nets, one for VPN-looking nets.
    normal_subnets, vpn_subnets = [], []
    #Loop through every interface we found.
    for interface in interfaces:
        #Lowercase the interface name so the hint match is case-insensitive.
        name_lower = interface["name"].lower()
        #Check whether any VPN hint substring appears in this adapter name.
        if any(hint in name_lower for hint in VPN_NAME_HINTS):
            #If it looks like a VPN adapter, file its subnet there.
            vpn_subnets.append(interface["net"])
        #Otherwise treat it as a normal, directly-connected subnet.
        else:
            #File its subnet into the normal list.
            normal_subnets.append(interface["net"])
    #Return both lists, de-duplicated by converting through a set.
    return sorted(set(normal_subnets)), sorted(set(vpn_subnets))


#Define find_default_gateway, which asks the OS which router it would use
#to reach the internet, since that address is almost always trustworthy.
def find_default_gateway():
    #Branch based on which operating system we are running on.
    if IS_WINDOWS:
        #On Windows, "route print 0.0.0.0" shows the default route table.
        output = run_command(["route", "print", "0.0.0.0"])
        #Look through each line of that output for the default route.
        for line in output.splitlines():
            #Split the line into whitespace-separated columns.
            parts = line.split()
            #A default route line starts with two "0.0.0.0" columns.
            if len(parts) >= 3 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                #The third column is the actual gateway address.
                return parts[2]
    #Otherwise, assume we are on Linux (or another route-compatible Unix).
    else:
        #"ip route show default" prints a line like "default via 10.0.0.1".
        output = run_command(["ip", "route", "show", "default"])
        #Split the whole output into individual words.
        parts = output.split()
        #Check whether the word "via" appears, which precedes the gateway.
        if "via" in parts:
            #The gateway address is the word right after "via".
            return parts[parts.index("via") + 1]
    #If nothing was found, return an empty string instead of crashing.
    return ""


#Define find_listening_ports, which lists every port currently accepting
#connections along with the process name that owns it.
def find_listening_ports():
    #Start with an empty list to collect results into.
    listening = []
    #Keep track of ports we have already recorded to avoid duplicates.
    seen_ports = set()
    #Wrap in a try block because reading all connections needs elevated
    #privileges on some systems and may raise a permissions error.
    try:
        #Ask psutil for every active internet (TCP/UDP) connection.
        for connection in psutil.net_connections(kind="inet"):
            #Only care about sockets that are actively listening.
            if connection.status != "LISTEN":
                #Skip anything that is not in the LISTEN state.
                continue
            #Skip ports we have already added to the results.
            if connection.laddr.port in seen_ports:
                #Move on to the next connection.
                continue
            #Remember this port so we do not list it twice.
            seen_ports.add(connection.laddr.port)
            #Default the owning process name to "?" in case we cannot read it.
            process_name = "?"
            #Try to look up the human-readable name of the owning process.
            try:
                #Only attempt this if a process ID was actually reported.
                if connection.pid:
                    #Ask psutil for the process object and read its name.
                    process_name = psutil.Process(connection.pid).name()
            #If we cannot read the process (it exited, access denied), skip.
            except Exception:
                #Leave process_name as "?" and keep going.
                pass
            #Add this port and its owning process to the results list.
            listening.append({"port": connection.laddr.port, "proc": process_name})
    #If listing connections needs permissions we do not have, tell the
    #caller instead of crashing the entire discovery step.
    except psutil.AccessDenied:
        #Print a clear one-line warning so the user knows to run as admin.
        print("  (need root/Administrator to see every listening port)")
    #Hand back whatever we managed to collect.
    return listening


#Define default_critical_paths, a small helper the wizard uses to suggest
#a starting list of files worth protecting, based on what actually exists
#on THIS machine right now (see the IS_WINDOWS comment above for why that
#is always the right machine, even for a remote target). Moved here from
#cli.py (which used to have its own copy, and gui/wizard.py a second,
#identical copy) so there is exactly one place this list is maintained,
#and so it is automatically probed on whichever machine discover() runs on.
def default_critical_paths():
    #Build the Windows candidate list if we are on Windows.
    if IS_WINDOWS:
        #List a handful of commonly-critical Windows paths.
        candidates = [r"C:\Windows\System32\drivers\etc\hosts", r"C:\inetpub\wwwroot", r"C:\inetpub\temp\appPools"]
    #Otherwise build the Linux candidate list.
    else:
        #List a handful of commonly-critical Linux config paths.
        candidates = [
            "/etc/ssh/sshd_config", "/etc/pam.d", "/etc/passwd", "/etc/sudoers", "/etc/sudoers.d",
            "/etc/hosts", "/etc/nginx", "/etc/apache2", "/etc/httpd", "/etc/mysql", "/etc/postgresql",
            "/var/www", "/etc/samba",
        ]
    #Only suggest paths that actually exist on this machine right now, so
    #the wizard's default list is never full of dead entries.
    return [path for path in candidates if os.path.exists(path)]


#Define discover, the single function cli.py actually calls. It runs every
#probe above and returns one dictionary the wizard can read defaults from.
#Everything in here is a plain, JSON-serializable dict on purpose: this
#exact return value is also what "poltergeist.py --discover-json" prints
#(see cli.py), which is how the wizard gets real, existence-checked
#defaults for a REMOTE target too - run once over SSH, right after deploy,
#against the target's own filesystem instead of the analyst's.
def discover():
    #Find every real network interface on this machine.
    interfaces = find_interfaces()
    #Split those interfaces into normal subnets and VPN-looking subnets.
    normal_subnets, vpn_subnets = classify_interfaces(interfaces)
    #Return everything the wizard needs as one combined dictionary.
    return {
        #The raw interface list, used only for printing to the user.
        "interfaces": interfaces,
        #Subnets that look like normal, directly-connected networks.
        "subnets": normal_subnets,
        #Subnets that look like VPN or tunnel adapters.
        "vpn_subnets": vpn_subnets,
        #The machine's current default gateway, if one was found.
        "gateway": find_default_gateway(),
        #Every port currently listening, with its owning process name.
        "listening": find_listening_ports(),
        #Whether the probed machine is Windows, so a remote wizard page
        #can show the right kind of path hints without any separate
        #remote-OS-detection step of its own.
        "is_windows": IS_WINDOWS,
        #The generic "commonly critical" path suggestions above.
        "default_critical_paths": default_critical_paths(),
        #Every role's own suggested paths, pre-filtered to what actually
        #exists on THIS machine, keyed by role so the wizard can just look
        #up whichever role the user picks after the fact (role is chosen
        #on a later wizard page, after discovery has already run once).
        "role_paths": {role_key: role_profiles.suggested_paths_for_role(role_key) for role_key in role_profiles.list_roles()},
    }
