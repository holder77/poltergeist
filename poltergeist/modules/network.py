#DESCRIPTION: This module answers "is this machine talking to anyone it
#             should not be?" It is a LIVE module, checked fresh every
#             time. It flags new listening ports, known-bad listening
#             ports, and any established connection to an address outside
#             the networks the user told the wizard to trust - PLUS a
#             beacon-timing heuristic (see check_beacon_pattern() below)
#             that flags a connection whose check-ins to one destination
#             keep landing at suspiciously REGULAR intervals, which is
#             how C2 malware checking in on a fixed timer looks different
#             from ordinary chatty traffic (a real person browsing, or a
#             legitimate app syncing, does not check in once every N
#             seconds on the dot). This is a deliberately simple, single
#             axis ("is the timing too regular") heuristic - nowhere near
#             as thorough as the user's own separate Shadow Watch tool's
#             4-axis differentiator (payload shape, process ancestry,
#             destination behavior, JSON shape), but it needs nothing
#             beyond what this module already reads (psutil connections,
#             persisted the same way tripwire.py already persists its own
#             state across scans), and it is explainable in one sentence
#             to whoever is reading the finding.

#import psutil so we can read every live network connection on either OS.
import psutil

#import ipaddress so we can test whether a remote IP falls inside one of
#the CIDR ranges the user marked as trusted or internal.
import ipaddress

#import capture_process from evidence.py so a high severity connection
#also gets the owning process's full forensic snapshot saved.
from ..evidence import capture_process

#import platform so the suggested review command matches the current OS.
import platform

#import os, json, time, and statistics for the beacon-timing state file
#and the regularity math below - the exact same small-JSON-state-file
#pattern tripwire.py and logging_health.py already use for their own
#persistent, across-scan memory.
import os
import json
import time
import statistics

#Store whether we are on Windows once for the whole module to reuse.
IS_WINDOWS = platform.system() == "Windows"


#Define suggest_network_fix, which builds a safe command to look closer
#at a connection or, if the human decides it is bad, to BLOCK that one
#remote IP at the firewall - never to kill the process automatically.
def suggest_network_fix(pid, remote_ip):
    #Build the OS-appropriate "look closer" command first.
    review = f"Get-Process -Id {pid} | Format-List *" if IS_WINDOWS else f"ss -tpn | grep {pid}"
    #Build the OS-appropriate "block just this IP" command.
    block = f'netsh advfirewall firewall add rule name="Poltergeist_Block" dir=out action=block remoteip={remote_ip}' \
        if IS_WINDOWS else f"iptables -A OUTPUT -d {remote_ip} -j DROP"
    #Combine both into one suggestion string.
    return f"review: {review}; to block just this IP: {block}"


#Define ip_in_any_network, a small helper that checks one IP address
#against a whole list of CIDR ranges at once.
def ip_in_any_network(ip_text, cidr_list):
    #Try the comparison, since a malformed IP or CIDR should not crash
    #the whole network check.
    try:
        #Parse the raw IP text into a real IP address object.
        ip_address = ipaddress.ip_address(ip_text)
        #Return True the first time the IP is found inside any network.
        return any(ip_address in ipaddress.ip_network(cidr, strict=False) for cidr in cidr_list)
    #If parsing fails for any reason, treat it as "not in any network".
    except Exception:
        #Return False so the caller does not accidentally trust a bad IP.
        return False


#Define beacon_state_path, the same small-helper pattern tripwire.py's
#own state_file_path() uses: a predictable, fixed location inside the
#evidence directory for this module's own across-scan memory.
def beacon_state_path(config):
    #Build the path inside the evidence directory.
    return os.path.join(config["evidence_dir"], "beacon_state.json")


#Define load_beacon_state/save_beacon_state - a flat dict mapping a
#remote IP (see check_beacon_pattern()'s own comment on why this is
#keyed by IP alone, not "ip:port") to a list of the recent Unix
#timestamps (floats, NOT the ISO strings findings.jsonl uses - these
#need to be subtracted from each other) at which this machine was seen
#talking to that destination.
def load_beacon_state(config):
    #Build the path to our state file.
    path = beacon_state_path(config)
    #Nothing has ever been tracked yet - start from an empty dict.
    if not os.path.exists(path):
        #Return a fresh, empty structure.
        return {}
    #Try to read and parse the state file.
    try:
        #Open and parse the JSON content.
        with open(path) as state_file:
            #Return the parsed state.
            return json.load(state_file)
    #If the file is corrupted for any reason, start fresh rather than crash.
    except Exception:
        #Return a fresh, empty structure.
        return {}


#Define save_beacon_state, writing the updated timestamp history back.
def save_beacon_state(config, state):
    #Open the state file for writing, creating it on the very first use.
    with open(beacon_state_path(config), "w") as state_file:
        #Write the dictionary back out as JSON.
        json.dump(state, state_file, indent=1)


#How many of the most recent check-in timestamps to keep per destination -
#enough to make a confident regularity judgment without the state file
#growing without bound for a long-running competition.
MAX_BEACON_SAMPLES = 20

#The fewest timestamps needed before this even attempts a judgment (3
#gaps between 4 points is the least that gives a meaningful spread to
#measure regularity against) - below this, say nothing rather than
#guess off of one or two data points.
MIN_BEACON_SAMPLES = 4

#How tightly clustered the gaps between check-ins need to be, as a
#coefficient of variation (standard deviation / mean) - 0.2 means every
#gap stays within roughly +/-20% of the average gap. Ordinary human or
#application traffic is far less uniform than this; a fixed-interval
#C2 beacon (even with typical "jitter" added on purpose to look less
#robotic) usually still lands inside it.
BEACON_CV_THRESHOLD = 0.2

#Ignore gaps shorter than this many seconds - a connection seen on
#back-to-back scans that are themselves only a few seconds apart (the
#user's own configured scan interval can be set quite low) would
#otherwise look artificially "regular" just because of how often we
#happen to be looking, not because the destination itself is being
#contacted on a timer.
MIN_BEACON_INTERVAL_SECONDS = 2.0


#Define check_beacon_pattern, called once per untrusted ESTABLISHED
#connection seen this scan. Records this sighting, then - once there is
#enough history for this exact destination - judges whether the gaps
#between sightings have been suspiciously regular, and reports a finding
#if so. Tracked by destination IP ALONE - not "ip:port", and not by
#process/PID either, the same reasoning extended one step further: a
#short-lived or respawning process (exactly what a C2 implant often is)
#can still be caught checking in to the same place even if its own PID
#keeps changing between scans - and just as easily, a C2 handler that
#rotates which REMOTE port it listens on for each check-in (a known,
#simple evasion specifically aimed at defeating "same ip:port seen
#repeatedly" tracking) would otherwise reset this heuristic's sample
#count back to 1 on every single connection, so MIN_BEACON_SAMPLES would
#never be reached and the beacon would never be caught at all - which is
#exactly the real gap a live retest against a port-rotating C2 surfaced.
#The destination IP is the one thing that cannot change without the
#implant also losing its handler, so that is what gets tracked.
def check_beacon_pattern(config, log, state, remote_ip, remote_port, process_name, process_exe, pid):
    #Build this destination's own tracking key - IP only (see above).
    key = remote_ip
    #Record this sighting, keeping only the most recent samples. Also
    #remember the most recent port this destination was reached on, and
    #the full set of distinct ports seen, purely for the finding message
    #below - neither one affects the regularity judgment itself.
    samples = state.get(key, [])
    samples.append(time.time())
    state[key] = samples[-MAX_BEACON_SAMPLES:]
    ports_key = f"{key}:ports"
    seen_ports = set(state.get(ports_key, []))
    seen_ports.add(remote_port)
    state[ports_key] = sorted(seen_ports)[-MAX_BEACON_SAMPLES:]
    #Not enough history yet to say anything meaningful.
    if len(state[key]) < MIN_BEACON_SAMPLES:
        #Nothing to report this time.
        return
    #Work out the gap, in seconds, between each consecutive pair of
    #sightings.
    gaps = [later - earlier for earlier, later in zip(state[key], state[key][1:])]
    #If any gap is implausibly short (see MIN_BEACON_INTERVAL_SECONDS's
    #own comment above), this is almost certainly just scan cadence
    #showing through, not a real beacon pattern - say nothing.
    if not gaps or min(gaps) < MIN_BEACON_INTERVAL_SECONDS:
        #Nothing to report this time.
        return
    #Work out how regular those gaps actually are.
    mean_gap = statistics.mean(gaps)
    #A zero or negative mean should not be possible given the check just
    #above, but guard against a division by zero regardless.
    if mean_gap <= 0:
        #Nothing sensible to compute - stop here.
        return
    #Population standard deviation (not sample) is fine here - this is a
    #descriptive measure of THIS exact history, not an estimate of some
    #larger population.
    coefficient_of_variation = statistics.pstdev(gaps) / mean_gap
    #A low coefficient of variation means the gaps are all close to the
    #same length - the hallmark of a timer-driven check-in.
    if coefficient_of_variation <= BEACON_CV_THRESHOLD:
        #Build the same kind of safe review-or-block suggestion the
        #ordinary "est:" finding above already uses.
        fix = suggest_network_fix(pid, remote_ip) if pid else None
        #Mention it plainly if this destination has been reached on more
        #than one remote port across these samples - that is itself worth
        #a human knowing (a C2 handler rotating its port specifically to
        #dodge "same ip:port" tracking), not just an internal detail of
        #why this finding is keyed the way it is.
        seen_ports_sorted = sorted(seen_ports)
        if len(seen_ports_sorted) > 1:
            port_note = f"on {len(seen_ports_sorted)} different ports ({', '.join(str(p) for p in seen_ports_sorted)}) - port-hopping, likely intentional"
        else:
            port_note = f"on port {remote_port} each time"
        #Report it as its own, distinctly-keyed high severity finding -
        #separate from the plain "est:" one, so both can exist side by
        #side without one suppressing the other.
        was_new = log.add(
            "network", "high", f"beacon:{key}",
            f"{process_name} (PID {pid}) -> {remote_ip} checks in roughly every "
            f"{mean_gap:.0f}s with very regular timing (possible C2 beacon), {port_note}",
            suggested_fix=fix,
        )
        #On a brand new beacon finding, also capture full forensic detail
        #on whichever process is making the connection right now.
        if was_new and pid:
            #Wrap in a try block since the process may have exited.
            try:
                #Save a full snapshot of the process and its binary.
                capture_process(config, psutil.Process(pid), f"possible C2 beacon to {remote_ip}:{remote_port}")
            #If the process is already gone, there is nothing to capture.
            except Exception:
                #Deliberately do nothing and continue.
                pass


#Define check, the function modules/__init__.py registers for this
#module's LIVE_MODULES entry.
def check(config, log):
    #Combine the user's own networks and VPN networks into one list of
    #addresses we consider "ours" and therefore not worth flagging.
    internal_networks = config["networks"] + config["vpn_networks"]
    #Load this module's own across-scan beacon-timing memory once, up
    #front, so every connection below shares the same in-memory copy
    #rather than re-reading the file over and over in the loop.
    beacon_state = load_beacon_state(config)
    #Try to read every live connection; this needs elevated privileges on
    #most systems to see connections owned by other users.
    try:
        #Ask psutil for every current TCP/UDP connection on the machine.
        connections = psutil.net_connections(kind="inet")
    #If we are not allowed to see the full connection list, say so once
    #and stop, rather than silently reporting an incomplete picture.
    except psutil.AccessDenied:
        #Log this as an informational note rather than a real finding.
        log.add("network", "info", "denied", "Cannot read connections; run as root/Administrator")
        #Return early since there is nothing else this check can do.
        return

    #Loop over every connection psutil found.
    for connection in connections:
        #Default the owning process name and path in case we cannot read them.
        process_name, process_exe = "?", ""
        #Only try to look up the process if a process ID was reported.
        if connection.pid:
            #Wrap the lookup since the process can exit at any moment.
            try:
                #Get the psutil process object for this connection's PID.
                owning_process = psutil.Process(connection.pid)
                #Read its name and executable path.
                process_name, process_exe = owning_process.name(), owning_process.exe()
            #If the process has already exited, just keep the defaults.
            except Exception:
                #Deliberately do nothing and keep the "?" placeholders.
                pass

        #Handle connections that are actively listening for new traffic.
        if connection.status == "LISTEN":
            #Read the local port this connection is listening on.
            port = connection.laddr.port
            #Check whether this port is on the always-suspicious list.
            if port in config["watch_ports"]:
                #Report this at high severity since these ports are
                #classic reverse-shell or backdoor listener choices.
                log.add("network", "high", f"listen:{port}", f"Suspicious port {port} listening ({process_name}, PID {connection.pid}) {process_exe}")
            #Otherwise, check whether this port was not in the baseline
            #list of ports that are expected to be open on a clean box.
            elif port not in config["expected_ports"]:
                #Report this at medium severity as a newly opened port.
                log.add("network", "medium", f"listen:{port}", f"NEW listening port {port} ({process_name}, PID {connection.pid}) {process_exe}")

        #Handle connections that are fully established (two-way traffic).
        elif connection.status == "ESTABLISHED" and connection.raddr:
            #Read the remote IP and port this machine is talking to.
            remote_ip, remote_port = connection.raddr.ip, connection.raddr.port
            #Skip loopback traffic, since it never leaves the machine.
            if remote_ip.startswith("127.") or remote_ip == "::1":
                #Move on to the next connection.
                continue
            #Work out whether this destination is one the user has marked
            #as trusted/internal (their own defended subnet, a VPN range,
            #or an explicit trusted IP - which very often INCLUDES the
            #auto-discovered default gateway, since the wizard offers that
            #as a sensible starting point for "Trusted external IPs").
            is_trusted_destination = ip_in_any_network(remote_ip, internal_networks) or remote_ip in config["trusted_ips"]
            #Always run the beacon-timing heuristic, trusted destination
            #or not - this is deliberate, not an oversight. A "defended
            #subnet" or "trusted IP" is trusted to NOT be malicious
            #traffic, not proven to be safe, and on a flat single-subnet
            #lab/competition box the C2 handler itself (or even the
            #default gateway, which the wizard pre-fills as a trusted IP)
            #can easily sit on that exact same subnet. Regular, timer-like
            #check-ins to ANY destination are themselves the specific,
            #hard-to-fake signal this heuristic looks for, so silently
            #skipping it just because the destination is "trusted" would
            #blind this exact scenario - a real beacon pivoting through a
            #trusted-by-default address. The plain, less specific "this
            #destination looks unusual" listing just below still skips a
            #trusted destination, to avoid flooding the Dashboard with
            #ordinary, harmless internal traffic.
            check_beacon_pattern(config, log, beacon_state, remote_ip, remote_port, process_name, process_exe, connection.pid)
            #Skip the plain "unusual destination" listing for anything
            #trusted/internal - this is the noisy, low-specificity signal,
            #not the beacon-timing one above, so it stays scoped to
            #destinations the user has NOT already said are expected.
            if is_trusted_destination:
                #Move on to the next connection.
                continue
            #Decide severity: high if either side of the connection uses a
            #known-bad port, medium otherwise since it is still unusual.
            severity = "high" if (remote_port in config["watch_ports"] or connection.laddr.port in config["watch_ports"]) else "medium"
            #Report the connection with both sides' addresses and ports,
            #along with a safe review-or-block suggestion for the human.
            fix = suggest_network_fix(connection.pid, remote_ip) if connection.pid else None
            was_new = log.add("network", severity, f"est:{remote_ip}:{remote_port}:{connection.pid}", f"{process_name} (PID {connection.pid}) -> {remote_ip}:{remote_port}  {process_exe}", suggested_fix=fix)
            #If this is a brand new high severity finding, also capture
            #full forensic detail on the process making the connection.
            if was_new and severity == "high" and connection.pid:
                #Wrap in a try block since the process may have exited.
                try:
                    #Save a full snapshot of the process and its binary.
                    capture_process(config, psutil.Process(connection.pid), f"connection to {remote_ip}:{remote_port}")
                #If the process is already gone, there is nothing to capture.
                except Exception:
                    #Deliberately do nothing and continue the loop.
                    pass

    #Persist whatever the beacon-timing state looks like after this pass,
    #so the next scan (whenever it runs - ambient or manual) has this
    #one's sightings to compare against.
    save_beacon_state(config, beacon_state)
