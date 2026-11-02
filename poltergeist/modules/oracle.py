#DESCRIPTION: This module is "the Oracle". It answers "what versions of
#software are actually running here, and are any of them known-bad?" It
#connects to each locally listening port exactly the way a normal client
#would (no exploit code, no attack traffic) and reads whatever banner
#text the service itself offers up - which is the same thing a plain
#"nmap -sV" or even "telnet host port" would see. It then checks that
#banner text against a small, offline, hand-maintained hint file at
#poltergeist/data/cve_hints.json. This is a weakness-finding tool for
#YOUR OWN box, meant to run before the competition starts, not a tool for
#probing anyone else's machine.

#import socket so we can open a plain TCP connection and read whatever
#the service sends back, the same way any normal client would.
import socket

#import json so we can load the offline CVE hint file.
import json

#import os so we can build the path to the bundled hint file reliably.
import os

#import urllib.request/urllib.error for refresh_hints_from_osint() below -
#a single HTTPS GET of one well-known government feed, no new pip
#dependency needed (same "stdlib first" preference ntp_sync.py explains
#in its own top comment).
import urllib.request
import urllib.error

#import datetime so refresh_hints_from_osint() can stamp the hint file
#with a plain "when was this last refreshed" note.
import datetime

#Build the path to the bundled CVE hint data file, next to this package.
HINTS_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "cve_hints.json")


#Define load_hints, which reads the offline hint file into memory once.
def load_hints():
    #Try to open and parse the hint file.
    try:
        #Open the bundled JSON file.
        with open(HINTS_PATH) as hints_file:
            #Parse it and return just the list of entries, ignoring the
            #"_readme" key which is documentation, not data.
            return json.load(hints_file).get("entries", [])
    #If the file is missing or malformed, do not crash the whole scan.
    except Exception:
        #Return an empty list so the rest of the module still runs fine.
        return []


#Define grab_banner, which connects to one local port and reads whatever
#text the service volunteers, the same way a normal client connection
#would see it. This is read-only and sends no exploit payloads.
def grab_banner(port, timeout=2):
    #Try the connection and read, since many ports will refuse or hang.
    try:
        #Open a short-lived TCP connection to this machine's own port.
        with socket.create_connection(("127.0.0.1", port), timeout=timeout) as sock:
            #Give the socket a short read timeout too, since some services
            #wait for the client to speak first and never send a banner.
            sock.settimeout(timeout)
            #Try to read whatever bytes the service sends immediately.
            data = sock.recv(256)
            #Decode the bytes as text, replacing anything that is not
            #valid text instead of crashing on binary protocol data.
            return data.decode(errors="replace").strip()
    #If the connection or read fails for any reason, there is no banner.
    except Exception:
        #Return an empty string, treated as "no banner" by the caller.
        return ""


#Define match_hints, which checks one banner string against every loaded
#hint entry and returns the ones that matched.
def match_hints(banner, hints):
    #Start with an empty list of matches for this banner.
    matches = []
    #Loop over every hint entry we loaded from the offline file.
    for hint in hints:
        #Check whether this hint's telltale text appears in the banner.
        if hint["contains"].lower() in banner.lower():
            #Record the matching hint for this banner.
            matches.append(hint)
    #Hand back every hint that matched this one banner.
    return matches


#Define scan_banners, the half of the Oracle that checks live service
#banners (what's actually running right now) against the offline hints.
#Returns (ports_checked, banners_read, cve_matches) so scan() below can
#always print a clear "here is what actually happened" summary, even on
#a clean box where nothing gets logged at severity above info - a silent
#run otherwise looks indistinguishable from the button doing nothing.
def scan_banners(config, log, hints):
    #Import discovery here (not at the top) to avoid a circular import,
    #since discovery.py does not need anything from this module.
    from ..discovery import find_listening_ports
    #Get the current list of listening ports to check.
    listening_ports = find_listening_ports()
    #Track counts for the final summary line.
    banners_read = 0
    cve_matches = 0
    #Loop over every listening port found.
    for entry in listening_ports:
        #Pull the port number and owning process name out of the entry.
        port, process_name = entry["port"], entry["proc"]
        #Try to read a banner from this port.
        banner = grab_banner(port)
        #Only continue if we actually got some text back.
        if not banner:
            #Move on to the next port; a silent port is not itself bad.
            continue
        #Report the raw banner at informational severity, since knowing
        #exactly what is running is useful even with no CVE match.
        log.add("oracle", "info", f"banner:{port}", f"Port {port} ({process_name}) banner: {banner[:120]}", quiet_dupes=False)
        banners_read += 1
        #Check this banner against every loaded hint.
        for hint in match_hints(banner, hints):
            #Report each match at high severity with the hint's own note.
            log.add("oracle", "high", f"cve:{port}:{hint['contains']}", f"Port {port} ({process_name}) matches known-risk version hint: {hint['note']}", quiet_dupes=False)
            cve_matches += 1
    #Hand back the three counts the final summary line needs.
    return len(listening_ports), banners_read, cve_matches


#Define scan_packages, the other half of the Oracle: this checks every
#INSTALLED package's name+version against the same offline hints, which
#catches a known-bad version sitting on disk even before it is ever
#started as a running service. Returns (packages_checked, cve_matches),
#same reasoning as scan_banners() above.
def scan_packages(config, log, hints):
    #Import packages.py here, not at the top, so oracle.py stays usable
    #even if someone copies just this one file somewhere else.
    from . import packages as packages_module
    #Collect the raw {name: version} dictionary for this OS.
    raw_packages = packages_module.collect_windows() if packages_module.IS_WINDOWS else packages_module.collect_linux()
    #Track the match count for the final summary line.
    cve_matches = 0
    #Loop over every installed package found.
    for name, version in raw_packages.items():
        #Build one combined "name version" string to match hints against.
        package_text = f"{name} {version}"
        #Check this package's name+version against every loaded hint.
        for hint in match_hints(package_text, hints):
            #Report each match at high severity with the hint's own note.
            log.add("oracle", "high", f"pkg_cve:{name}:{hint['contains']}", f"Installed package {name} {version} matches known-risk version hint: {hint['note']}", quiet_dupes=False)
            cve_matches += 1
    #Hand back the two counts the final summary line needs.
    return len(raw_packages), cve_matches


#The CISA "Known Exploited Vulnerabilities" (KEV) catalog - a single,
#free, no-API-key-required JSON file the U.S. government publishes,
#listing every vulnerability CISA has CONFIRMED is being actively
#exploited in the wild right now. This is a well-chosen source for a
#tool like this one specifically because it is small, prioritized, and
#stable - not the entire NVD firehose of every CVE ever issued, just the
#ones most worth a blue team's limited attention before a competition.
KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

#How long to wait for the KEV feed before giving up - kept short, same
#reasoning as ntp_sync.py's own NTP_QUERY_TIMEOUT_SECONDS: this must
#never hang indefinitely just because outbound HTTPS to this address is
#blocked, whether by a competition range's firewall or the analyst's own.
KEV_FETCH_TIMEOUT_SECONDS = 10

#A short, honest tag written onto every hint entry refresh_hints_from_
#osint() adds, so a LATER refresh can tell "something a previous refresh
#added" apart from the 5 hand-typed STARTER entries (and anything else a
#person added by hand) - and safely replace only its own previous batch
#rather than piling up duplicates forever, one refresh at a time.
KEV_SOURCE_TAG = "cisa_kev"


#Define refresh_hints_from_osint, a PRE-COMPETITION-ONLY, explicitly
#opt-in action (never part of any automatic scan, and never registered
#in modules/__init__.py's LIVE_MODULES, same reasoning as scan() itself
#just below) that reaches out to the open internet exactly once, to pull
#a fresh batch of known-risky-software hints into the same offline file
#scan_banners()/scan_packages() above already read from. This is the
#direct, honest answer to "can OSINT feed into this tool at all?" - yes,
#but only here, only before a competition starts while real internet
#access still exists, and the result is still just a small OFFLINE file
#read during the competition itself, never a live lookup mid-event.
#
#Written with the EXACT same "never hang, never crash, never pretend a
#failure is a success" shape ntp_sync.py's own get_offset_seconds() uses
#for the same reason: a locked-down network refusing this request is the
#ordinary, expected case, not a bug to be alarmed about.
def refresh_hints_from_osint(timeout_seconds=KEV_FETCH_TIMEOUT_SECONDS):
    #Try the actual network fetch. Every single way this can go wrong
    #(DNS failure, connection refused, TLS error, timeout, a non-200
    #response) is caught here and reported as a plain, calm message -
    #never raised up to crash whatever menu/CLI path called this.
    try:
        #Send a plain, read-only HTTPS GET - a descriptive User-Agent
        #string is set because some servers reject requests that don't
        #identify themselves at all.
        request = urllib.request.Request(
            KEV_FEED_URL,
            headers={"User-Agent": "Poltergeist-blue-team-tool (pre-competition offline hint refresh)"},
        )
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            raw_bytes = response.read()
    except Exception as exc:
        #Could not reach the feed at all - say so plainly and change
        #nothing. This is the expected outcome on an air-gapped range,
        #not a sign anything is broken.
        return False, 0, (
            f"Could not reach the CISA KEV feed ({exc}). This is normal and expected on an "
            "air-gapped or locked-down network - nothing was changed. Try this again from a "
            "machine with real internet access, before the competition starts."
        )
    #Try to parse what came back as the KEV feed's own known JSON shape.
    try:
        feed = json.loads(raw_bytes)
        vulnerabilities = feed["vulnerabilities"]
    except Exception as exc:
        #Got bytes back, but they were not the feed we expected - the
        #feed's own format may have changed. Say so rather than silently
        #writing nothing or crashing.
        return False, 0, (
            f"The CISA KEV feed did not parse the way this code expects ({exc}) - its format may "
            "have changed. Nothing was changed."
        )
    #Build one fresh hint entry per DISTINCT vendor+product pair, not one
    #per individual CVE - the KEV catalog often lists several CVEs
    #against the exact same product, and one combined entry with every
    #matching CVE ID named in its note is far more readable than a dozen
    #near-identical entries that would all fire together on one banner
    #or package match anyway.
    new_entries_by_contains = {}
    for vuln in vulnerabilities:
        #Pull the three fields this needs; skip any entry missing one of
        #them rather than guessing at a blank value.
        vendor = str(vuln.get("vendorProject", "")).strip()
        product = str(vuln.get("product", "")).strip()
        cve_id = str(vuln.get("cveID", "")).strip()
        if not vendor or not product or not cve_id:
            continue
        #Build the combined "vendor product" text this entry will match
        #against, and use its lowercase form as the de-duplication key.
        contains_text = f"{vendor} {product}"
        dedupe_key = contains_text.lower()
        #First CVE seen for this vendor+product - start a new entry.
        if dedupe_key not in new_entries_by_contains:
            new_entries_by_contains[dedupe_key] = {
                "service": "any",
                "contains": contains_text,
                "note": "",
                "source": KEV_SOURCE_TAG,
                "_cve_ids": [],
            }
        #Either way, record this CVE ID against that entry.
        new_entries_by_contains[dedupe_key]["_cve_ids"].append(cve_id)
    #Now that every entry has its full list of CVE IDs, turn that list
    #into one honest, readable note - and remove the temporary "_cve_ids"
    #working field, which is not part of the normal hint entry shape
    #match_hints()/scan_banners()/scan_packages() above expect.
    for entry in new_entries_by_contains.values():
        cve_ids = entry.pop("_cve_ids")
        #Show up to 8 CVE IDs by name, then just a count of any more -
        #keeps the note readable even for a very widely-hit product.
        shown_ids = ", ".join(cve_ids[:8])
        extra_note = f", and {len(cve_ids) - 8} more" if len(cve_ids) > 8 else ""
        entry["note"] = (
            f"CISA's Known Exploited Vulnerabilities catalog lists {len(cve_ids)} actively-exploited "
            f"CVE(s) against this vendor/product: {shown_ids}{extra_note}. This is a LOOSE match on "
            "vendor+product NAME only (unlike the precise version-string hints above) - confirm the "
            "actual installed/running version against the specific CVE ID(s) before treating this as "
            "a confirmed hit."
        )
    new_entries = list(new_entries_by_contains.values())
    #Load whatever is already in the hint file right now, so this never
    #throws away the 5 hand-typed STARTER entries (or anything else a
    #person has added by hand) - only entries THIS function itself added
    #on some previous run (tagged source == KEV_SOURCE_TAG) are replaced.
    try:
        with open(HINTS_PATH) as hints_file:
            existing_file = json.load(hints_file)
    except Exception:
        #No usable existing file - start from an empty, still-honest shell
        #rather than failing outright; the fresh KEV entries are still
        #worth saving even if the original starter file was lost.
        existing_file = {"_readme": "This is a tiny STARTER file, not a live feed.", "entries": []}
    #Keep every entry that is NOT one of this function's own previous
    #additions, then add the freshly-fetched batch on top.
    kept_entries = [entry for entry in existing_file.get("entries", []) if entry.get("source") != KEV_SOURCE_TAG]
    existing_file["entries"] = kept_entries + new_entries
    #Stamp the file with a plain "when was this last refreshed" note, so
    #anyone opening cve_hints.json by hand can see how stale it might be.
    existing_file["_kev_last_refreshed"] = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    #Try to save the merged file back to disk.
    try:
        with open(HINTS_PATH, "w") as hints_file:
            json.dump(existing_file, hints_file, indent=2)
    except Exception as exc:
        #Fetched everything fine but could not write it - say so plainly
        #rather than claiming success.
        return False, 0, f"Fetched {len(new_entries)} hint(s) from CISA's KEV feed but could not save them to {HINTS_PATH} ({exc})."
    #Success - report exactly what happened, honestly, same spirit as
    #scan()'s own always-print-a-clear-outcome-line rule below.
    return True, len(new_entries), (
        f"Added/refreshed {len(new_entries)} OSINT-derived hint(s) from CISA's Known Exploited "
        f"Vulnerabilities catalog into {HINTS_PATH} (your other {len(kept_entries)} hand-kept "
        "hint(s) were left untouched). Remember: these are LOOSE vendor+product matches, not the "
        "precise version-string hints above - still confirm before treating a match as certain."
    )


#Define scan, the function cli.py calls to run a full Oracle pass. It is
#NOT registered in modules/__init__.py's automatic LIVE_MODULES, since
#version scanning is something you run once up front, not every 15
#seconds - call it explicitly from the "Oracle" menu option instead.
def scan(config, log):
    #Load the offline hint data once for this whole scan.
    hints = load_hints()
    #Warn plainly if the hint file could not be loaded or is empty, so the
    #user understands an empty result might just mean no data was loaded.
    if not hints:
        #Print a one-line note before continuing.
        print("  (no CVE hints loaded - see poltergeist/data/cve_hints.json)")
    #Check every live service banner against the hints.
    ports_checked, banners_read, banner_matches = scan_banners(config, log, hints)
    #Check every installed package's version against the hints too.
    packages_checked, package_matches = scan_packages(config, log, hints)
    #Always print a clear, one-line "here is what actually happened"
    #summary - unlike Scribe (which always has at least a "report written
    #to..." or "nothing to report" line), a clean box can make this scan
    #complete with NOTHING logged above informational severity, which
    #otherwise looks identical to the button having done nothing at all.
    total_matches = banner_matches + package_matches
    print(f"  Oracle scan complete: {ports_checked} open port(s) checked ({banners_read} gave a "
          f"readable banner), {packages_checked} installed package(s) checked, "
          f"{total_matches} known-risk version match(es) found.")
