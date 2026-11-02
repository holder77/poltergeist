#DESCRIPTION: This file is "the Scribe". Judges in a blue team competition
#             usually want a written incident report, and nobody wants to
#             write one by hand while also defending a box. This file
#             reads every finding already logged in findings.jsonl (every
#             finding was already timestamped and recorded the moment it
#             happened) and turns it into one clean, readable Markdown
#             file, grouped by severity, with every suggested command
#             included so the report also doubles as a remediation log.

#import os so we can build the output file's path.
import os

#import json so we can read findings.jsonl back into memory.
import json

#import datetime so the report file itself gets a clear timestamp in its
#name and in its header.
import datetime

#import ntp_sync so the report's own "Generated:" timestamp is checked
#against a real NTP time source rather than just trusting this
#machine's own system clock - the direct fix for "it will help a lot
#when we have to make reports later when all the timestamps match."
#See ntp_sync.py's own top comment for the full reasoning (including
#why this never blocks/slows report generation even when NTP is
#unreachable, which is common on a locked-down competition range, and
#why that file lives at the top level of the package next to this one
#rather than inside modules/).
from . import ntp_sync


#Define _format_local, a small private helper that takes a timezone-
#AWARE UTC datetime (what ntp_sync.corrected_utcnow() and
#_parse_stored_ts below both hand back) and renders it in THIS
#machine's own current local timezone - the one running report.py
#itself, which is always the analyst's own machine, never a remote
#target (see this file's own module docstring and app.py's own comment
#on why report.generate() is always local/in-process). Converting here,
#at display time, rather than storing local time in the first place, is
#what makes "sync to me when it generates" work automatically for
#WHOEVER runs this, wherever they are, with zero hardcoded timezone or
#location anywhere in this project: Python's own astimezone() with no
#argument already asks the operating system what timezone it's
#currently set to (DST included), the exact same way the clock in the
#corner of that machine's own screen already shows - if that machine's
#OS is set to, say, America/Denver, this automatically renders in
#Denver's own current time, with no "Colorado" written anywhere in this
#codebase.
def _format_local(utc_dt):
    #Convert to this machine's own local timezone, DST-aware.
    local_dt = utc_dt.astimezone()
    #Work out the UTC offset as a readable "+HH:MM"/"-HH:MM" string -
    #utcoffset() returns a timedelta, which can be negative (west of
    #UTC, which Colorado and most of the US always are).
    offset = local_dt.utcoffset()
    offset_total_minutes = int(offset.total_seconds() // 60)
    sign = "+" if offset_total_minutes >= 0 else "-"
    offset_total_minutes = abs(offset_total_minutes)
    offset_str = f"{sign}{offset_total_minutes // 60:02d}:{offset_total_minutes % 60:02d}"
    #%Z asks the OS for this timezone's own current abbreviation (e.g.
    #"MST" or "MDT", correctly picking whichever one actually applies
    #right now) - fall back to the plain numeric offset if the platform
    #ever hands back an empty abbreviation (some minimal/embedded
    #Python builds do).
    tz_abbrev = local_dt.strftime("%Z") or offset_str
    return local_dt.strftime("%Y-%m-%d %H:%M:%S") + f" {tz_abbrev} (UTC{offset_str})"


#Define _display_timestamp, which renders one FINDING's own stored "ts"
#value for the report - converting it into this machine's own local
#time, exactly like _format_local above, for any finding recorded under
#this round's new explicit-UTC format (ends in "Z" - see evidence.py's
#own now()). A finding recorded before this fix existed has no
#timezone marker at all and is shown unchanged, clearly labeled as such,
#rather than silently guessed at - there is no way to know after the
#fact which timezone an old, naive timestamp was actually written in.
def _display_timestamp(ts_string):
    if not ts_string.endswith("Z"):
        #Pre-existing, naive timestamp from before this fix - nothing
        #to convert; say so rather than pretend it's as trustworthy as
        #a converted one.
        return f"{ts_string} (pre-sync, timezone unknown)"
    try:
        #Parse the stored "...Z" string back into a timezone-aware UTC
        #datetime, then hand it to the same local-time formatter the
        #report's own header line uses, so every timestamp in the
        #finished report - the header and every single finding - is
        #shown in the exact same timezone, which is the whole point.
        utc_dt = datetime.datetime.strptime(ts_string, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)
        return _format_local(utc_dt)
    #A genuinely malformed timestamp should never stop the whole report
    #from being written - fall back to showing the raw stored text.
    except ValueError:
        return ts_string


#Define load_findings_file, the same small shared-shape helper dashboard.py
#uses, kept as its own local copy here (not imported from dashboard.py) so
#this file stays self-contained and never depends on the web server module
#just to read a JSONL file.
def load_findings_file(path):
    #If the file does not exist yet, there is nothing to load.
    if not os.path.exists(path):
        #Return an empty list rather than crash on a missing file.
        return []
    #Open the file and parse every non-blank line as one JSON finding.
    with open(path) as findings_file:
        #Return every parsed finding found in the file.
        return [json.loads(line) for line in findings_file if line.strip()]


#Define generate, the one function the "Scribe" menu option calls. Each
#running install now ever points at ONE target (see config.py's "target"
#key) - a remote target's findings are already synced back into THIS
#machine's own findings.jsonl by modules/remote.py's pull_evidence() the
#moment any action runs against it, so there is exactly one findings file
#to ever read here, local or remote target alike.
def generate(config):
    #Load every finding logged so far.
    local_path = os.path.join(config["evidence_dir"], "findings.jsonl")
    findings = load_findings_file(local_path)
    #If nothing has ever been logged, there is nothing to write a report
    #about, so say so plainly instead of producing an empty file.
    if not findings:
        #Tell the user exactly why no report was generated.
        print("  No findings logged yet, nothing to report.")
        #Return None so the caller knows no file was written.
        return None
    #Group every finding by its severity, so the report can list the most
    #important things first regardless of when they happened or which
    #machine they came from.
    by_severity = {"high": [], "medium": [], "info": []}
    #Loop over every finding we loaded.
    for finding in findings:
        #File it into the matching severity bucket, defaulting to "info"
        #for any severity value this report does not explicitly expect.
        by_severity.setdefault(finding.get("severity", "info"), []).append(finding)
    #Record exactly when this report was generated - NTP-corrected (see
    #ntp_sync.py), not just whatever this machine's own system clock
    #happens to currently read. corrected_utcnow() always returns a
    #usable answer (it falls back to this machine's own clock, offset
    #0.0, if NTP could not be reached at all), so this never blocks or
    #fails report generation even on a network that blocks outbound NTP.
    generated_at_utc = ntp_sync.corrected_utcnow()
    #Build the report's file name from the UTC timestamp (not the local-
    #time display version below) so two reports generated back-to-back
    #from two different machines in two different timezones still sort
    #and never collide the same way they always have.
    #Swap the "+00:00" UTC marker for "Z" BEFORE turning colons into
    #dashes - doing it in the other order (as an earlier version of this
    #line did) turns "+00:00" into "+00-00" first, so the "+00:00"->"Z"
    #replacement never matches anything and a stray "+00-00" is left
    #sitting in the filename instead of the clean trailing "Z".
    safe_timestamp = generated_at_utc.isoformat(timespec="seconds").replace("+00:00", "Z").replace(":", "-")
    file_name = f"incident_report_{safe_timestamp}.md"
    #Build the full output path inside the evidence directory.
    output_path = os.path.join(config["evidence_dir"], file_name)
    #Open the output file for writing.
    with open(output_path, "w") as report_file:
        #Write the report's title and generation timestamp, shown in
        #THIS machine's own current local timezone (see _format_local's
        #own comment on why that needs no hardcoded location anywhere
        #in this project to still show up correctly for whoever's
        #actually reading the finished report).
        report_file.write(f"# Poltergeist Incident Report\n\nGenerated: {_format_local(generated_at_utc)}\n\n")
        #Say plainly whether this timestamp (and every finding's own
        #timestamp below) was actually verified against a real NTP time
        #source, or is only as good as this machine's own system clock -
        #a judge or an analyst reading the report later should never
        #have to wonder which one they're looking at, and a clock that
        #turns out to have been drifting (or deliberately skewed - see
        #ntp_sync.py's own top comment) is itself worth knowing about.
        report_file.write(f"**Clock sync:** {ntp_sync.describe_sync_status()}\n\n")
        #Name exactly which machine this report covers, so a judge reading
        #it does not have to guess.
        target_label = (config.get("target") or {}).get("label") or "this machine"
        report_file.write(f"**Machine covered:** {target_label}\n\n")
        #Write a one-line summary of how many findings are in each bucket.
        report_file.write(f"**Summary:** {len(by_severity['high'])} high, {len(by_severity['medium'])} medium, {len(by_severity['info'])} informational findings.\n\n")
        #Loop over the three severities in a fixed, most-important-first order.
        for severity in ("high", "medium", "info"):
            #Write a section header for this severity level.
            report_file.write(f"## {severity.upper()} severity\n\n")
            #If there were no findings at this severity, say so plainly.
            if not by_severity[severity]:
                #Write a one-line "none" note instead of an empty section.
                report_file.write("_None._\n\n")
                #Move on to the next severity level.
                continue
            #Loop over every finding at this severity level.
            for finding in by_severity[severity]:
                #Write the finding's timestamp, module, and message as one
                #bullet point - the timestamp converted to this same
                #machine's own local timezone (see _display_timestamp's
                #own comment), so every single line in the report, no
                #matter which machine originally logged it, reads in the
                #exact same timezone instead of a patchwork of whatever
                #each source machine's own clock happened to be set to.
                report_file.write(f"- **{_display_timestamp(finding['ts'])}** `{finding['module']}` — {finding['message']}\n")
                #If this finding had a suggested follow-up command, include
                #it indented under the bullet so the report also works as
                #a remediation checklist.
                if finding.get("fix"):
                    #Write the suggested fix as a sub-bullet.
                    report_file.write(f"  - *suggested:* `{finding['fix']}`\n")
            #Add a blank line after each severity section for readability.
            report_file.write("\n")
    #Tell the user exactly where the finished report was written.
    print(f"  Report written to {output_path}")
    #Hand back the path in case the caller wants to do something with it.
    return output_path
