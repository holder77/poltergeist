#DESCRIPTION: This file is the "main page" - a small web page, built with
#             only Python's standard library (no Flask, so requirements.txt
#             stays at just psutil), that shows the most recent findings
#             and auto-refreshes every few seconds. It is bound to
#             127.0.0.1 ONLY, never 0.0.0.0, so it is never reachable from
#             anywhere else on the network, including during a
#             competition where you do not want to open a new attack
#             surface just to watch your own alerts.

#import http.server, the standard library's own small web server, so we
#never need to add a web framework as a dependency just for this.
from http.server import BaseHTTPRequestHandler, HTTPServer

#import os so paths can be built for the handler; findings.jsonl itself
#is now read and parsed through evidence.load_findings_file() instead
#of a local copy (see the import below), so json is no longer needed
#directly in this file.
import os

#import threading so the Dashboard can run in the background instead of
#blocking the whole program - the menu/wizard need to keep running in the
#same terminal while the Dashboard quietly serves pages behind them.
import threading

#import html so any text pulled from a finding (a file path, a command) is
#safely escaped before being dropped into the page, even though these
#values come from our own tool rather than from an attacker's input.
import html

#import load_config so every single page request re-reads the config fresh
#from disk instead of trusting a copy captured back when the server first
#started - if the user re-runs the setup wizard mid-session (which can
#change evidence_dir), the very next page load should reflect that, not
#keep quietly showing findings from wherever evidence_dir used to point.
from .config import load_config

#import format_ts_for_display so every row on this live page shows its
#timestamp in whoever's actually LOOKING at this page's own local
#timezone, not the raw UTC it's stored as - see evidence.py's own top
#comment on this function for why (a finding stamped a second ago can
#otherwise look like it's "from 10pm" to someone sitting in a timezone
#several hours behind UTC, even though nothing is actually stale).
#
#Also import load_findings_file and latest_state - this page used to
#print EVERY line ever written to findings.jsonl, newest first, with no
#collapsing at all: an ongoing condition got a brand new line every
#single scan cycle (see latest_state's own comment in evidence.py for
#why), and a condition that was fixed by hand (a malicious process
#killed, a dropped file deleted) kept its last, already-stale alert
#sitting on this page forever, since nothing ever told this page the
#condition had gone away. latest_state() collapses the history down to
#"the current state of each distinct thing being tracked" - combined
#with the live-check modules (processes.py, persistence.py) now calling
#evidence.resolve_stale() to explicitly log a "resolved" record the
#moment something they flagged stops being true, this page now actually
#reflects what's true right now, the same way the GUI's own Dashboard
#tab (gui/live_dashboard.py) already did before this fix.
from .evidence import format_ts_for_display, load_findings_file, latest_state


#Define build_page, which reads the current findings and renders them as
#one simple, readable HTML page. Each running install now ever points at
#ONE target (see config.py's "target" key) - a remote target's findings
#are already synced back into THIS machine's own findings.jsonl by
#modules/remote.py's pull_evidence() the moment any action runs against
#it, so there is exactly one findings file to ever read here.
def build_page(config):
    #Load every finding ever logged for the currently configured target.
    findings_path = os.path.join(config["evidence_dir"], "findings.jsonl")
    all_findings = load_findings_file(findings_path)
    #Collapse that full history down to just the current state of each
    #distinct thing being tracked - see this file's own import comment,
    #and latest_state's own comment in evidence.py, for why this page
    #used to show the same ongoing condition over and over, and kept
    #showing an already-fixed one forever.
    all_findings = latest_state(all_findings)
    #Cap the page at the 200 most recent findings so a long competition
    #never makes a single page load slow.
    all_findings = all_findings[:200]
    #Start building the HTML rows, one per finding.
    rows = []
    #Loop over every finding we are going to display.
    for finding in all_findings:
        #Pick a CSS class based on severity so high severity rows stand out.
        css_class = {"high": "high", "medium": "medium"}.get(finding.get("severity"), "info")
        #Escape every piece of text before it goes into the page -
        #converting the raw stored UTC timestamp to THIS machine's own
        #local time first (see format_ts_for_display's own comment).
        ts = html.escape(format_ts_for_display(finding.get("ts", "")))
        module = html.escape(finding.get("module", ""))
        severity = html.escape(finding.get("severity", ""))
        message = html.escape(finding.get("message", ""))
        fix = html.escape(finding.get("fix") or "")
        #Build one table row for this finding, with an optional fix line.
        fix_html = f'<div class="fix">suggested: {fix}</div>' if fix else ""
        rows.append(f'<tr class="{css_class}"><td>{ts}</td><td>{module}</td><td>{severity}</td><td>{message}{fix_html}</td></tr>')
    #Join every row into one block of HTML table body content.
    rows_html = "\n".join(rows) if rows else '<tr><td colspan="4">No findings yet.</td></tr>'
    #Work out the target's friendly label for the page's own intro text.
    target_label = (config.get("target") or {}).get("label") or "this machine"
    #Return the complete page as one HTML string, including a meta-refresh
    #tag so the browser reloads itself automatically every 5 seconds.
    return f"""<!doctype html>
<html><head><meta charset="utf-8"><meta http-equiv="refresh" content="5">
<title>Poltergeist Dashboard</title>
<style>
body {{ background:#0b0f14; color:#d8e0e8; font-family: monospace; margin: 2rem; }}
h1 {{ color:#b26bf5; }}
table {{ width:100%; border-collapse: collapse; }}
td {{ padding: 6px 10px; border-bottom: 1px solid #222; vertical-align: top; }}
tr.high td {{ color:#ff6666; }}
tr.medium td {{ color:#ffcc66; }}
tr.info td {{ color:#66ccff; }}
.fix {{ color:#888; font-size: 0.85em; margin-top: 2px; }}
</style></head>
<body>
<h1>Poltergeist: {html.escape(target_label)}</h1>
<p>Auto-refreshes every 5 seconds. This page is only reachable from this machine (127.0.0.1).</p>
<table><tr><th>Time</th><th>Module</th><th>Severity</th><th>Message</th></tr>
{rows_html}
</table>
</body></html>"""


#Define the handler class once, at import time rather than freshly inside
#every run()/start_background() call. It takes no config at __init__ time
#at all - do_GET below loads the config fresh from disk on every single
#request, through load_config(), the exact same "never trust a stale copy"
#approach build_page() already uses for findings.jsonl itself. This is
#what lets the Dashboard survive the user re-running the setup wizard
#(which can change evidence_dir) in the SAME session the Dashboard is
#already running in, without needing to be restarted.
class Handler(BaseHTTPRequestHandler):
    #Define do_GET, called automatically for every browser request.
    def do_GET(self):
        #Send a normal 200 OK response status.
        self.send_response(200)
        #Tell the browser this is an HTML page.
        self.send_header("Content-Type", "text/html; charset=utf-8")
        #Finish the headers section of the response.
        self.end_headers()
        #Load the current config fresh, build the current page fresh from
        #it, and send that as the response body.
        self.wfile.write(build_page(load_config()).encode("utf-8"))

    #Override log_message to silence the default per-request console
    #spam, since findings already print their own lines to the terminal.
    def log_message(self, format, *args):
        #Deliberately do nothing, suppressing the default access log.
        pass


#Define build_server, a tiny shared helper so run() and start_background()
#both build the exact same kind of server the exact same way, binding
#ONLY to 127.0.0.1 so nothing outside this machine can ever reach it, even
#accidentally. Returns None instead of raising if the port is already
#taken, so both callers can print one clear message instead of a traceback.
def build_server(port):
    #Try to actually bind the port.
    try:
        #Build and return the server, bound to localhost only.
        return HTTPServer(("127.0.0.1", port), Handler)
    #A port already in use (very likely cause: the Dashboard auto-started
    #already and this is a second attempt to start it) raises OSError.
    except OSError:
        #Return None so the caller can explain what happened.
        return None


#Define run, the function --dashboard and (as a manual fallback) the menu
#use when the Dashboard is not already running in the background. It
#blocks until Ctrl+C, the same way --monitor does.
def run(port=8765):
    #Build the server.
    server = build_server(port)
    #If the port was already taken, say so plainly instead of crashing.
    if server is None:
        #Explain the likely cause - the background auto-start probably beat
        #us to this port - and stop here.
        print(f"  Could not bind port {port} - something is already using it (likely the Dashboard that auto-starts with the menu). Open http://127.0.0.1:{port} directly instead.")
        #Return early since there is no server to run.
        return
    #Tell the user exactly where to open it in a browser.
    print(f"  Dashboard running at http://127.0.0.1:{port}  (local machine only). Ctrl+C to stop.")
    #Wrap in a try block so Ctrl+C exits cleanly.
    try:
        #Serve requests forever until interrupted.
        server.serve_forever()
    #Catch the keyboard interrupt raised by Ctrl+C.
    except KeyboardInterrupt:
        #Print a clean confirmation that the dashboard has stopped.
        print("\n  Dashboard stopped.")


#Define start_background, the function the main menu calls automatically
#the moment it launches, so the live findings page is already up before
#the user even finishes the setup wizard - the Dashboard is never blocked
#waiting for a config, since the Handler loads one fresh on every request.
#Runs the server on a background thread so the menu keeps responding to
#keyboard input in the same terminal at the same time.
def start_background(port=8765):
    #Build the server the same way run() does.
    server = build_server(port)
    #If the port is already taken (e.g. this is called a second time),
    #say so plainly and hand back None rather than silently doing nothing.
    if server is None:
        #Explain the likely cause and stop here.
        print(f"  Dashboard could not auto-start - port {port} is already in use by something else.")
        #Return None so the caller knows the background server is not up.
        return None
    #Build a thread that runs the server's forever-loop. daemon=True means
    #this thread will never keep the whole program alive by itself - the
    #moment the main program exits (Quit), this thread is torn down with
    #it instead of leaving an orphaned server running.
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    #Actually start the background thread running.
    server_thread.start()
    #Tell the user exactly where to open it, right away.
    print(f"  Dashboard live at http://127.0.0.1:{port}  (this machine only, auto-refreshes every 5s)")
    #Hand back the server object in case the caller ever needs it (for
    #example, to notice later that it is already running).
    return server
