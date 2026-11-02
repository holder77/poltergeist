#DESCRIPTION: This file lives at the top level of the package (next to
#             evidence.py and report.py, NOT inside modules/) on purpose -
#             it is plain infrastructure every finding/report timestamp
#             leans on, not a security CHECK in its own right, so it has
#             no business being registered anywhere in modules/__init__.py's
#             LIVE_MODULES list. Just as importantly, evidence.py needs to
#             import this file directly, and modules/__init__.py itself
#             already imports OTHER modules (persistence.py, for one) that
#             import evidence.py right back - putting this file inside the
#             modules/ package would make importing it also run modules/
#             __init__.py's own top-level imports first, which would walk
#             straight back into evidence.py before evidence.py had
#             finished its own definitions, a circular import. Living
#             beside evidence.py/report.py instead avoids that entirely.
#
#             This module answers one question: "is this machine's own
#             system clock actually correct, and if not, by how much?" -
#             the direct answer to the feedback that every timestamp
#             this tool records was just whatever datetime.now() said on
#             whichever machine happened to be running at the time, with
#             no indication of timezone and no way to tell whether that
#             clock was even right. A competition range box is very
#             often left on UTC/"Zulu" time by default, a laptop sitting
#             on a VM host that's drifted, or (worth remembering for a
#             BLUE TEAM tool specifically) a deliberately skewed clock is
#             itself a classic anti-forensics trick to confuse a log
#             timeline - so knowing the real offset is not just
#             cosmetic.
#
#             This module talks to a real NTP (Network Time Protocol)
#             server over the open internet to learn the true current
#             time, and hands back the OFFSET between that and this
#             machine's own clock - never changes the machine's actual
#             system clock itself (this tool never touches anything it
#             doesn't own, same rule as everywhere else in this project -
#             see evidence.py's own top comment). Every caller elsewhere
#             in this project (evidence.py's own now(), report.py's
#             report header) just adds that offset to a normal clock
#             read, rather than this module doing anything invasive.
#
#             Written with Python's own socket/struct - no new pip
#             dependency (an "ntplib" package exists, but this project
#             already prefers shelling out to or hand-rolling a small,
#             well-understood protocol over adding a dependency just to
#             save a few lines - see log_review.py's own wevtutil/
#             journalctl calls for the same reasoning) - and it is
#             written to NEVER slow down or break a scan: a competition
#             range very often blocks outbound NTP (UDP port 123)
#             entirely, same as it blocks most other outbound traffic,
#             so every failure here is caught, remembered, and silently
#             falls back to "no correction" rather than raising,
#             retrying forever, or hanging a scan.

#import socket/struct to build and send the actual NTP request packet
#by hand, and parse the 48-byte reply - this is the entire SNTP
#(Simple NTP, RFC 4330) client this module needs; there is no larger
#protocol to implement for "what time is it, really?"
import socket
import struct

#import time for both time.time() (this machine's own current clock
#reading, used to measure the round trip and to compute the final
#corrected "now") and as the thing being measured against.
import time

#import datetime so corrected_utcnow() below can hand back a real,
#timezone-AWARE datetime object (explicitly UTC) rather than a bare
#number of seconds - evidence.py and report.py both want an actual
#datetime to format, not arithmetic to redo themselves.
import datetime


#A short list of well-known, highly-available public NTP servers to try
#in order - if the first is blocked, slow, or simply not resolvable on
#this particular network (common on an isolated competition range),
#the next one is tried before giving up entirely. pool.ntp.org is the
#standard default; the other two are large, reliable operators kept as
#fallbacks specifically because a range's firewall rules sometimes allow
#one well-known provider's IP ranges through but not another's.
NTP_SERVERS = ["pool.ntp.org", "time.cloudflare.com", "time.google.com"]

#The standard NTP UDP port - fixed by the protocol itself, not configurable.
NTP_PORT = 123

#NTP timestamps are counted in seconds since 1900-01-01, while every
#other timestamp in this project (and Python's own time.time()) counts
#from 1970-01-01 - this is the fixed, well-known number of seconds
#between those two epochs, used to convert one to the other.
NTP_EPOCH_DELTA = 2208988800

#How long to wait for any ONE server to answer before giving up on it
#and trying the next - kept short and deliberately not retried within a
#single attempt, so a fully-blocked network (no answer from any server)
#fails fast rather than stalling a scan for many seconds.
NTP_QUERY_TIMEOUT_SECONDS = 2.0

#How long a successfully-measured offset (or a confirmed failure) stays
#cached before this module will bother asking the network again. Clock
#drift changes slowly - there is no value in querying NTP before every
#single finding a scan logs, only in knowing the offset is still roughly
#current. Five minutes keeps one scan's worth of findings all correctable
#by the same single measurement, without ever going stale for long.
CACHE_TTL_SECONDS = 300

#The one piece of module-level state this file keeps - the last
#successfully (or unsuccessfully) measured offset, when it was measured,
#and why it failed if it did. A plain dictionary rather than a class
#since there is only ever one of these per running process, exactly the
#same "one shared piece of state" pattern modules/tripwire.py's own
#watched-folder list uses.
_cache = {"offset_seconds": 0.0, "measured_at_monotonic": 0.0, "synced": False, "server": None, "error": None}


#Define _query_one_server, which sends exactly one minimal SNTP request
#to the given server and returns the measured offset in seconds
#(positive means the real time is AHEAD of this machine's own clock,
#i.e. this machine is running slow) - or raises an exception if
#anything at all goes wrong (DNS failure, no reply inside the timeout,
#a malformed/too-short reply). Every possible failure is deliberately
#left to raise here; the caller (get_offset_seconds below) is the one
#place that decides what "every server failed" should mean.
def _query_one_server(server, timeout_seconds):
    #Build the request packet: 48 bytes total, every byte zero except
    #the very first. That first byte packs three fields together - the
    #top two bits are the "leap indicator" (0 = no warning), the next
    #three bits are the NTP version number (we send 3, the most widely
    #supported version any real server still answers), and the bottom
    #three bits are the "mode" (3 = client request). 0x1B is exactly
    #those three fields combined: 00 011 011.
    request_packet = b"\x1b" + 47 * b"\0"
    #Open a plain UDP socket - NTP is UDP-based, no connection to hold
    #open, just one request and (hopefully) one reply.
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        #Never let one slow/unreachable server hang this whole function -
        #give up on it after timeout_seconds and let the caller move on.
        client_socket.settimeout(timeout_seconds)
        #Record our OWN clock right before sending, so we can later
        #estimate what our own clock read at roughly the moment the
        #server's reply reflects.
        request_sent_at = time.time()
        client_socket.sendto(request_packet, (server, NTP_PORT))
        response_packet, _server_address = client_socket.recvfrom(48)
        #And record our own clock again right after the reply arrives.
        response_received_at = time.time()
    finally:
        #Always close the socket, whether the request succeeded or not.
        client_socket.close()
    #A genuine NTP/SNTP reply is always exactly 48 bytes - anything
    #shorter is not a real reply (a stray UDP packet from something
    #else entirely, for instance), and should never be trusted as a time.
    if len(response_packet) < 48:
        raise ValueError(f"short/invalid NTP reply from {server} ({len(response_packet)} bytes)")
    #Bytes 40-43 of the reply hold the server's own "transmit timestamp" -
    #the whole-seconds count, since the NTP epoch, of the moment the
    #server sent this very reply - as a big-endian unsigned 32-bit
    #integer ("!I" in struct's format language). The next 4 bytes hold a
    #fractional-second count this module does not need for second-level
    #drift detection, so it's left unread.
    transmit_seconds_since_ntp_epoch = struct.unpack("!I", response_packet[40:44])[0]
    #Convert the server's NTP-epoch seconds count into the same 1970-
    #epoch "Unix time" every other timestamp in this project already uses.
    server_time_unix = transmit_seconds_since_ntp_epoch - NTP_EPOCH_DELTA
    #The true round-trip delay is unknown without reading more of the
    #packet's own timing fields, which this simple client deliberately
    #skips - this tool only needs to catch a clock that's badly wrong
    #(minutes, hours, or deliberately skewed), not shave milliseconds off
    #a stratum-1-grade measurement. The midpoint between when we sent our
    #request and when we got the reply is a perfectly good stand-in for
    #"what our own clock read at roughly the moment this reply reflects."
    local_time_at_reply_unix = (request_sent_at + response_received_at) / 2
    #The offset is simply how far the server's reported time is from
    #what our own clock read at that same moment.
    return server_time_unix - local_time_at_reply_unix


#Define get_offset_seconds, the one function every other piece of this
#module (and, through it, evidence.py/report.py) actually calls. Returns
#a (offset_seconds, synced, error) triple:
#  - offset_seconds: add this to time.time() to get a corrected reading.
#    0.0 if NTP has never been successfully reached.
#  - synced: True only if an NTP server has answered within the current
#    cache window - False means "running on this machine's own system
#    clock, uncorrected," which report.py uses to say so plainly rather
#    than silently presenting an uncorrected time as if it were verified.
#  - error: a short, human-readable reason the last attempt failed, or
#    None if the most recent attempt succeeded (or none has been made).
#Cached for CACHE_TTL_SECONDS so a scan logging many findings in a row
#only ever touches the network once, and a fully-blocked network (very
#common on an isolated competition range, which often blocks everything
#outbound except what the exercise explicitly needs) is remembered as
#"not reachable" rather than retried on every single finding, which
#would otherwise mean every finding during the whole scan pays that same
#multi-second timeout penalty one after another.
def get_offset_seconds(force_refresh=False):
    now_monotonic = time.time()
    if not force_refresh and (now_monotonic - _cache["measured_at_monotonic"]) < CACHE_TTL_SECONDS:
        #The cached measurement is still fresh enough to trust - no need
        #to touch the network again.
        return _cache["offset_seconds"], _cache["synced"], _cache["error"]
    #Try each known server in turn; the first one to actually answer
    #wins, and nothing further is tried once we have a real measurement.
    last_error = None
    for server in NTP_SERVERS:
        try:
            offset_seconds = _query_one_server(server, NTP_QUERY_TIMEOUT_SECONDS)
            #A real reply came back - cache it and hand it straight back.
            _cache.update(offset_seconds=offset_seconds, measured_at_monotonic=now_monotonic,
                          synced=True, server=server, error=None)
            return offset_seconds, True, None
        #Catch absolutely anything that can go wrong talking to ONE
        #server (DNS failure, connection refused, timeout, a malformed
        #reply) and simply move on to try the next one - a single bad
        #server should never be treated as "NTP is unreachable."
        except Exception as exc:
            last_error = f"{server}: {exc}"
            continue
    #Every server in the list failed - almost always because outbound
    #NTP (UDP 123) is blocked on this network entirely, which is a very
    #ordinary thing for a locked-down competition range to do. Cache
    #this as "not synced" (offset 0.0 - no correction applied, rather
    #than guessing) so the rest of this run does not keep re-trying a
    #network that has already shown it won't answer.
    _cache.update(offset_seconds=0.0, measured_at_monotonic=now_monotonic,
                  synced=False, server=None, error=last_error)
    return 0.0, False, last_error


#Define corrected_utcnow, which hands back the current moment as a real,
#timezone-AWARE Python datetime, explicitly in UTC, corrected by
#whatever offset is currently cached (0.0 - i.e. "trust the system clock
#as-is" - if NTP has never been reachable from this machine). This is
#the one function evidence.py's own now() calls for every finding's
#"ts" field, and the one report.py calls for its own "Generated:" line -
#both get the SAME corrected notion of "right now," computed the same
#way, regardless of which machine (the analyst's own, or - for
#findings a remote target logged about itself - the monitored machine)
#actually ran it.
def corrected_utcnow():
    offset_seconds, _synced, _error = get_offset_seconds()
    return datetime.datetime.fromtimestamp(time.time() + offset_seconds, tz=datetime.timezone.utc)


#Define describe_sync_status, a small human-readable summary of the
#CURRENTLY cached NTP state - used only by report.py, to tell the person
#reading a report plainly whether its timestamps were actually verified
#against a real time source or are only as good as this machine's own
#clock. Calling get_offset_seconds() first (rather than reading _cache
#directly) means this always reflects a fresh attempt if the cache had
#gone stale, instead of silently reporting old, possibly outdated state.
def describe_sync_status():
    offset_seconds, synced, error = get_offset_seconds()
    if synced:
        #Say which direction the clock was off and by how much - a drift
        #of more than a minute or two is itself worth a second look (see
        #this module's own top comment on clock skew as an anti-forensics
        #technique), so the exact, signed number is shown rather than
        #rounded away to "a little" or "a lot."
        direction = "slow" if offset_seconds > 0 else "fast" if offset_seconds < 0 else "exactly correct"
        if offset_seconds == 0:
            return f"NTP-synced via {_cache['server']} (this machine's clock was exactly correct)"
        return f"NTP-synced via {_cache['server']} (this machine's own clock was {direction} by {abs(offset_seconds):.1f}s)"
    #NTP could not be reached at all - say so plainly rather than
    #letting an uncorrected timestamp look just as authoritative as a
    #verified one.
    return "NTP sync unavailable (outbound NTP may be blocked on this network) - using this machine's own system clock as-is"
