#DESCRIPTION: This module answers the other half of "lets you upload
#             winevents as well and it analyzes those" - specifically a
#             genuinely BINARY Windows Event Log file (.evtx), the
#             format wevtutil/Event Viewer themselves write and export
#             by default. This is the one piece of this round's ask
#             this file is DELIBERATELY HONEST about not fully solving:
#             a .evtx file's actual event content (which event ID
#             fired, which structured fields it carried) is stored as
#             "Binary XML" - a compact, template-based binary encoding
#             that needs a real token-by-token decoder to read
#             correctly, which is a substantial undertaking well beyond
#             a "basic" reader (see modules/pcap_review.py's own top
#             comment for this project's established "basic X, pure
#             Python, honestly scoped" pattern - this follows the exact
#             same philosophy).
#
#             What THIS module does, reliably, with no new dependency:
#             walks the real, documented EVTX container format (file
#             header -> fixed-size chunks -> fixed-size event record
#             headers) to get an accurate record count and time range -
#             the structural, metadata-level parts of the format, which
#             are NOT binary-XML-encoded and so can be read with simple
#             struct unpacking - and then does a best-effort scan for
#             human-readable UTF-16LE text actually embedded in each
#             record's binary XML payload (usernames, IP addresses, and
#             provider names are very often stored as literal text
#             there, even though the surrounding XML structure and the
#             event ID itself are not), surfaced for an analyst's own
#             manual review rather than claimed as a severity-judged
#             finding. For a field-accurate, brute-force-style severity
#             check the SAME way Linux/syslog-style logs get, export the
#             Windows log to text first (wevtutil's own "/f:text", or
#             "Export-Csv" from PowerShell) and use the regular "Upload
#             Log to Analyze" button instead - modules/log_review.py's
#             own analyze_uploaded_text() already auto-detects and fully
#             parses that text format.

#import struct for every fixed-width binary field this file reads.
import struct

#import re for the UTF-16LE printable-text extraction below.
import re

#import datetime to turn a raw Windows FILETIME into a real, readable
#timestamp.
import datetime

#The file-level signature every real .evtx file starts with.
EVTX_FILE_MAGIC = b"ElfFile\x00"

#The signature every 64KB chunk within the file starts with.
EVTX_CHUNK_MAGIC = b"ElfChnk\x00"

#The signature every individual event record within a chunk starts
#with - these four bytes, read as a little-endian UInt32, are the
#well-known value 0x00002a2a ("**" repeated, by convention).
EVTX_RECORD_MAGIC = b"\x2a\x2a\x00\x00"

#Every chunk in a real .evtx file is exactly this many bytes, starting
#right after the 4096-byte file header.
EVTX_CHUNK_SIZE = 65536

#The file header itself is always exactly this many bytes.
EVTX_FILE_HEADER_SIZE = 4096

#Event records within a chunk begin at this fixed offset (the first 512
#bytes of a chunk hold the chunk's own header plus a common-string
#table this basic reader does not need to decode).
EVTX_CHUNK_RECORDS_START_OFFSET = 512

#Hard caps so a huge or corrupted file can never turn one upload click
#into a multi-minute hang or an out-of-memory crash - same reasoning
#pcap_review.py's own MAX_PACKETS uses.
MAX_CHUNKS = 2000
MAX_RECORDS = 200000
MAX_EXTRACTED_STRINGS = 500

#A regex matching a run of 4+ printable ASCII characters, each followed
#by a null byte - the shape a plain ASCII string takes once encoded as
#UTF-16LE, which is how the vast majority of human-readable text inside
#a binary-XML event record is actually stored (usernames, hostnames, IP
#addresses, provider names). This is a heuristic, not a structural
#decode - see this file's own top comment for exactly why that's an
#honest, deliberate choice here, not an oversight.
UTF16LE_PRINTABLE_RUN_PATTERN = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")

#A plain IPv4-shape pattern, used to flag which of the extracted
#strings look like they might be a source address worth a second look.
IPV4_LOOKING_PATTERN = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

#FILETIME's own epoch (1601-01-01 00:00:00 UTC) expressed as seconds
#before the Unix epoch - the standard constant for this conversion.
FILETIME_EPOCH_OFFSET_SECONDS = 11644473600


def looks_like_evtx(data):
    #A real .evtx file always starts with this exact 8-byte signature.
    return data[:8] == EVTX_FILE_MAGIC


def _filetime_to_datetime(filetime_value):
    #A FILETIME of 0 means "no timestamp was actually set" - never a
    #real date, so don't pretend it is one.
    if not filetime_value:
        return None
    try:
        unix_seconds = (filetime_value / 10_000_000) - FILETIME_EPOCH_OFFSET_SECONDS
        return datetime.datetime.fromtimestamp(unix_seconds, tz=datetime.timezone.utc)
    #An implausible value (corrupt data, a record we mis-walked into)
    #should never crash this reader - just treat it as "no timestamp".
    except (OverflowError, OSError, ValueError):
        return None


def _extract_printable_strings(record_bytes):
    #Find every run of UTF-16LE-encoded printable ASCII text in this
    #one record's own binary XML payload.
    found = []
    for match in UTF16LE_PRINTABLE_RUN_PATTERN.finditer(record_bytes):
        try:
            text = match.group(0).decode("utf-16-le").strip()
        #A decode should never actually fail given the pattern that
        #matched it, but this is cheap insurance against any edge case.
        except UnicodeDecodeError:
            continue
        if text:
            found.append(text)
    return found


#Define iter_chunks, walking the file's own fixed-size 64KB chunks,
#starting right after the 4096-byte file header, stopping the moment a
#chunk's own magic doesn't match (reached unused trailing space, or
#this isn't really a chunk-structured file at all) rather than trusting
#the file header's own "chunk count" field, which can be stale on a
#dirty/crashed capture - exactly the kind of file a blue-team
#competitor is most likely to actually be handed.
def iter_chunks(data):
    offset = EVTX_FILE_HEADER_SIZE
    chunks_read = 0
    while offset + 8 <= len(data) and chunks_read < MAX_CHUNKS:
        if data[offset:offset + 8] != EVTX_CHUNK_MAGIC:
            #Not a real chunk - stop walking rather than guess further.
            break
        chunk_end = min(offset + EVTX_CHUNK_SIZE, len(data))
        yield data[offset:chunk_end]
        offset += EVTX_CHUNK_SIZE
        chunks_read += 1


#Define iter_chunk_records, walking one chunk's own event records,
#starting at the fixed offset every chunk's records begin at, stopping
#the moment a record's own magic doesn't match (reached this chunk's
#free/unused trailing space).
def iter_chunk_records(chunk_bytes):
    offset = EVTX_CHUNK_RECORDS_START_OFFSET
    records_read = 0
    while offset + 24 <= len(chunk_bytes) and records_read < MAX_RECORDS:
        if chunk_bytes[offset:offset + 4] != EVTX_RECORD_MAGIC:
            #Reached this chunk's free space - nothing more to read.
            break
        record_size, = struct.unpack_from("<I", chunk_bytes, offset + 4)
        #A corrupt or implausible size must never be trusted blindly -
        #it would either infinite-loop (size of 0) or read past this
        #chunk's own bounds into whatever bytes happen to follow it.
        if record_size < 24 or offset + record_size > len(chunk_bytes):
            break
        record_id, = struct.unpack_from("<Q", chunk_bytes, offset + 8)
        filetime_value, = struct.unpack_from("<Q", chunk_bytes, offset + 16)
        binxml_data = chunk_bytes[offset + 24: offset + record_size - 4]
        yield {"record_id": record_id, "timestamp": _filetime_to_datetime(filetime_value), "binxml": binxml_data}
        offset += record_size
        records_read += 1


#Define analyze_evtx_bytes, the pure, testable core of this whole file:
#given the raw bytes of a .evtx file, return a plain dict summarizing
#what was structurally readable - record count, time range, and a
#deduplicated, capped list of human-readable text strings found
#embedded across every record, for manual review. Nothing here touches
#the filesystem or the shared Log object, so this one function can be -
#and is, see evtx_review_test.py - tested completely on its own, same
#split every other *_review.py module in this project uses.
def analyze_evtx_bytes(data):
    record_count = 0
    first_seen = None
    last_seen = None
    extracted_strings = set()
    possible_ip_strings = set()
    truncated = False
    for chunk_bytes in iter_chunks(data):
        for record in iter_chunk_records(chunk_bytes):
            record_count += 1
            if record_count >= MAX_RECORDS:
                truncated = True
            timestamp = record["timestamp"]
            if timestamp is not None:
                first_seen = timestamp if first_seen is None else min(first_seen, timestamp)
                last_seen = timestamp if last_seen is None else max(last_seen, timestamp)
            if len(extracted_strings) < MAX_EXTRACTED_STRINGS:
                for text in _extract_printable_strings(record["binxml"]):
                    extracted_strings.add(text)
                    if IPV4_LOOKING_PATTERN.match(text):
                        possible_ip_strings.add(text)
    return {
        "record_count": record_count,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "truncated": truncated,
        #Sorted purely so the GUI's own output (and this module's own
        #tests) are deterministic from one run to the next.
        "extracted_strings": sorted(extracted_strings)[:MAX_EXTRACTED_STRINGS],
        "possible_ip_strings": sorted(possible_ip_strings),
    }


#Define analyze_uploaded_evtx, called directly by the GUI's "Upload Log"
#button (via log_review.py's own dispatch - see app.py's upload handler)
#whenever the uploaded bytes start with the EVTX file magic. Like
#log_review.py's analyze_uploaded_text(), this is NOT a LIVE_MODULES
#entry - it runs once, against whichever file the analyst just picked.
def analyze_uploaded_evtx(config, log, filename, data):
    if not looks_like_evtx(data):
        #Something else entirely (truncated download, wrong file, a
        #renamed non-evtx file) - say so plainly rather than silently
        #returning an empty, misleadingly "clean" summary.
        log.add("logs", "info", f"unsupported_format:{filename}",
                f"{filename} does not look like a classic .evtx file (wrong file signature)")
        return {"record_count": 0, "first_seen": None, "last_seen": None, "truncated": False,
                "extracted_strings": [], "possible_ip_strings": []}
    summary = analyze_evtx_bytes(data)
    #Always file one plain informational summary line, even when
    #nothing further was extracted, so this upload shows up as evidence
    #it was actually looked at - same habit log_review.py's own
    #analyze_uploaded_text() and pcap_review.py's own
    #analyze_uploaded_pcap() both already follow.
    time_range = ""
    if summary["first_seen"] and summary["last_seen"]:
        time_range = f", spanning {summary['first_seen'].isoformat()} to {summary['last_seen'].isoformat()}"
    log.add("logs", "info", f"uploaded:{filename}:summary",
            f"[uploaded Windows event log: {filename}] {summary['record_count']} event record(s) read{time_range}. "
            "This is a BASIC structural read only (record count/timestamps, plus readable text found embedded in "
            "each record) - exact event IDs are not decoded from the binary format. For a full brute-force-style "
            "check, export this log to text via wevtutil ('/f:text') or PowerShell and upload that instead.")
    #Surface any IP-looking strings found, for manual review - NOT
    #severity-judged (see this file's own top comment for why), just
    #surfaced as a lead worth following up by hand.
    if summary["possible_ip_strings"]:
        log.add("logs", "info", f"uploaded:{filename}:possible_ips",
                f"[uploaded Windows event log: {filename}] possible IP address(es) found in the raw event data "
                f"(unconfirmed which event/field they belong to): {', '.join(summary['possible_ip_strings'][:30])}")
    return summary
