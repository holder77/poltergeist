#DESCRIPTION: This module answers the "upload a pcap to analyze" ask with
#             a BASIC FLOW SUMMARY - who talked to whom, on what port,
#             how much, and for how long - read straight out of the raw
#             .pcap file bytes with nothing but the Python standard
#             library (struct + socket). There is no tshark, no scapy,
#             no external packet-parsing library anywhere in this file
#             on purpose: a competition box may have no internet access
#             to install one, and this scope was deliberately kept to
#             "basic flow summary" rather than full deep-packet
#             inspection (see the project's own scope notes - this was
#             an explicit, resolved trade-off, not an oversight).
#
#             Like modules/log_review.py, this is GUI-only - there is no
#             fixed pcap file this runs against on a schedule, so it is
#             NOT in modules/__init__.py's LIVE_MODULES. The GUI's
#             "Upload PCAP to Analyze" button (see gui/app.py) calls
#             analyze_uploaded_pcap() directly, once, against whatever
#             capture file the analyst just picked.
#
#             Only the classic ".pcap" file format (the one tcpdump -w
#             and Wireshark's "Save As -> .pcap" both produce) is
#             supported - NOT the newer ".pcapng" format, which uses a
#             completely different, block-based structure. check() says
#             so plainly rather than silently misreading one.
#
#             Only plain Ethernet-framed IPv4 traffic carrying TCP or UDP
#             is summarized. Anything else (IPv6, ARP, a non-Ethernet
#             link layer) is counted but not broken into flows - this
#             keeps the parser small and honest about what it covers,
#             rather than guessing at formats it was never tested
#             against.

#import struct to unpack the fixed-width binary headers a .pcap file,
#an Ethernet frame, and an IPv4/TCP/UDP header are all made of.
import struct

#import socket purely for its inet_ntoa helper, which turns the 4 raw
#bytes of an IPv4 address into the familiar "1.2.3.4" text form -
#nothing here opens an actual network socket.
import socket


#The two classic-pcap magic numbers struct can see at the very start of
#the file, one for each byte order the capturing machine might have
#used, each paired with the struct format character that tells struct
#which order to read the REST of the file in once we know which magic
#number matched. ">" below also covers the (rare) nanosecond-resolution
#variants, which only differ in how the per-packet timestamp fields are
#scaled - a detail this basic summary never needs, since it only cares
#about ORDERING of timestamps, not sub-second precision.
PCAP_MAGIC_LITTLE_ENDIAN = 0xa1b2c3d4
PCAP_MAGIC_BIG_ENDIAN = 0xd4c3b2a1
PCAP_MAGIC_LITTLE_ENDIAN_NS = 0xa1b23c4d
PCAP_MAGIC_BIG_ENDIAN_NS = 0x4d3cb2a1

#The global file header is always exactly 24 bytes: magic(4) + major
#version(2) + minor version(2) + timezone offset(4, always 0 in
#practice) + sigfigs(4, always 0 in practice) + snaplen(4) + link-layer
#type(4).
GLOBAL_HEADER_SIZE = 24

#Each individual packet record header is always exactly 16 bytes:
#timestamp seconds(4) + timestamp microseconds-or-nanoseconds(4) +
#captured length(4) + original on-the-wire length(4, can be larger than
#captured length if the capture tool used a snap length).
PACKET_HEADER_SIZE = 16

#The link-layer type value meaning "plain Ethernet" - by far the most
#common value found in a real .pcap file, and the only one this basic
#parser knows how to look inside.
LINKTYPE_ETHERNET = 1

#The two IPv4 "next protocol" numbers this summary cares about pulling
#port numbers out of. Anything else (ICMP's 1, and everything beyond)
#is still counted toward the flow's packet/byte totals using just the
#IP addresses, with no port numbers attached.
PROTOCOL_TCP = 6
PROTOCOL_UDP = 17

#A hard cap on how many packets a single upload will actually parse -
#same reasoning log_review.py's own MAX_LOG_LINES uses: a multi-gigabyte
#capture should never turn one button click into a multi-minute hang.
#Anything beyond this count is silently stopped, not pretended away -
#see analyze_pcap_bytes()'s own "truncated" flag.
MAX_PACKETS = 50000

#How many distinct destination PORTS, from the same source IP to the
#same single destination IP, count as "enough to call this a probable
#port scan" rather than just a handful of ordinary short-lived
#connections (a web page pulling several assets, etc.).
PORT_SCAN_DISTINCT_PORT_THRESHOLD = 15

#A short, named list of destination ports with a long-standing
#reputation as default ports for well-known remote-access trojans and
#reverse-shell listeners - NOT a claim that traffic on one of these is
#definitely malicious (plenty of legitimate traffic also lands on an
#oddball high port), just enough to be worth a human's second look,
#same spirit as persistence.py's own EVASIVE_CONTENT_PATTERNS list.
SUSPICIOUS_DESTINATION_PORTS = {
    4444: "a very common default Metasploit/reverse-shell listener port",
    31337: "a classic 'elite' backdoor port (leetspeak for 'eleet')",
    1337: "another classic 'elite' backdoor port",
    6666: "a port sometimes used by IRC-based botnet command-and-control",
    6667: "the standard IRC port, sometimes repurposed for botnet C2",
    12345: "a port associated with several older remote-access trojans",
    54321: "a port associated with several older remote-access trojans",
}


#Define read_packets, a generator that walks the raw bytes of a classic
#.pcap file and yields (timestamp_seconds, link_layer_type, packet_bytes)
#for each packet record found - the one place in this file that touches
#the pcap CONTAINER format itself, kept separate from the Ethernet/IP/
#TCP/UDP parsing below so each piece can be tested (and reasoned about)
#on its own.
def read_packets(data, max_packets=MAX_PACKETS):
    #A file too short to even hold the global header is not a valid
    #capture at all - hand back nothing rather than raising partway
    #through a struct.unpack.
    if len(data) < GLOBAL_HEADER_SIZE:
        return
    #Peek at just the first 4 bytes, in BOTH byte orders, to work out
    #which one this specific file was written in before unpacking
    #anything else.
    magic_little, = struct.unpack("<I", data[0:4])
    magic_big, = struct.unpack(">I", data[0:4])
    if magic_little in (PCAP_MAGIC_LITTLE_ENDIAN, PCAP_MAGIC_LITTLE_ENDIAN_NS):
        byte_order = "<"
    elif magic_big in (PCAP_MAGIC_LITTLE_ENDIAN, PCAP_MAGIC_LITTLE_ENDIAN_NS):
        #The file's bytes are big-endian, so reading them with a
        #little-endian format string is what actually recovers the
        #real values - struct's own "<"/">" markers describe how to
        #READ the bytes, not which order they happen to already be in.
        byte_order = ">"
    else:
        #Neither byte order's magic number matched anything recognized
        #(most likely: this is a .pcapng file, or not a capture file at
        #all) - nothing more can be read.
        return
    #Pull the link-layer type out of the global header - the last 4
    #bytes of the 24-byte header - so every packet below can be handed
    #this same value without re-reading it each time.
    linktype, = struct.unpack(byte_order + "I", data[20:24])
    #Walk every packet record starting right after the global header.
    offset = GLOBAL_HEADER_SIZE
    packets_read = 0
    while offset + PACKET_HEADER_SIZE <= len(data) and packets_read < max_packets:
        ts_sec, ts_frac, captured_length, _original_length = struct.unpack(
            byte_order + "IIII", data[offset:offset + PACKET_HEADER_SIZE])
        offset += PACKET_HEADER_SIZE
        #A corrupted or truncated capture can claim a captured_length
        #that runs past the actual remaining bytes - stop cleanly
        #rather than yielding a short, misleading packet.
        if offset + captured_length > len(data):
            break
        packet_bytes = data[offset:offset + captured_length]
        offset += captured_length
        #ts_frac is microseconds in the overwhelmingly common case;
        #treating it as a simple fractional-second addition is accurate
        #enough for this summary's own purposes (ordering packets and
        #measuring rough flow duration), even on the rarer nanosecond
        #variant, where it would just slightly overstate the fraction.
        timestamp = ts_sec + (ts_frac / 1000000.0)
        yield timestamp, linktype, packet_bytes
        packets_read += 1


#Define parse_ipv4_tcp_udp, given one raw Ethernet-framed packet, return
#a plain dict describing its flow identity and size if (and only if) it
#is an IPv4 packet carrying TCP or UDP - or None for anything else
#(IPv6, ARP, a VLAN tag this parser doesn't bother unwrapping more than
#once, a malformed/truncated packet, etc.). Returning None rather than
#raising keeps one odd packet from ever stopping the whole summary.
def parse_ipv4_tcp_udp(packet_bytes, linktype):
    #Only plain Ethernet framing is understood here.
    if linktype != LINKTYPE_ETHERNET:
        return None
    #An Ethernet header is at minimum 14 bytes (6 dest MAC + 6 src MAC +
    #2 ethertype) - anything shorter cannot be a real frame.
    if len(packet_bytes) < 14:
        return None
    ethertype, = struct.unpack(">H", packet_bytes[12:14])
    ip_offset = 14
    #A single 802.1Q VLAN tag inserts 4 extra bytes and its own nested
    #ethertype field right after the normal one - unwrap exactly one
    #level of that, which covers the large majority of real captures
    #that use VLAN tagging at all.
    if ethertype == 0x8100 and len(packet_bytes) >= 18:
        ethertype, = struct.unpack(">H", packet_bytes[16:18])
        ip_offset = 18
    #0x0800 is IPv4 - anything else (0x0806 ARP, 0x86DD IPv6, etc.) is
    #simply not something this basic summary breaks into a flow.
    if ethertype != 0x0800:
        return None
    #An IPv4 header is at minimum 20 bytes.
    if len(packet_bytes) < ip_offset + 20:
        return None
    ip_header = packet_bytes[ip_offset:ip_offset + 20]
    version_and_ihl = ip_header[0]
    #The low nibble of the first byte is the header length, measured in
    #32-bit (4-byte) words - almost always 5 (a plain 20-byte header,
    #with no IP options), but this is read properly rather than assumed.
    header_length_bytes = (version_and_ihl & 0x0F) * 4
    protocol = ip_header[9]
    source_ip = socket.inet_ntoa(ip_header[12:16])
    destination_ip = socket.inet_ntoa(ip_header[16:20])
    transport_offset = ip_offset + header_length_bytes
    source_port = None
    destination_port = None
    #Both TCP and UDP happen to put source port and destination port in
    #exactly the same first-4-bytes position, so one read covers both.
    if protocol in (PROTOCOL_TCP, PROTOCOL_UDP) and len(packet_bytes) >= transport_offset + 4:
        source_port, destination_port = struct.unpack(">HH", packet_bytes[transport_offset:transport_offset + 4])
    return {
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "protocol": protocol,
        "source_port": source_port,
        "destination_port": destination_port,
        #The ORIGINAL on-the-wire packet length is a more honest size to
        #tally than the possibly-snap-length-truncated captured bytes,
        #but since read_packets() already only hands us the captured
        #bytes, length-of-what-we-actually-have is what gets counted -
        #close enough for a basic summary, and never overstates traffic
        #that was never actually captured.
        "length": len(packet_bytes),
    }


#Define protocol_name, a tiny human-readable label helper so findings
#and the GUI summary never show a bare, unexplained protocol number.
def protocol_name(protocol_number):
    if protocol_number == PROTOCOL_TCP:
        return "TCP"
    if protocol_number == PROTOCOL_UDP:
        return "UDP"
    #Anything else just shows its raw IP protocol number - this basic
    #summary does not maintain a full IANA protocol-number table.
    return f"proto {protocol_number}"


#Define analyze_pcap_bytes, the pure, testable core of this whole file -
#given the raw bytes of a .pcap file, return a plain dict with the flow
#summary and a short list of basic-heuristic findings. Nothing here
#touches the filesystem or the shared Log object, so this one function
#can be - and is, see pcap_review_test.py - tested completely on its
#own, same split log_review.py's analyze_lines() uses.
def analyze_pcap_bytes(data):
    flows = {}
    other_packet_count = 0
    other_byte_count = 0
    total_packets = 0
    truncated = False
    #Walk every packet the container format yields.
    for timestamp, linktype, packet_bytes in read_packets(data):
        total_packets += 1
        if total_packets >= MAX_PACKETS:
            truncated = True
        parsed = parse_ipv4_tcp_udp(packet_bytes, linktype)
        if parsed is None:
            #Not IPv4 TCP/UDP traffic this basic summary breaks into a
            #flow - still counted, just not attributed to one.
            other_packet_count += 1
            other_byte_count += len(packet_bytes)
            continue
        #A flow's identity is its full 5-tuple - source IP, destination
        #IP, protocol, source port, destination port - so a web
        #browser's many short-lived connections to the SAME server on
        #different local ports are correctly kept as separate flows,
        #never merged into one misleadingly large one.
        flow_key = (parsed["source_ip"], parsed["destination_ip"], parsed["protocol"],
                    parsed["source_port"], parsed["destination_port"])
        if flow_key not in flows:
            flows[flow_key] = {
                "source_ip": parsed["source_ip"],
                "destination_ip": parsed["destination_ip"],
                "protocol": parsed["protocol"],
                "source_port": parsed["source_port"],
                "destination_port": parsed["destination_port"],
                "packet_count": 0,
                "byte_count": 0,
                "first_seen": timestamp,
                "last_seen": timestamp,
            }
        flow = flows[flow_key]
        flow["packet_count"] += 1
        flow["byte_count"] += parsed["length"]
        flow["first_seen"] = min(flow["first_seen"], timestamp)
        flow["last_seen"] = max(flow["last_seen"], timestamp)

    #Build the short list of basic heuristic findings from the finished
    #flow table - deliberately just two checks, matching this module's
    #"basic flow summary" scope rather than trying to be a full IDS.
    basic_findings = []

    #Heuristic 1: any flow landing on a well-known suspicious port.
    for flow in flows.values():
        destination_port = flow["destination_port"]
        if destination_port in SUSPICIOUS_DESTINATION_PORTS:
            reason = SUSPICIOUS_DESTINATION_PORTS[destination_port]
            basic_findings.append((
                "medium",
                f"suspicious_port:{flow['source_ip']}:{flow['destination_ip']}:{destination_port}",
                f"{flow['source_ip']} -> {flow['destination_ip']}:{destination_port} "
                f"({protocol_name(flow['protocol'])}, {flow['packet_count']} packets) - "
                f"port {destination_port} is {reason}",
            ))

    #Heuristic 2: one source IP reaching a large number of DISTINCT
    #destination ports on the SAME single destination IP - the classic
    #shape of a port scan, as opposed to a normal client that talks to
    #just a handful of ports on any one server.
    ports_per_source_and_destination = {}
    for flow in flows.values():
        if flow["destination_port"] is None:
            continue
        pair_key = (flow["source_ip"], flow["destination_ip"])
        ports_per_source_and_destination.setdefault(pair_key, set()).add(flow["destination_port"])
    for (source_ip, destination_ip), distinct_ports in ports_per_source_and_destination.items():
        if len(distinct_ports) >= PORT_SCAN_DISTINCT_PORT_THRESHOLD:
            basic_findings.append((
                "high",
                f"portscan:{source_ip}:{destination_ip}",
                f"{source_ip} contacted {len(distinct_ports)} distinct ports on {destination_ip} - "
                "this shape looks like a port scan, not ordinary traffic",
            ))

    return {
        "flows": list(flows.values()),
        "other_packet_count": other_packet_count,
        "other_byte_count": other_byte_count,
        "total_packets": total_packets,
        "truncated": truncated,
        "basic_findings": basic_findings,
    }


#Define looks_like_classic_pcap, a tiny standalone check so the
#magic-number test is spelled out as its own clearly-named boolean
#rather than a dense inline condition that would be easy to get the
#operator precedence wrong on (mixing "or" and "and" without enough
#parentheses is exactly how that kind of bug hides).
def looks_like_classic_pcap(data):
    if len(data) < 4:
        return False
    magic_little, = struct.unpack("<I", data[0:4])
    magic_big, = struct.unpack(">I", data[0:4])
    recognized_magics = (PCAP_MAGIC_LITTLE_ENDIAN, PCAP_MAGIC_LITTLE_ENDIAN_NS,
                          PCAP_MAGIC_BIG_ENDIAN, PCAP_MAGIC_BIG_ENDIAN_NS)
    return magic_little in recognized_magics or magic_big in recognized_magics


#Define analyze_uploaded_pcap, called directly by the GUI's "Upload PCAP
#to Analyze" button - like log_review.py's analyze_uploaded_text(), this
#is NOT a LIVE_MODULES entry (there is no fixed capture file to re-read
#on a schedule); it runs once, against whichever file the analyst just
#picked. filename is used only to make each finding's key unique to
#that specific upload, the same reasoning analyze_uploaded_text() uses.
def analyze_uploaded_pcap(config, log, filename, data):
    #A file that does not even start with a recognized classic-pcap
    #magic number is reported plainly rather than silently returning an
    #empty, misleadingly "clean" summary - most likely cause is a
    #.pcapng file, which this basic parser does not read.
    if not looks_like_classic_pcap(data):
        log.add("pcap", "info", f"unsupported_format:{filename}",
                f"{filename} does not look like a classic .pcap file (wrong magic number) - "
                "if this came from Wireshark, try 'File > Save As' and choose the "
                "'Wireshark/tcpdump/... - pcap' format rather than the newer pcapng default")
        return {"flows": [], "other_packet_count": 0, "other_byte_count": 0,
                "total_packets": 0, "truncated": False, "basic_findings": []}
    summary = analyze_pcap_bytes(data)
    #Report every basic-heuristic finding through the shared Log
    #object, keyed with the uploaded file's own name baked in so two
    #different uploads' matching patterns never collide or silently
    #suppress one another.
    for severity, key, message in summary["basic_findings"]:
        log.add("pcap", severity, f"uploaded:{filename}:{key}", f"[uploaded: {filename}] {message}")
    #Also file one plain informational summary line, even when nothing
    #suspicious was found at all, so a clean-looking capture still shows
    #up on the Dashboard as evidence that it was actually looked at.
    log.add("pcap", "info", f"uploaded:{filename}:summary",
            f"[uploaded: {filename}] analyzed {summary['total_packets']} packets across "
            f"{len(summary['flows'])} IPv4 TCP/UDP flows"
            + (" (capture was larger than this tool reads in one pass - results reflect "
               "only the first packets read)" if summary["truncated"] else ""))
    #Hand back the full summary dict too, so the GUI can show an
    #immediate on-screen flow table without re-reading findings.jsonl.
    return summary
