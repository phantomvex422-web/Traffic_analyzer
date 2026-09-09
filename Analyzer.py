"""
Network Traffic Analyzer - Phase 4 (refined detection)
Loads a pcap file, counts packets, prints a protocol breakdown,
ranks top talkers, reconstructs conversations (flows), and
detects likely port-scan activity using unanswered-SYN analysis.
"""

from scapy.all import rdpcap
from collections import Counter, defaultdict
import sys


def load_pcap(filepath):
    """Read a pcap file from disk and return the list of packets."""
    packets = rdpcap(filepath)
    return packets


def protocol_breakdown(packets):
    """
    Count packets by their highest-level protocol.
    Each packet is counted once, at its most specific layer.
    """
    counts = Counter()

    for pkt in packets:
        if pkt.haslayer("DNS"):
            counts["DNS"] += 1
        elif pkt.haslayer("TCP"):
            counts["TCP"] += 1
        elif pkt.haslayer("UDP"):
            counts["UDP"] += 1
        elif pkt.haslayer("ICMP"):
            counts["ICMP"] += 1
        elif pkt.haslayer("ARP"):
            counts["ARP"] += 1
        elif pkt.haslayer("IP"):
            counts["IP (other)"] += 1
        else:
            counts["Other"] += 1

    return counts


def top_talkers(packets):
    """
    Aggregate traffic per IP address, crediting both source and destination.
    Returns a dict:  ip -> {"packets": int, "bytes": int}
    """
    stats = defaultdict(lambda: {"packets": 0, "bytes": 0})

    for pkt in packets:
        if not pkt.haslayer("IP"):
            continue

        src = pkt["IP"].src
        dst = pkt["IP"].dst
        size = len(pkt)

        for ip in (src, dst):
            stats[ip]["packets"] += 1
            stats[ip]["bytes"] += size

    return stats


def flow_key(pkt):
    """
    Build a direction-agnostic key identifying the conversation a packet
    belongs to, by sorting the two (ip, port) endpoints so both directions
    collapse into one flow. Matches Wireshark's Conversations grouping.
    """
    ip = pkt["IP"]
    src_ip, dst_ip = ip.src, ip.dst

    if pkt.haslayer("TCP"):
        proto = "TCP"
        sport, dport = pkt["TCP"].sport, pkt["TCP"].dport
    elif pkt.haslayer("UDP"):
        proto = "UDP"
        sport, dport = pkt["UDP"].sport, pkt["UDP"].dport
    else:
        proto = "OTHER"
        sport, dport = 0, 0

    endpoint_a = (src_ip, sport)
    endpoint_b = (dst_ip, dport)

    low, high = sorted([endpoint_a, endpoint_b])
    return (low[0], low[1], high[0], high[1], proto)


def reconstruct_flows(packets):
    """
    Group packets into conversations using flow_key().
    Tracks packets, bytes, and first/last timestamp per flow.
    """
    flows = defaultdict(lambda: {"packets": 0, "bytes": 0,
                                 "start": None, "end": None})

    for pkt in packets:
        if not pkt.haslayer("IP"):
            continue

        key = flow_key(pkt)
        ts = float(pkt.time)
        size = len(pkt)

        flow = flows[key]
        flow["packets"] += 1
        flow["bytes"] += size

        if flow["start"] is None or ts < flow["start"]:
            flow["start"] = ts
        if flow["end"] is None or ts > flow["end"]:
            flow["end"] = ts

    return flows


def detect_port_scans(packets, port_threshold=20,
                      unanswered_host_threshold=50):
    """
    Flag source IPs that look like they are performing a port scan, using
    connection-success analysis to avoid false-positiving on normal browsing.

    Two scan shapes
    ---------------
      1. VERTICAL   - one source hits MANY different ports on ONE host.
      2. HORIZONTAL - one source sends connection attempts to MANY hosts that
                      are never answered (a host/network sweep).

    Why "unanswered" matters
    ------------------------
    Counting distinct hosts alone false-positives badly: a single modern web
    page legitimately contacts dozens of CDNs, ad, analytics and font servers,
    so normal browsing easily touches 150+ hosts. What browsing does NOT do is
    leave a pile of *unanswered* connection attempts - almost every SYN a
    browser sends gets a SYN-ACK back and completes.

    A horizontal scanner is the opposite: it sprays SYNs across a range probing
    for an open service, and most targets never reply (host down, port closed
    and dropped, or filtered). So we count, per source, the destinations that
    were SYN'd but never sent a SYN-ACK back. A large number of these is the
    real scan signal.

    TCP flags:  SYN = 0x02, ACK = 0x10
      - bare SYN      (SYN set, ACK clear) = a connection attempt
      - SYN-ACK       (SYN set, ACK set)   = the target accepting / replying
    """
    # --- Pass 1: record who attempted what, and who replied ---

    # src_ip -> dst_ip -> set of dst ports it sent bare SYNs to
    ports_per_target = defaultdict(lambda: defaultdict(set))
    # src_ip -> set of dst hosts it sent bare SYNs to
    syn_targets = defaultdict(set)
    # set of (attacker_ip, target_ip) pairs where target replied with SYN-ACK.
    # A SYN-ACK travels target -> attacker, so we flip src/dst to line it up
    # with the original attempt's (attacker, target) direction.
    answered = set()

    for pkt in packets:
        if not pkt.haslayer("TCP") or not pkt.haslayer("IP"):
            continue

        flags = pkt["TCP"].flags
        syn = flags & 0x02
        ack = flags & 0x10

        src = pkt["IP"].src
        dst = pkt["IP"].dst
        dport = pkt["TCP"].dport

        if syn and not ack:
            # Connection attempt: attacker=src, target=dst
            ports_per_target[src][dst].add(dport)
            syn_targets[src].add(dst)
        elif syn and ack:
            # Reply from a target: packet goes target(src) -> attacker(dst).
            # Record it under (attacker, target) = (dst, src).
            answered.add((dst, src))

    # --- Pass 2: score each source ---

    findings = []

    for src in syn_targets:
        # VERTICAL: most ports touched on any single target host.
        max_ports_on_one_host = max(
            len(ports) for ports in ports_per_target[src].values()
        )
        if max_ports_on_one_host >= port_threshold:
            findings.append(
                (src, "VERTICAL",
                 f"hit {max_ports_on_one_host} ports on a single host")
            )

        # HORIZONTAL: count targets that were SYN'd but never replied.
        unanswered = [
            dst for dst in syn_targets[src]
            if (src, dst) not in answered
        ]
        if len(unanswered) >= unanswered_host_threshold:
            findings.append(
                (src, "HORIZONTAL",
                 f"{len(unanswered)} unanswered SYNs "
                 f"across {len(syn_targets[src])} hosts")
            )

    return findings


def human_bytes(num):
    """Turn a raw byte count into a readable string (KB / MB)."""
    for unit in ("B", "KB", "MB", "GB"):
        if num < 1024:
            return f"{num:.1f} {unit}"
        num /= 1024
    return f"{num:.1f} TB"


def main():
    filepath = sys.argv[1] if len(sys.argv) > 1 else "test.pcap"

    print(f"Loading: {filepath}")
    packets = load_pcap(filepath)

    total = len(packets)
    print(f"\nTotal packets: {total}\n")

    # --- Protocol breakdown ---
    print("Protocol breakdown:")
    counts = protocol_breakdown(packets)
    for proto, count in counts.most_common():
        percentage = (count / total) * 100
        print(f"  {proto:<12} {count:>6}  ({percentage:.1f}%)")

    # --- Top talkers ---
    print("\nTop talkers (by bytes):")
    stats = top_talkers(packets)
    ranked = sorted(stats.items(), key=lambda item: item[1]["bytes"], reverse=True)
    print(f"  {'IP address':<18}{'Packets':>10}{'Bytes':>14}")
    for ip, data in ranked[:10]:
        print(f"  {ip:<18}{data['packets']:>10}{human_bytes(data['bytes']):>14}")

    # --- Flows / conversations ---
    print("\nTop conversations (by bytes):")
    flows = reconstruct_flows(packets)
    print(f"  Total flows: {len(flows)}\n")

    flow_ranked = sorted(flows.items(),
                         key=lambda item: item[1]["bytes"], reverse=True)

    header = (f"  {'Source':<22}{'Destination':<22}"
              f"{'Proto':<7}{'Pkts':>7}{'Bytes':>11}{'Dur(s)':>9}")
    print(header)

    for key, data in flow_ranked[:15]:
        low_ip, low_port, high_ip, high_port, proto = key
        source = f"{low_ip}:{low_port}"
        dest = f"{high_ip}:{high_port}"
        duration = data["end"] - data["start"]
        print(f"  {source:<22}{dest:<22}{proto:<7}"
              f"{data['packets']:>7}{human_bytes(data['bytes']):>11}"
              f"{duration:>9.1f}")

    # --- Port scan detection ---
    print("\nPort scan detection:")
    findings = detect_port_scans(packets)

    if not findings:
        print("  No port-scan activity detected.")
    else:
        for src, scan_type, detail in findings:
            print(f"  [!] {src:<16} {scan_type:<12} {detail}")


if __name__ == "__main__":
    main()