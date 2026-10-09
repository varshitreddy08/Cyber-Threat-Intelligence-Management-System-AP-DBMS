"""
CTIMS PCAP Analyzer — uses pyshark (tshark wrapper) to parse network captures.
Called from Next.js API route. Outputs JSON to stdout.
Usage: python analyze_pcap.py <path_to_pcap>
"""
import sys, json, os, collections

# Point pyshark to the installed tshark
os.environ["PATH"] += r";C:\Program Files\Wireshark"

try:
    import pyshark
except ImportError:
    print(json.dumps({"error": "pyshark not installed"}))
    sys.exit(1)

def analyze(pcap_path: str) -> dict:
    src_ips     = collections.Counter()
    dst_ips     = collections.Counter()
    protocols   = collections.Counter()
    ports       = collections.Counter()
    dns_queries = []
    http_hosts  = []
    suspicious  = []
    total_pkts  = 0

    # Suspicious port list
    SUSPICIOUS_PORTS = {
        4444: "Metasploit default",
        1337: "Common C2",
        6667: "IRC (botnet)",
        6666: "IRC (botnet)",
        31337: "Elite backdoor",
        12345: "NetBus backdoor",
        27374: "Sub7 backdoor",
        1433: "MSSQL",
        3389: "RDP",
        22:   "SSH",
        23:   "Telnet (insecure)",
    }

    try:
        cap = pyshark.FileCapture(
            pcap_path,
            only_summaries=False,
            keep_packets=False,
            use_ek=False,
        )

        for pkt in cap:
            total_pkts += 1
            if total_pkts > 5000:   # Cap at 5000 packets for speed
                break

            try:
                proto = pkt.highest_layer
                protocols[proto] += 1

                # IP layer
                if hasattr(pkt, "ip"):
                    src = pkt.ip.src
                    dst = pkt.ip.dst
                    src_ips[src] += 1
                    dst_ips[dst] += 1

                # TCP/UDP port analysis
                if hasattr(pkt, "tcp"):
                    dport = int(pkt.tcp.dport)
                    sport = int(pkt.tcp.sport)
                    ports[dport] += 1
                    if dport in SUSPICIOUS_PORTS:
                        suspicious.append({
                            "type": "Suspicious Port",
                            "detail": f"TCP dst={dport} ({SUSPICIOUS_PORTS[dport]}) from {pkt.ip.src if hasattr(pkt,'ip') else 'unknown'}",
                            "severity": "High" if dport in (4444,1337,31337) else "Medium"
                        })

                if hasattr(pkt, "udp"):
                    dport = int(pkt.udp.dport)
                    ports[dport] += 1

                # DNS queries
                if hasattr(pkt, "dns") and hasattr(pkt.dns, "qry_name"):
                    qname = str(pkt.dns.qry_name)
                    dns_queries.append(qname)
                    # Flag unusual TLDs
                    unusual_tlds = [".xyz",".tk",".top",".pw",".cc",".su",".ru"]
                    for tld in unusual_tlds:
                        if qname.endswith(tld):
                            suspicious.append({
                                "type": "Suspicious DNS",
                                "detail": f"Query to suspicious TLD domain: {qname}",
                                "severity": "High"
                            })

                # HTTP host
                if hasattr(pkt, "http") and hasattr(pkt.http, "host"):
                    http_hosts.append(str(pkt.http.host))

            except Exception:
                continue

        cap.close()

    except Exception as e:
        return {"error": str(e)}

    # Top IPs
    top_src = [{"ip": ip, "count": c} for ip, c in src_ips.most_common(10)]
    top_dst = [{"ip": ip, "count": c} for ip, c in dst_ips.most_common(10)]
    top_protocols = [{"name": p, "count": c} for p, c in protocols.most_common(10)]
    top_ports = [{"port": p, "count": c} for p, c in ports.most_common(10)]

    # Deduplicate DNS and HTTP
    unique_dns   = list(dict.fromkeys(dns_queries))[:20]
    unique_hosts = list(dict.fromkeys(http_hosts))[:20]

    # Deduplicate suspicious
    seen = set()
    unique_suspicious = []
    for s in suspicious:
        key = s["detail"]
        if key not in seen:
            seen.add(key)
            unique_suspicious.append(s)

    # Build suggested IOCs from top destination IPs
    suggested_iocs = []
    for entry in top_dst[:5]:
        ip = entry["ip"]
        # Skip private/local IPs
        if not (ip.startswith("10.") or ip.startswith("192.168.")
                or ip.startswith("172.") or ip.startswith("127.")
                or ip.startswith("0.") or ip == "255.255.255.255"):
            suggested_iocs.append({
                "type": "IP",
                "value": ip,
                "count": entry["count"],
                "severity": "Medium",
                "reason": f"Frequent destination — {entry['count']} packets"
            })

    for domain in unique_dns[:3]:
        for tld in [".xyz",".tk",".top",".pw",".cc"]:
            if domain.endswith(tld):
                suggested_iocs.append({
                    "type": "Domain",
                    "value": domain,
                    "count": 1,
                    "severity": "High",
                    "reason": "Suspicious TLD in DNS query"
                })

    return {
        "total_packets": total_pkts,
        "top_source_ips": top_src,
        "top_dest_ips": top_dst,
        "protocol_breakdown": top_protocols,
        "top_ports": top_ports,
        "dns_queries": unique_dns,
        "http_hosts": unique_hosts,
        "suspicious_activity": unique_suspicious[:20],
        "suggested_iocs": suggested_iocs,
    }


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: analyze_pcap.py <pcap_file>"}))
        sys.exit(1)

    result = analyze(sys.argv[1])
    print(json.dumps(result, indent=2))
