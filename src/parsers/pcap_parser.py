from scapy.all import rdpcap, DNSQR, IP, TCP, Raw
from src.schema import ForensicArtifact
from datetime import datetime

def parse_pcap(file_path: str):
    """Parses PCAP file to extract DNS queries and HTTP connections."""
    artifacts = []
    
    try:
        packets = rdpcap(file_path)
        
        for pkt in packets:
            # Check for DNS
            if pkt.haslayer(DNSQR):
                qname = pkt[DNSQR].qname.decode('utf-8', errors='ignore') if pkt[DNSQR].qname else ""
                ip_src = pkt[IP].src if pkt.haslayer(IP) else "UNKNOWN"
                
                artifact = ForensicArtifact(
                    timestamp=datetime.utcfromtimestamp(float(pkt.time)).isoformat() + "Z",
                    source_type="PCAP_DNS",
                    host=ip_src,
                    user="NETWORK",
                    details=f"DNS Query: {qname}",
                    ioc_detected=qname.strip('.')
                )
                artifacts.append(artifact)
                
            # Check for HTTP (Simple port 80 check)
            elif pkt.haslayer(TCP) and (pkt[TCP].dport == 80 or pkt[TCP].sport == 80):
                if pkt.haslayer(Raw):
                    payload = pkt[Raw].load.decode('utf-8', errors='ignore')
                    if "HTTP" in payload:
                        # Extract first line (e.g. GET / HTTP/1.1)
                        first_line = payload.split('\r\n')[0]
                        ip_src = pkt[IP].src if pkt.haslayer(IP) else "UNKNOWN"
                        ip_dst = pkt[IP].dst if pkt.haslayer(IP) else "UNKNOWN"
                        
                        artifact = ForensicArtifact(
                            timestamp=datetime.utcfromtimestamp(float(pkt.time)).isoformat() + "Z",
                            source_type="PCAP_HTTP",
                            host=ip_src,
                            user="NETWORK",
                            details=f"HTTP Traffic to {ip_dst}: {first_line}",
                            ioc_detected=ip_dst
                        )
                        artifacts.append(artifact)
                        
    except Exception as e:
        print(f"Error parsing PCAP {file_path}: {e}")
        
    return artifacts

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        res = parse_pcap(sys.argv[1])
        for a in res[:5]: # Print first 5
            print(a.model_dump_json(indent=2))
