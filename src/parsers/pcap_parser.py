from scapy.all import rdpcap, DNSQR, IP, TCP, Raw
from src.schema import ForensicArtifact
from datetime import datetime
import math
from collections import defaultdict

def shannon_entropy(data: str) -> float:
    """Calculates the Shannon entropy of a string to detect randomized/encrypted payloads."""
    if not data:
        return 0
    entropy = 0
    for x in set(data):
        p_x = float(data.count(x)) / len(data)
        entropy += - p_x * math.log(p_x, 2)
    return entropy

def parse_pcap(file_path: str):
    """Parses PCAP file to extract DNS queries, HTTP connections, and detect C2/Tunneling anomalies."""
    artifacts = []
    
    # Track connections for C2 beacon detection
    # Key: (src_ip, dst_ip, dport), Value: [timestamps]
    connections = defaultdict(list)
    
    try:
        packets = rdpcap(file_path)
        
        for pkt in packets:
            timestamp = float(pkt.time)
            dt_iso = datetime.utcfromtimestamp(timestamp).isoformat() + "Z"
            
            # 1. DNS Analysis & Tunneling Detection
            if pkt.haslayer(DNSQR):
                qname = pkt[DNSQR].qname.decode('utf-8', errors='ignore').strip('.') if pkt[DNSQR].qname else ""
                ip_src = pkt[IP].src if pkt.haslayer(IP) else "UNKNOWN"
                
                # Anomaly Detection: High entropy or unusually long subdomains often indicate DNS tunneling (e.g., Cobalt Strike, Iodine)
                entropy = shannon_entropy(qname)
                is_tunnel = entropy > 4.5 or len(qname) > 60
                
                source_type = "PCAP_DNS_TUNNEL" if is_tunnel else "PCAP_DNS"
                details = f"DNS Query: {qname}"
                if is_tunnel:
                    details += f" [ANOMALY DETECTED: High Entropy ({entropy:.2f}) / Length]"
                
                artifact = ForensicArtifact(
                    timestamp=dt_iso,
                    source_type=source_type,
                    host=ip_src,
                    user="NETWORK",
                    details=details,
                    ioc_detected=qname
                )
                artifacts.append(artifact)
                
            # 2. HTTP Analysis
            elif pkt.haslayer(TCP) and pkt.haslayer(IP):
                ip_src = pkt[IP].src
                ip_dst = pkt[IP].dst
                dport = pkt[TCP].dport
                
                # Track connection for beacon analysis
                connections[(ip_src, ip_dst, dport)].append(timestamp)
                
                if (dport == 80 or pkt[TCP].sport == 80) and pkt.haslayer(Raw):
                    payload = pkt[Raw].load.decode('utf-8', errors='ignore')
                    if "HTTP" in payload:
                        first_line = payload.split('\r\n')[0]
                        
                        artifact = ForensicArtifact(
                            timestamp=dt_iso,
                            source_type="PCAP_HTTP",
                            host=ip_src,
                            user="NETWORK",
                            details=f"HTTP Traffic to {ip_dst}: {first_line}",
                            ioc_detected=ip_dst
                        )
                        artifacts.append(artifact)
                        
        # 3. C2 Beacon Detection (Post-Processing)
        # Look for frequent connections to the same destination which might indicate a beacon
        for (src, dst, port), times in connections.items():
            if len(times) >= 5: # Threshold for demo purposes
                # Calculate average jitter/interval if we wanted to be extremely precise
                # For this MVP, volume is enough to flag suspicion
                beacon_artifact = ForensicArtifact(
                    timestamp=datetime.utcnow().isoformat() + "Z", # Synthetic artifact time
                    source_type="PCAP_C2_BEACON",
                    host=src,
                    user="NETWORK",
                    details=f"Suspected C2 Beacon: {len(times)} connections to {dst}:{port} detected.",
                    ioc_detected=dst
                )
                artifacts.append(beacon_artifact)
                        
    except Exception as e:
        print(f"Error parsing PCAP {file_path}: {e}")
        
    return artifacts

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        res = parse_pcap(sys.argv[1])
        for a in res[:5]:
            print(a.model_dump_json(indent=2))
