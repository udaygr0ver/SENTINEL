import os
from unittest.mock import patch, MagicMock
from src.parsers.pcap_parser import parse_pcap
from scapy.all import IP, TCP, UDP, DNS, DNSQR, wrpcap, Raw

def test_parse_pcap_success(tmp_path):
    pcap_file = tmp_path / "mock.cap"
    
    pkt1 = IP(src='192.168.1.100', dst='10.0.0.5')/TCP(sport=12345, dport=80)/Raw(load='GET /login HTTP/1.1\r\nHost: 10.0.0.5\r\n\r\n')
    pkt2 = IP(src='10.0.0.5', dst='192.168.1.100')/TCP(sport=80, dport=12345)/Raw(load='HTTP/1.1 200 OK\r\n\r\n')
    
    wrpcap(str(pcap_file), [pkt1, pkt2])
    
    artifacts = parse_pcap(str(pcap_file))
    assert len(artifacts) == 2
    
def test_parse_pcap_dns_tunneling(tmp_path):
    pcap_file = tmp_path / "dns_tunnel.cap"
    
    # Very high entropy / long string typical of Iodine/DNSCat2
    long_subdomain = "xksjdfhsjdkfhsjkdhfjshdfjksdhfjksdhfjsdhfjksdhfjsdhfjsdhfjsdf.evil.com"
    
    pkt_dns = IP(src='192.168.1.100', dst='8.8.8.8')/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=long_subdomain))
    
    wrpcap(str(pcap_file), [pkt_dns])
    
    artifacts = parse_pcap(str(pcap_file))
    
    assert len(artifacts) == 1
    art = artifacts[0]
    assert art.source_type == "PCAP_DNS_TUNNEL"
    assert "ANOMALY DETECTED" in art.details

def test_parse_pcap_c2_beacon(tmp_path):
    pcap_file = tmp_path / "c2_beacon.cap"
    
    # Generate 6 packets to the same destination
    pkts = []
    for _ in range(6):
        pkts.append(IP(src='192.168.1.50', dst='103.45.67.89')/TCP(sport=50000, dport=443))
        
    wrpcap(str(pcap_file), pkts)
    
    artifacts = parse_pcap(str(pcap_file))
    
    # We expect 1 C2 beacon artifact (no HTTP artifacts because no payload)
    assert len(artifacts) == 1
    art = artifacts[0]
    assert art.source_type == "PCAP_C2_BEACON"
    assert "103.45.67.89:443" in art.details
    assert "6 connections" in art.details
    
def test_parse_pcap_invalid_file():
    artifacts = parse_pcap("non_existent_file.cap")
    assert artifacts == []
