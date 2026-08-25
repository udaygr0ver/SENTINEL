import os
from unittest.mock import patch, MagicMock
from src.parsers.pcap_parser import parse_pcap
from scapy.all import IP, TCP, wrpcap, Raw

def test_parse_pcap_success(tmp_path):
    # Generate a mock PCAP file with known HTTP and non-HTTP traffic
    pcap_file = tmp_path / "mock.cap"
    
    pkt1 = IP(src='192.168.1.100', dst='10.0.0.5')/TCP(sport=12345, dport=80)/Raw(load='GET /login HTTP/1.1\r\nHost: 10.0.0.5\r\n\r\n')
    pkt2 = IP(src='10.0.0.5', dst='192.168.1.100')/TCP(sport=80, dport=12345)/Raw(load='HTTP/1.1 200 OK\r\n\r\n')
    pkt3 = IP(src='192.168.1.100', dst='10.0.0.5')/TCP(sport=12346, dport=443)/Raw(load='Encrypted data') # Should be ignored
    
    wrpcap(str(pcap_file), [pkt1, pkt2, pkt3])
    
    artifacts = parse_pcap(str(pcap_file))
    
    # We expect 2 artifacts (the HTTP ones)
    assert len(artifacts) == 2
    
    art1 = artifacts[0]
    assert art1.source_type == "PCAP_HTTP"
    assert art1.host == "192.168.1.100"
    assert art1.ioc_detected == "10.0.0.5"
    assert "GET /login HTTP/1.1" in art1.details

def test_parse_pcap_invalid_file():
    # Test with a non-existent file or invalid file
    artifacts = parse_pcap("non_existent_file.cap")
    assert artifacts == []
