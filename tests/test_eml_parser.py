from src.parsers.eml_parser import parse_eml


def test_parse_eml_phishing(tmp_path):
    eml_file = tmp_path / "test_phish.eml"
    
    eml_content = (
        b"From: attacker@evil-corp.com\r\n"
        b"To: victim@company.com\r\n"
        b"Subject: Action Required: Reset Your Password\r\n"
        b"Date: Mon, 12 Oct 2026 10:00:00 +0000\r\n"
        b"Authentication-Results: spf=fail dkim=fail\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"\r\n"
        b"Please click here to verify: https://evil-c2-server.com/reset-password\r\n"
    )
    
    eml_file.write_bytes(eml_content)
    
    artifacts = parse_eml(str(eml_file))
    
    assert len(artifacts) >= 2
    types = [a.source_type for a in artifacts]
    assert "EML_HEADER" in types
    assert "EML_URL" in types
    
    # Check URL artifact
    url_art = next(a for a in artifacts if a.source_type == "EML_URL")
    assert url_art.ioc_detected == "https://evil-c2-server.com/reset-password"
    assert url_art.user == "victim@company.com"
