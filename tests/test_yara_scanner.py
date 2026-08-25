from unittest.mock import MagicMock, patch

from src.parsers.yara_scanner import scan_file


@patch('src.parsers.yara_scanner.yara')
def test_scan_file_yara(mock_yara, tmp_path):
    # Setup mock YARA rule match
    mock_rules = MagicMock()
    mock_match = MagicMock()
    mock_match.rule = "Mimikatz_String_Catch"
    mock_match.meta = {"description": "Detects mimikatz", "mitre": "T1003"}
    mock_rules.match.return_value = [mock_match]
    
    mock_yara.compile.return_value = mock_rules
    
    dummy_file = tmp_path / "malware.exe"
    dummy_file.write_text("mimikatz")
    
    artifacts = scan_file(str(dummy_file))
    
    assert len(artifacts) == 1
    art = artifacts[0]
    assert art.source_type == "YARA_MATCH"
    assert art.ioc_detected == "Mimikatz_String_Catch"
    assert "T1003" in art.details
