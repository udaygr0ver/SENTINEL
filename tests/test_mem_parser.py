import json
from unittest.mock import MagicMock, patch

from src.parsers.mem_parser import parse_memory

# Mock output for windows.pslist
MOCK_PSLIST_JSON = json.dumps([
    {
        "PID": 4,
        "PPID": 0,
        "ImageFileName": "System",
        "CreateTime": "2026-08-19 10:00:00.000000"
    },
    {
        "PID": 1337,
        "PPID": 4,
        "ImageFileName": "mimikatz.exe",
        "CreateTime": "2026-08-19 10:05:00.000000"
    }
])

# Mock output for windows.malfind
MOCK_MALFIND_JSON = json.dumps([
    {
        "PID": 1337,
        "Process": "mimikatz.exe",
        "Protection": "PAGE_EXECUTE_READWRITE"
    }
])

# Mock output for windows.netscan
MOCK_NETSCAN_JSON = json.dumps([
    {
        "PID": 1337,
        "Proto": "TCP",
        "LocalAddr": "192.168.1.5",
        "LocalPort": 4444,
        "ForeignAddr": "10.0.0.99",
        "ForeignPort": 8080,
        "State": "ESTABLISHED"
    }
])

@patch('src.parsers.mem_parser.subprocess.run')
def test_parse_memory(mock_run, tmp_path):
    # Setup mock returns depending on the arguments
    def side_effect(*args, **kwargs):
        mock_result = MagicMock()
        mock_result.returncode = 0
        cmd = args[0]
        if "windows.pslist" in cmd:
            mock_result.stdout = MOCK_PSLIST_JSON
        elif "windows.malfind" in cmd:
            mock_result.stdout = MOCK_MALFIND_JSON
        elif "windows.netscan" in cmd:
            mock_result.stdout = MOCK_NETSCAN_JSON
        else:
            mock_result.stdout = "[]"
        return mock_result

    mock_run.side_effect = side_effect

    dummy_file = tmp_path / "dummy.raw"
    dummy_file.write_text("dummy")

    artifacts = parse_memory(str(dummy_file))
    
    assert len(artifacts) == 4 # 2 pslist, 1 malfind, 1 netscan
    
    # Check malfind artifact
    malfind_art = [a for a in artifacts if a.source_type == "MEM_MALFIND"][0]
    assert "mimikatz.exe" in malfind_art.details
    
    # Check netscan artifact
    netscan_art = [a for a in artifacts if a.source_type == "MEM_NETSCAN"][0]
    assert "10.0.0.99" in netscan_art.details
    assert netscan_art.ioc_detected == "10.0.0.99"
