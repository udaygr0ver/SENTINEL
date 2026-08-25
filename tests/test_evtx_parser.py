from unittest.mock import patch, MagicMock
from src.parsers.evtx_parser import parse_evtx

MOCK_XML_4688 = """
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>4688</EventID>
    <TimeCreated SystemTime="2026-08-19T10:15:30.000000Z" />
    <Computer>WORKSTATION-01</Computer>
  </System>
  <EventData>
    <Data Name="SubjectUserName">Admin</Data>
    <Data Name="NewProcessName">C:\\Windows\\System32\\cmd.exe</Data>
    <Data Name="CommandLine">cmd.exe /c powershell -enc JABz...=</Data>
  </EventData>
</Event>
"""

MOCK_XML_4624 = """
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>4624</EventID>
    <TimeCreated SystemTime="2026-08-19T10:10:00.000000Z" />
    <Computer>WORKSTATION-01</Computer>
  </System>
  <EventData>
    <Data Name="TargetUserName">Admin</Data>
    <Data Name="LogonType">3</Data>
    <Data Name="IpAddress">10.0.0.50</Data>
  </EventData>
</Event>
"""

@patch('src.parsers.evtx_parser.Evtx')
def test_parse_evtx(mock_evtx_class):
    # Setup mock EVTX records
    mock_log = MagicMock()
    
    mock_record_1 = MagicMock()
    mock_record_1.xml.return_value = MOCK_XML_4688
    
    mock_record_2 = MagicMock()
    mock_record_2.xml.return_value = MOCK_XML_4624
    
    mock_log.records.return_value = [mock_record_1, mock_record_2]
    
    # Evtx is used as a context manager: with Evtx(...) as log:
    mock_evtx_class.return_value.__enter__.return_value = mock_log
    
    artifacts = parse_evtx("dummy.evtx")
    
    assert len(artifacts) == 2
    
    art1 = artifacts[0]
    assert art1.source_type == "EVTX_4688"
    assert art1.host == "WORKSTATION-01"
    assert art1.user == "Admin"
    assert "cmd.exe /c powershell" in art1.details
    
    art2 = artifacts[1]
    assert art2.source_type == "EVTX_4624"
    assert art2.ioc_detected == "10.0.0.50"
    assert "Logon Type: 3" in art2.details
