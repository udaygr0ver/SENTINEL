rule Mimikatz_String_Catch
{
    meta:
        description = "Detects basic strings associated with Mimikatz credential dumping"
        author = "SENTINEL"
        severity = "High"
        mitre = "T1003"
    
    strings:
        $s1 = "mimikatz" ascii wide nocase
        $s2 = "sekurlsa::logonpasswords" ascii wide nocase
        $s3 = "lsass.exe" ascii wide nocase
        
    condition:
        2 of ($s*)
}

rule Suspicious_PowerShell_Encoded
{
    meta:
        description = "Detects base64 encoded powershell execution"
        author = "SENTINEL"
        severity = "Medium"
        mitre = "T1059.001"
        
    strings:
        $enc1 = "powershell -enc" ascii wide nocase
        $enc2 = "powershell.exe -encodedcommand" ascii wide nocase
        
    condition:
        any of ($enc*)
}
