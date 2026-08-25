rule Ransomware_Crypto_Behavior {
    meta:
        description = "Detects generic ransomware file encryption behaviors and ransom note strings"
        author = "SENTINEL Threat Intel"
        mitre = "T1486"
    strings:
        // Common Ransom Note Names
        $note1 = "READ_ME.txt" ascii wide
        $note2 = "DECRYPT_FILES.html" ascii wide
        $note3 = "HOW_TO_DECRYPT.txt" ascii wide
        
        // VSS Deletion
        $vss1 = "vssadmin.exe Delete Shadows /All /Quiet" ascii wide nocase
        $vss2 = "vssadmin delete shadows" ascii wide nocase
        $vss3 = "WMIC.exe shadowcopy delete" ascii wide nocase
        
        // Crypto / Tor
        $crypto1 = "Tor Browser" ascii wide
        $crypto2 = "bitcoin" ascii wide nocase
        $crypto3 = "AES-256" ascii wide
        $crypto4 = "RSA-2048" ascii wide
        
    condition:
        any of ($note*) or any of ($vss*) or 2 of ($crypto*)
}

rule WannaCry_Ransomware {
    meta:
        description = "Detects WannaCry Ransomware (WanaCrypt0r) specific artifacts"
        author = "SENTINEL Threat Intel"
        mitre = "T1486, T1210"
    strings:
        $s1 = "WanaCrypt0r" ascii wide
        $s2 = "!WannaDecryptor!.exe" ascii wide
        $s3 = "msg/m_english.wnry" ascii wide
        $s4 = "tasksche.exe" ascii wide
        $mutex1 = "MsWinZonesCacheCounterMutexA" ascii wide
    condition:
        2 of ($s*) or $mutex1
}
