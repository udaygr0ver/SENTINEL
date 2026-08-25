rule Lateral_Movement_PsExec {
    meta:
        description = "Detects PsExec execution, often used for lateral movement"
        author = "SENTINEL Threat Intel"
        mitre = "T1569.002"
    strings:
        $s1 = "PSEXESVC.exe" ascii wide nocase
        $s2 = "psexec.exe" ascii wide nocase
        $s3 = "PsExec service" ascii wide nocase
        $s4 = "Sysinternals" ascii wide
    condition:
        2 of ($s*)
}

rule Lateral_Movement_WMI {
    meta:
        description = "Detects WMI remote execution patterns (WMIC)"
        author = "SENTINEL Threat Intel"
        mitre = "T1047"
    strings:
        $wmi1 = "wmic.exe /node:" ascii wide nocase
        $wmi2 = "process call create" ascii wide nocase
        $wmi3 = "Win32_ProcessStartTrace" ascii wide nocase
    condition:
        any of ($wmi*)
}

rule Lateral_Movement_CobaltStrike {
    meta:
        description = "Detects default Cobalt Strike Named Pipes"
        author = "SENTINEL Threat Intel"
        mitre = "T1569"
    strings:
        $pipe1 = "\\\\.\\pipe\\msagent_" ascii wide nocase
        $pipe2 = "\\\\.\\pipe\\postex_" ascii wide nocase
        $pipe3 = "\\\\.\\pipe\\status_" ascii wide nocase
        $pipe4 = "\\\\.\\pipe\\spoolss" ascii wide nocase
    condition:
        any of ($pipe*)
}
