rule Decko_EICAR_Test_File
{
    meta:
        description = "Detects the harmless EICAR antivirus test string"
        severity = "CRITICAL"
    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" ascii
    condition:
        $eicar
}

rule Decko_Suspicious_PowerShell
{
    meta:
        description = "Detects common encoded or hidden PowerShell command patterns"
        severity = "HIGH"
    strings:
        $ps = "powershell" ascii wide nocase
        $encoded = "-enc" ascii wide nocase
        $hidden = "-w hidden" ascii wide nocase
    condition:
        $ps and any of ($encoded, $hidden)
}

rule Decko_Process_Injection_APIs
{
    meta:
        description = "Detects a combination of Windows process-injection API names"
        severity = "HIGH"
    strings:
        $a1 = "VirtualAllocEx" ascii wide
        $a2 = "WriteProcessMemory" ascii wide
        $a3 = "CreateRemoteThread" ascii wide
    condition:
        2 of ($a*)
}

rule Decko_PHP_Command_Execution
{
    meta:
        description = "Detects common PHP command-execution web-shell patterns"
        severity = "HIGH"
    strings:
        $php = "<?php" ascii nocase
        $system = "system(" ascii nocase
        $eval = "eval(base64_decode" ascii nocase
    condition:
        ($php and $system) or $eval
}
