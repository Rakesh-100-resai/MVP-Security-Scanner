/* 
=============================================================
 MVP Scanner YARA Rules - Phase 1
 Author: Internship Project
 Purpose: Catch test files, anomalies, obfuscation, and config tampering
=============================================================
*/

import "pe"

//////////////////////////////////////////////////////////////
// 1. EICAR Test Rule (for validating scanner pipeline)
//////////////////////////////////////////////////////////////
rule EICAR_Test_String {
    meta:
        description = "Detects the EICAR antivirus test file"
        author = "MVP Scanner"
        severity = "low"
        category = "test"
    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
    condition:
        $eicar
}

//////////////////////////////////////////////////////////////
// 2. Suspicious PE Files (packed, high entropy, odd sections)
//////////////////////////////////////////////////////////////
rule Suspicious_PE_File {
    meta:
        description = "Detects suspicious PE sections or packing"
        author = "MVP Scanner"
        severity = "medium"
        category = "anomaly"
    condition:
        uint16(0) == 0x5A4D and  // MZ header
        (
            pe.number_of_sections > 10 or
            pe.entry_point > filesize or
            entropy(0, filesize) > 7.5
        )
}

//////////////////////////////////////////////////////////////
// 3. Obfuscated Scripts (JS, PowerShell, etc.)
//////////////////////////////////////////////////////////////
rule Obfuscated_Script {
    meta:
        description = "Detects suspiciously obfuscated scripts"
        author = "MVP Scanner"
        severity = "medium"
        category = "obfuscation"
    strings:
        $encoded1 = /fromCharCode\(.*\)/
        $encoded2 = /[A-Za-z0-9+\/]{100,}=/
    condition:
        any of them
}

//////////////////////////////////////////////////////////////
// 4. Suspicious Config Changes (INI, YAML, conf files)
//////////////////////////////////////////////////////////////
rule Suspicious_Config_Change {
    meta:
        description = "Detects sensitive keywords or IPs in configs"
        author = "MVP Scanner"
        severity = "high"
        category = "config"
    strings:
        $pwd = "password="
        $key = "api_key="
        $ip = /([0-9]{1,3}\.){3}[0-9]{1,3}/
    condition:
        any of them
}

rule Malformed_PDF {
    meta:
        description = "Detects non-standard or corrupted PDF headers"
        author = "MVP Scanner"
        severity = "medium"
    strings:
        $pdf_header = "%PDF"
    condition:
        not $pdf_header at 0
}
