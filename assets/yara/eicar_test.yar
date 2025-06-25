rule EicarTest {
    meta:
        description = "EICAR Detected"
        author = "Ap3x"
        date = "2025-03-27"
    strings:
        // Detects EICAR test file(used for testing)
        $eicar_string = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

    condition:
        // Trigger if any known malware signatures, DOS mode error string, or EICAR test file string is found
        any of ($eicar_string)
}
