# IOT notes
Sources read: OWASP IoT project pages (tab_seek_and_understand.md, tab_validate_and_test.md, index), sources/top10s/iot_map.md (UK Code of Practice and GSMA mappings), cheat sheets Drone_Security, Automotive_Security, Secure_Product_Design, Key_Management, Cryptographic_Storage, Secrets_Management, Password_Storage, Transport_Layer_Security, Pinning, Logging, Software_Supply_Chain_Security, Vulnerable_Dependency_Management, Dependency_Graph_SBOM; ATT&CK ICS (sources/attack/ics-attack.json); CWE xml.
Coverage: I1 to I10 each have 3 to 5 tests (PWD I1, NET I2, ECO I3, UPD I4, COMP I5, PRIV I6, DATA I7, MGMT I8, DEF I9, PHYS I10).
The IoT Top 10 has no per-item page on disk, only one-line descriptions, so tests use those lines plus the UK Code of Practice and GSMA rows from iot_map.md. These rows are cited in `other` as listed in iot_map.md.
## Missing sources
- OWASP IoT Security Testing Guide (ISTG) and its test cases (only a pointer in tab_validate_and_test.md)
- OWASP Firmware Security Testing Methodology (FSTM) full text (nine stages listed only)
- Official IoT Top 10 2018 PDF (link not on disk)
- ETSI EN 303 645, NIST IR 8259, IEC 62443, firmware vendor guides, UART/JTAG guides
- OWASP IoTGoat material
Tool hints (binwalk, firmwalker, flashrom, OpenOCD, nmap) are example hints only and are not cited from a source.
