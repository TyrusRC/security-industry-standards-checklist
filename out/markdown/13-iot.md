# IOT security test cases

46 tests. Tick the box when the test passes.


## COMP

- [ ] **IOT-COMP-001** Make a component list from the firmware and find known vulnerabilities  
  *Severity if fail:* High | *Type:* Automated, Manual  
  *Objective:* Finds old kernels, libraries and daemons in the image.  
  *Steps:*
  1. Unpack the firmware.
  2. List the kernel, libc, web server, TLS library and other packages with versions.
  3. Compare each version with vulnerability databases.
  4. Record the fix status.
  *Example:* `binwalk -e fw.bin; syft dir:_fw.bin.extracted; grype dir:_fw.bin.extracted; uname banner in the kernel.`  
  *Expected:* No component has a known unpatched critical or high vulnerability. The vendor keeps a component list for each release.  
  *Refs:* other: GSMA CLP13_7.11; cwe: CWE-1395, CWE-1104; cheatsheet: Vulnerable_Dependency_Management_Cheat_Sheet, Dependency_Graph_SBOM_Cheat_Sheet; iot_top10: I5  
  *See:* WEB-DEP-002, WEB-DEP-003

- [ ] **IOT-COMP-002** Check for unmaintained or unsupported components  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds parts that no longer get fixes.  
  *Steps:*
  1. List the end-of-life dates of the OS, kernel and libraries.
  2. Mark unsupported items.
  3. Check the replacement plan.
  4. Check which items cannot be updated.
  *Example:* `Document review plus version dates; compare with the vendor support policy.`  
  *Expected:* No unsupported component is in use, or the vendor limits its exposure and plans its replacement.  
  *Refs:* cwe: CWE-1104, CWE-1329; cheatsheet: Automotive_Security_Cheat_Sheet, Vulnerable_Dependency_Management_Cheat_Sheet; iot_top10: I5

- [ ] **IOT-COMP-003** Review the supply chain of hardware and software parts  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds untrusted suppliers and changed parts.  
  *Steps:*
  1. List the chips, modules and third-party software.
  2. Ask for the supplier security terms and patch ownership.
  3. Compare the delivered part with the specification.
  4. Check the code and hardware signing of the supplier.
  *Example:* `Document review; hash compare of supplier firmware blobs with the vendor list.`  
  *Expected:* Suppliers are assessed. Patch ownership and support periods are set in contracts. Delivered parts match the specification.  
  *Refs:* other: GSMA CLP13_9.7; cheatsheet: Software_Supply_Chain_Security_Cheat_Sheet, Drone_Security_Cheat_Sheet; attack: T0862; iot_top10: I5, I10  
  *See:* WEB-DEP-005

- [ ] **IOT-COMP-004** Check OS hardening and process privileges on the device  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds root-only designs, missing sandbox and weak file rights.  
  *Steps:*
  1. Get a shell on a lab unit.
  2. List the running processes and users.
  3. Check file rights and writable system paths.
  4. Check the kernel and OS hardening options.
  *Example:* `ps; ls -l; find / -perm -4000; checksec --kernel; mount output for read-only flags.`  
  *Expected:* Services run as non-root users with the least rights. System partitions are read-only where possible.  
  *Refs:* other: GSMA CLP13_8.1; cwe: CWE-250, CWE-732; cheatsheet: Secure_Product_Design_Cheat_Sheet; iot_top10: I5, I9


## DATA

- [ ] **IOT-DATA-001** Capture device traffic and find clear-text data  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds data sent without encryption on any link.  
  *Steps:*
  1. Capture traffic of the device on Wi-Fi, Ethernet and any radio.
  2. List protocols and ports.
  3. Look for credentials, tokens and data in clear text.
  4. Check MQTT, CoAP and HTTP use.
  *Example:* `Wireshark filter mqtt or coap or http; tshark -Y "http" -r cap.pcap.`  
  *Expected:* All data in transit uses TLS, DTLS or an equal secure protocol. No credential or user data appears in clear text.  
  *Refs:* other: UK Code of Practice for Consumer IoT Security provision 5, as listed in iot_map.md, GSMA CLP13_6.19; cwe: CWE-319; cheatsheet: Transport_Layer_Security_Cheat_Sheet; attack: T0842, T0830; iot_top10: I7  
  *See:* WEB-TLS-006

- [ ] **IOT-DATA-002** Test certificate validation and TLS settings of the device  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds devices that accept any certificate or old TLS versions.  
  *Steps:*
  1. Route device traffic through a proxy with a lab CA.
  2. Check if the device connects.
  3. Use an expired certificate and a wrong host name.
  4. Scan the cloud endpoint for protocol versions.
  *Example:* `mitmproxy with a lab CA; testssl.sh on the endpoint.`  
  *Expected:* The device refuses untrusted certificates. Only TLS 1.2 and TLS 1.3 with strong ciphers are used.  
  *Refs:* cwe: CWE-295, CWE-297; cheatsheet: Pinning_Cheat_Sheet, Transport_Layer_Security_Cheat_Sheet; iot_top10: I7, I3  
  *See:* WEB-TLS-010

- [ ] **IOT-DATA-003** Check sensitive data and keys in flash storage  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds secrets and personal data stored in clear text on the device.  
  *Steps:*
  1. Dump the flash of a lab unit.
  2. Unpack the file systems.
  3. Search for keys, tokens, Wi-Fi passwords and user data.
  4. Check if the storage is encrypted.
  *Example:* `flashrom -r dump.bin; binwalk -e dump.bin; strings; grep -r "BEGIN" _dump.bin.extracted.`  
  *Expected:* Secrets and personal data are encrypted or kept in a secure element. No clear key is in the flash.  
  *Refs:* other: GSMA CLP13_7.1; cwe: CWE-312, CWE-922, CWE-321; cheatsheet: Cryptographic_Storage_Cheat_Sheet, Key_Management_Cheat_Sheet, Drone_Security_Cheat_Sheet; attack: T0893; iot_top10: I7, I10  
  *See:* WEB-DATA-013

- [ ] **IOT-DATA-004** Check cryptographic algorithms, key size and random source  
  *Severity if fail:* Medium | *Type:* Manual, Code Review  
  *Objective:* Finds weak algorithms and poor random numbers.  
  *Steps:*
  1. List the crypto libraries and calls in the firmware.
  2. Check the algorithms, modes and key sizes.
  3. Check the random source and its entropy at boot.
  4. Check key use per device.
  *Example:* `strings and Ghidra search for rand(), MD5, DES, ECB; ent on random output from a lab unit.`  
  *Expected:* The device uses approved algorithms and a hardware or CSPRNG random source. Keys are unique per device.  
  *Refs:* other: GSMA CLP13_6.10, GSMA CLP12_6.2; cwe: CWE-327, CWE-330, CWE-338; cheatsheet: Key_Management_Cheat_Sheet, Cryptographic_Storage_Cheat_Sheet; iot_top10: I7  
  *See:* WEB-CRYPTO-014

- [ ] **IOT-DATA-005** Check the logging of the device for sensitive data  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds logs and diagnostic output with credentials or user data.  
  *Steps:*
  1. Turn on default logging.
  2. Use all main functions.
  3. Read the logs from the console, files and cloud.
  4. Search for secrets and personal data.
  *Example:* `logread; dmesg; serial console capture; grep for token and password.`  
  *Expected:* Logs hold no credentials or personal data. Diagnostic output is off or protected in production.  
  *Refs:* cwe: CWE-532, CWE-215; cheatsheet: Logging_Cheat_Sheet, Automotive_Security_Cheat_Sheet; iot_top10: I7, I6  
  *See:* WEB-LOG-006


## DEF

- [ ] **IOT-DEF-001** Review the out-of-box configuration of the device  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds insecure defaults such as open services, debug mode and weak encryption.  
  *Steps:*
  1. Reset a lab unit to factory state.
  2. Scan ports and read the default settings.
  3. List all features that are on by default.
  4. Compare with the minimum needed.
  *Example:* `nmap -p- after reset; export of the default config.`  
  *Expected:* Defaults are secure. Unneeded features are off, encryption is on and setup forces a new credential.  
  *Refs:* other: UK Code of Practice for Consumer IoT Security provision 12, as listed in iot_map.md; cwe: CWE-1188, CWE-1392; cheatsheet: Secure_Product_Design_Cheat_Sheet; iot_top10: I9  
  *See:* MOB-PRIV-011

- [ ] **IOT-DEF-002** Check who can change security settings on the device  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds devices that do not let operators harden them or that let users weaken them.  
  *Steps:*
  1. List the security settings in the interface.
  2. Change each setting as owner and as a limited user.
  3. Check that a limited user cannot weaken them.
  4. Check the audit entry for each change.
  *Example:* `Web interface review; API calls with low-privilege tokens.`  
  *Expected:* Operators can raise security settings. Only authorized roles can change them and each change is logged.  
  *Refs:* other: GSMA CLP12_8.4; cwe: CWE-269, CWE-732; cheatsheet: Secure_Product_Design_Cheat_Sheet; iot_top10: I9

- [ ] **IOT-DEF-003** Check that debug interfaces and test features are off in production  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds enabled UART consoles, JTAG, test accounts and debug services.  
  *Steps:*
  1. Open the case of a lab unit.
  2. Find UART and JTAG pads.
  3. Connect a logic adapter and watch the boot output.
  4. Try to get a shell or debug access.
  *Example:* `Identify pins with a multimeter; screen /dev/ttyUSB0 115200; OpenOCD on a lab unit only.`  
  *Expected:* Production units give no shell or debug access on UART or JTAG without authentication. Debug services are off.  
  *Refs:* other: GSMA CLP13_8.2; cwe: CWE-489, CWE-1191, CWE-1244; cheatsheet: Automotive_Security_Cheat_Sheet; iot_top10: I9, I10

- [ ] **IOT-DEF-004** Test secure boot and image signing  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds devices that boot unsigned code.  
  *Steps:*
  1. Read the boot chain description.
  2. Write a changed image to a lab unit.
  3. Boot the unit.
  4. Check that the first stage is in ROM or locked.
  *Example:* `Programmer or bootloader console on a lab unit; read the fuse state if documented.`  
  *Expected:* Each boot stage checks the signature of the next. The device refuses to boot a changed image.  
  *Refs:* other: GSMA CLP13_6.15, GSMA CLP13_6.3, UK Code of Practice for Consumer IoT Security provision 7, as listed in iot_map.md; cwe: CWE-345, CWE-347; cheatsheet: Drone_Security_Cheat_Sheet, Automotive_Security_Cheat_Sheet; attack: T1693.001; iot_top10: I9, I10

- [ ] **IOT-DEF-005** Check removable media and autorun behavior  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds devices that run or import code from USB or SD cards.  
  *Steps:*
  1. Insert a USB drive or SD card with a harmless marker script.
  2. Watch the device.
  3. Check import and update from media.
  4. Check for signature checks on media content.
  *Example:* `Marker script that only writes a file; serial console log.`  
  *Expected:* The device does not run code from media. Updates from media need a valid signature.  
  *Refs:* cheatsheet: Drone_Security_Cheat_Sheet; attack: T0895, T0847; iot_top10: I9, I10


## ECO

- [ ] **IOT-ECO-001** Test the device web interface for authentication and input flaws  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds missing login, injection and XSS in the device web interface.  
  *Steps:*
  1. Map every page and request of the web interface.
  2. Call each admin request without a login.
  3. Send special characters in each field.
  4. Check the cookie and header settings.
  *Example:* `Burp Suite; commix only in a lab for command injection checks.`  
  *Expected:* Every request needs authentication and authorization. Input is validated. The interface has no injection flaw.  
  *Refs:* other: UK Code of Practice for Consumer IoT Security provision 13, as listed in iot_map.md, GSMA CLP12_6.9; cwe: CWE-306, CWE-78, CWE-79; attack: T0819; iot_top10: I3

- [ ] **IOT-ECO-002** Test the cloud and back-end API used by the device  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds API calls that expose other devices or users.  
  *Steps:*
  1. Capture the API calls of the device and the app.
  2. Change the device ID in each call.
  3. Replay calls with a token from another account.
  4. Check the responses for other data.
  *Example:* `Burp Repeater; compare the responses for device A and device B.`  
  *Expected:* The API checks that the caller owns the device. Changed IDs give an error and no data.  
  *Refs:* other: GSMA CLP12_6.8, GSMA CLP12_6.12; cwe: CWE-862, CWE-863; iot_top10: I3

- [ ] **IOT-ECO-003** Check the companion mobile app and the device for shared trust  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds mobile app flows that let a user take control of a device they do not own.  
  *Steps:*
  1. Pair a lab device with account A.
  2. Try to pair or control it with account B.
  3. Check the ownership change and reset steps.
  4. Check what the old owner can still do.
  *Example:* `Burp Suite on the app; Frida only on a lab device; the mobile app tests are in the MOB sheet.`  
  *Expected:* Only the owner can control the device. An ownership change removes the access of the old owner.  
  *Refs:* cwe: CWE-863; cheatsheet: Automotive_Security_Cheat_Sheet; iot_top10: I3

- [ ] **IOT-ECO-004** Check input validation and output filtering on all device interfaces  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds interfaces that act on data without a check of type, length and range.  
  *Steps:*
  1. List all input paths: API, radio, serial, file.
  2. Send out-of-range and wrong-type values.
  3. Check the state in which the action is allowed.
  4. Check the output for internal data.
  *Example:* `Protocol client scripts for MQTT, CoAP or HTTP; compare the responses.`  
  *Expected:* The device checks type, length, range and state before it acts. Errors show no internal data.  
  *Refs:* other: UK Code of Practice for Consumer IoT Security provision 13, as listed in iot_map.md, GSMA CLP12_6.10; cwe: CWE-120; cheatsheet: Automotive_Security_Cheat_Sheet; iot_top10: I3

- [ ] **IOT-ECO-005** Test command messages for replay and spoofing  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds control messages that an attacker can copy and send again.  
  *Steps:*
  1. Capture a command message such as lock or open.
  2. Send it again later from another host.
  3. Change a field and send it with the old signature.
  4. Check for a counter or timestamp check.
  *Example:* `Wireshark capture; scapy or mosquitto_pub replay in a lab.`  
  *Expected:* The device rejects replayed, changed and unauthenticated commands.  
  *Refs:* cwe: CWE-345, CWE-353; cheatsheet: Drone_Security_Cheat_Sheet, Automotive_Security_Cheat_Sheet; attack: T1692, T0830; iot_top10: I3, I7


## MGMT

- [ ] **IOT-MGMT-001** Check the device inventory and the remote management channel  
  *Severity if fail:* Medium | *Type:* Config Review, Manual  
  *Objective:* Finds fleets that have no asset list and unauthenticated remote management.  
  *Steps:*
  1. Ask for the device inventory process.
  2. Find the remote management service.
  3. Test the authentication on the channel.
  4. Test whether one command reaches one device only.
  *Example:* `Document review plus a lab connection to the management service with a test token.`  
  *Expected:* The operator knows every device and its version. Remote management needs strong authentication and is logged.  
  *Refs:* other: GSMA CLP13_6.12, GSMA CLP12_5.7; cwe: CWE-306; attack: T0822, T0859; iot_top10: I8

- [ ] **IOT-MGMT-002** Check device monitoring, anomaly alerts and incident response  
  *Severity if fail:* Medium | *Type:* Manual, Config Review  
  *Objective:* Finds fleets where attacks produce no alert.  
  *Steps:*
  1. List the telemetry and logs the cloud receives.
  2. Make a test event: failed logins and a config change.
  3. Check that an alert fires.
  4. Check the incident response contact for the product.
  *Example:* `SIEM or cloud monitor rule list; test alert time.`  
  *Expected:* Security events create alerts. A response plan and a vulnerability disclosure contact exist.  
  *Refs:* other: GSMA CLP12_5.8, GSMA CLP13_7.2, UK Code of Practice for Consumer IoT Security provision 2 and 10, as listed in iot_map.md; cwe: CWE-778; cheatsheet: Logging_Cheat_Sheet, Automotive_Security_Cheat_Sheet; iot_top10: I8  
  *See:* WEB-LOG-014

- [ ] **IOT-MGMT-003** Test secure decommissioning and credential revocation  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds retired devices that keep access to the cloud.  
  *Steps:*
  1. Register a lab device.
  2. Remove it in the cloud console.
  3. Try to connect with its credentials.
  4. Check that the device wipes local keys.
  *Example:* `Replay the device token after removal; read the device storage after the wipe.`  
  *Expected:* A removed device loses all cloud access at once. Local keys and data are wiped.  
  *Refs:* other: GSMA CLP13_8.10; cwe: CWE-522; cheatsheet: Key_Management_Cheat_Sheet, Drone_Security_Cheat_Sheet; iot_top10: I8, I6

- [ ] **IOT-MGMT-004** Check behaviour of the device when the network or power fails  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds devices that fail open or lose their security state.  
  *Steps:*
  1. Cut the network on a lab unit.
  2. Check local functions and security checks.
  3. Cut and restore power.
  4. Check that the device returns to a safe state.
  *Example:* `Disconnect the uplink; power cycle with a controllable switch.`  
  *Expected:* The device keeps its security settings. It fails safe and joins the network again in an orderly way.  
  *Refs:* other: UK Code of Practice for Consumer IoT Security provision 9, as listed in iot_map.md, GSMA CLP13_8.9; cwe: CWE-693; cheatsheet: Secure_Product_Design_Cheat_Sheet, Automotive_Security_Cheat_Sheet; iot_top10: I8, I9


## NET

- [ ] **IOT-NET-001** Scan the device for open ports and unneeded services  
  *Severity if fail:* High | *Type:* Automated, Manual  
  *Objective:* Finds services that the device does not need, such as Telnet, FTP and debug daemons.  
  *Steps:*
  1. Power the device on a lab network.
  2. Scan all TCP and UDP ports.
  3. List each service and its version.
  4. Compare with the documented service list.
  *Example:* `nmap -sS -sU -p- -sV --top-ports 1000 device; masscan on a lab range only.`  
  *Expected:* Only documented services listen. Telnet, FTP and debug services are off. Each service needs authentication.  
  *Refs:* other: UK Code of Practice for Consumer IoT Security provision 6, as listed in iot_map.md; cwe: CWE-306, CWE-1188; attack: T0883, T0866; iot_top10: I2

- [ ] **IOT-NET-002** Check the services of the device for known vulnerable versions  
  *Severity if fail:* High | *Type:* Automated  
  *Objective:* Finds old daemons with public vulnerabilities.  
  *Steps:*
  1. Read the version banner of each service.
  2. Check each version in vulnerability databases.
  3. Check for unpatched web server and UPnP builds.
  4. Record the fixed version.
  *Example:* `nmap -sV --script vulners device; compare with NVD.`  
  *Expected:* No service version has a known unpatched vulnerability.  
  *Refs:* cwe: CWE-1395; cheatsheet: Vulnerable_Dependency_Management_Cheat_Sheet; attack: T0866, T0819; iot_top10: I2, I5  
  *See:* WEB-DEP-003

- [ ] **IOT-NET-003** Test the device for exposure to the internet  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds devices that open ports to the internet through UPnP or default NAT rules.  
  *Steps:*
  1. Check if the device asks the router to open ports.
  2. Scan the public address of the lab network from outside.
  3. Check for cloud relay use instead of inbound ports.
  4. Record each reachable service.
  *Example:* `upnpc -l on the lab network; external nmap scan of the lab WAN address.`  
  *Expected:* The device opens no inbound port to the internet. Remote access uses an authenticated outbound cloud channel.  
  *Refs:* cwe: CWE-306; attack: T0883, T0822; iot_top10: I2

- [ ] **IOT-NET-004** Test network services with malformed input and long input  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds crashes and memory errors in the parsers of the device.  
  *Steps:*
  1. Pick one network service.
  2. Send over-long and malformed fields in a lab.
  3. Watch the device for crash, reboot or hang.
  4. Record the input that caused it.
  *Example:* `Boofuzz or a protocol fuzzer on a lab device; serial console log for crash traces.`  
  *Expected:* The service rejects bad input with an error. The device does not crash or reboot.  
  *Refs:* cwe: CWE-120, CWE-787, CWE-125; attack: T0814; iot_top10: I2

- [ ] **IOT-NET-005** Check wireless interfaces for weak pairing and open access  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds Wi-Fi, Bluetooth and radio links with weak pairing or no encryption.  
  *Steps:*
  1. List all radio interfaces of the device.
  2. Capture the pairing and the data with a sniffer.
  3. Check the encryption and the pairing method.
  4. Try to join without a user action.
  *Example:* `Wireshark with a monitor mode adapter; Bluetooth sniffer; nRF Sniffer on a lab device.`  
  *Expected:* Radio links use encryption and authenticated pairing. The device does not join or pair without a user action.  
  *Refs:* cwe: CWE-319; cheatsheet: Drone_Security_Cheat_Sheet; attack: T0887, T0830; iot_top10: I2, I7


## PHYS

- [ ] **IOT-PHYS-001** Review the casing, ports and tamper protection of the device  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds exposed ports and a casing that gives easy access to the board.  
  *Steps:*
  1. List all external ports and buttons.
  2. Open the casing.
  3. Check for tamper switches and seals.
  4. Check for labeled debug pads.
  *Example:* `Visual inspection with a camera and a multimeter.`  
  *Expected:* Unused ports are closed. The casing shows tamper evidence. Debug pads are removed or locked.  
  *Refs:* other: GSMA CLP13_7.3; cheatsheet: Drone_Security_Cheat_Sheet; iot_top10: I10

- [ ] **IOT-PHYS-002** Test flash and memory extraction  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds devices where an attacker can read the firmware and secrets from the chip.  
  *Steps:*
  1. Identify the flash chip.
  2. Try an in-circuit read in a lab.
  3. Check the dump for clear data.
  4. Check read-out protection fuses.
  *Example:* `flashrom with a clip programmer; binwalk on the dump.`  
  *Expected:* Read-out protection or storage encryption stops the use of a dump. Secrets are not in clear text.  
  *Refs:* other: GSMA CLP13_7.1, GSMA CLP13_9.4; cwe: CWE-312, CWE-1191; cheatsheet: Drone_Security_Cheat_Sheet, Cryptographic_Storage_Cheat_Sheet; attack: T0893; iot_top10: I10, I7

- [ ] **IOT-PHYS-003** Test the physical access of lost or captured devices to cloud accounts  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds devices that give a finder access to the account or network.  
  *Steps:*
  1. Take a lab device with a paired account.
  2. Read stored tokens and Wi-Fi settings.
  3. Use them from another host.
  4. Check the revocation steps for the owner.
  *Example:* `Extract the tokens from the lab dump; replay them against the lab cloud.`  
  *Expected:* A stolen device does not give lasting access. The owner can revoke the device and its tokens.  
  *Refs:* cwe: CWE-922, CWE-522; cheatsheet: Drone_Security_Cheat_Sheet, Automotive_Security_Cheat_Sheet; attack: T0859; iot_top10: I10, I8

- [ ] **IOT-PHYS-004** Check side channels and fault injection protection for high-risk devices  
  *Severity if fail:* Info | *Type:* Config Review  
  *Objective:* Finds secrets that leak through power analysis or glitches.  
  *Steps:*
  1. Decide if the threat model includes lab attackers.
  2. Check the secure element or crypto chip data sheet.
  3. Check for glitch and temperature monitors.
  4. Review any lab test report.
  *Example:* `Document review: certification reports, chip data sheets.`  
  *Expected:* Devices with high risk use certified secure elements. The vendor holds a test report.  
  *Refs:* other: GSMA CLP13_9.6, GSMA CLP13_9.3; iot_top10: I10


## PRIV

- [ ] **IOT-PRIV-001** Map the personal data that the device and its cloud collect  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds data that the device collects without need or without notice.  
  *Steps:*
  1. Capture device, app and cloud traffic during normal use.
  2. List all data types: audio, video, location, identifiers.
  3. Compare with the privacy notice.
  4. Mark data without a stated purpose.
  *Example:* `Wireshark and mitmproxy in a lab; field list against the notice.`  
  *Expected:* The device sends only data that is needed and named in the notice. Sensors do not record without a user signal.  
  *Refs:* other: UK Code of Practice for Consumer IoT Security provision 8, as listed in iot_map.md, GSMA CLP11_6; cwe: CWE-359, CWE-201; iot_top10: I6  
  *See:* MOB-PRIV-004

- [ ] **IOT-PRIV-002** Test removal of personal data at factory reset and transfer of ownership  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds data that stays on a device after reset or sale.  
  *Steps:*
  1. Fill a lab device with test user data.
  2. Do a factory reset.
  3. Read the flash with a programmer or from a shell.
  4. Search the dump for the test data.
  *Example:* `Dump flash with flashrom or a serial shell; strings and grep for test data.`  
  *Expected:* A factory reset removes all personal data and credentials. Users get clear steps to delete data.  
  *Refs:* other: UK Code of Practice for Consumer IoT Security provision 11, as listed in iot_map.md, GSMA CLP13_8.10; cwe: CWE-212, CWE-312; cheatsheet: Drone_Security_Cheat_Sheet; iot_top10: I6, I8

- [ ] **IOT-PRIV-003** Check unique device identifiers and metadata for tracking  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds identifiers that let others track users.  
  *Steps:*
  1. Capture radio and cloud traffic.
  2. Look for fixed MAC, serial and device ID values.
  3. Compare the values over time and place.
  4. Check what third parties receive.
  *Example:* `Wireshark; Bluetooth sniffer for static addresses.`  
  *Expected:* Identifiers are random or rotate where possible. Metadata is not shared without a stated need.  
  *Refs:* other: GSMA CLP13_7.8, GSMA CLP13_8.11; cwe: CWE-359; iot_top10: I6

- [ ] **IOT-PRIV-004** Check consent, privacy controls and third-party sharing for the device  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds sharing with partners without consent and no control for the user.  
  *Steps:*
  1. Read the setup flow for consent steps.
  2. Look for privacy settings in the app.
  3. Capture traffic to third-party hosts.
  4. Withdraw consent and capture again.
  *Example:* `mitmproxy host list before and after consent change.`  
  *Expected:* Users can give and withdraw consent. Sharing with third parties stops after withdrawal.  
  *Refs:* other: UK Code of Practice for Consumer IoT Security provision 8, as listed in iot_map.md, GSMA CLP12_7.4, GSMA CLP12_8.3; cwe: CWE-359; iot_top10: I6  
  *See:* PRIV-CONSENT-003, PRIV-SHARE-001


## PWD

- [ ] **IOT-PWD-001** Find default and shared credentials on the device  
  *Severity if fail:* Critical | *Type:* Manual  
  *Objective:* Finds devices that ship with the same login on every unit.  
  *Steps:*
  1. Read the quick start guide and the label for default logins.
  2. Log in to each interface with the default login.
  3. Reset two devices to factory state.
  4. Compare the credentials of the two devices.
  *Example:* `nmap -sV -p- device; hydra is not needed: try only the vendor documented login on a lab unit.`  
  *Expected:* Each device has a unique credential or forces a new one at first use. A reset never restores a shared default.  
  *Refs:* other: UK Code of Practice for Consumer IoT Security provision 1, as listed in iot_map.md, GSMA CLP13_6.8; cwe: CWE-1392, CWE-1393, CWE-1391; attack: T1694.001; iot_top10: I1, I9

- [ ] **IOT-PWD-002** Search the firmware for hard-coded passwords and keys  
  *Severity if fail:* Critical | *Type:* Manual, Automated  
  *Objective:* Finds credentials and backdoor accounts inside the firmware image.  
  *Steps:*
  1. Get the firmware image from the vendor site or the device.
  2. Unpack it with binwalk -e.
  3. Search the files for passwd, shadow, keys and strings.
  4. Test each found account on a lab device.
  *Example:* `binwalk -e fw.bin; firmwalker.sh _fw.bin.extracted; strings -n 8 bin/* | grep -i pass; cat etc/shadow.`  
  *Expected:* The firmware holds no hard-coded password, key or backdoor account. All secrets are made per device.  
  *Refs:* other: UK Code of Practice for Consumer IoT Security provision 4, as listed in iot_map.md; cwe: CWE-798, CWE-259, CWE-321; cheatsheet: Key_Management_Cheat_Sheet, Secrets_Management_Cheat_Sheet; attack: T1694.002; iot_top10: I1, I7  
  *See:* WEB-CRYPTO-018

- [ ] **IOT-PWD-003** Test password policy and lock-out on the device interfaces  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds weak passwords and unlimited guessing on web, SSH and Telnet.  
  *Steps:*
  1. List every interface that accepts a password.
  2. Set a short and a common password.
  3. Send 20 wrong logins in a row to a lab unit.
  4. Check for a delay, a lock or an alert.
  *Example:* `Burp Intruder at low rate on the device web login; nmap --script ssh-auth-methods.`  
  *Expected:* The device rejects weak passwords. Repeated wrong logins cause a delay or a lock.  
  *Refs:* cwe: CWE-1391; cheatsheet: Password_Storage_Cheat_Sheet; attack: T0859; iot_top10: I1

- [ ] **IOT-PWD-004** Check how the device stores and checks user passwords  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds clear text and weak hashes in device databases.  
  *Steps:*
  1. Find the password file or database in the extracted firmware.
  2. Read the stored value format.
  3. Identify the hash type and salt.
  4. Check the hash cost.
  *Example:* `cat etc/shadow; sqlite3 config.db .dump; look for crypt prefixes $1$, $5$, $6$, $y$.`  
  *Expected:* Passwords are stored with a salted, slow hash such as Argon2id, bcrypt or PBKDF2.  
  *Refs:* cwe: CWE-256, CWE-257, CWE-916; cheatsheet: Password_Storage_Cheat_Sheet; iot_top10: I1, I7  
  *See:* WEB-CRYPTO-013

- [ ] **IOT-PWD-005** Check device-to-cloud identity and mutual authentication  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds devices that share one cloud key or do not prove their identity.  
  *Steps:*
  1. Capture the device enrollment.
  2. Compare the device credentials of two units.
  3. Present one device credential from another device in a lab.
  4. Check that the cloud rejects the copy.
  *Example:* `Wireshark and a lab proxy; compare client certificates or tokens of two devices.`  
  *Expected:* Each device has its own identity. The cloud rejects a credential that comes from a different unit or is revoked.  
  *Refs:* other: GSMA CLP13_6.20, GSMA CLP13_7.6; cwe: CWE-306, CWE-798; iot_top10: I1, I3


## UPD

- [ ] **IOT-UPD-001** Check that firmware updates are signed and the device checks the signature  
  *Severity if fail:* Critical | *Type:* Manual  
  *Objective:* Finds devices that install unsigned or changed firmware.  
  *Steps:*
  1. Get an update package.
  2. Change one byte in a lab copy.
  3. Try to install it.
  4. Try to install a package with a wrong signature.
  *Example:* `binwalk the package; openssl dgst -verify; flash the changed copy only on a lab unit.`  
  *Expected:* The device rejects firmware with a missing or wrong signature.  
  *Refs:* other: UK Code of Practice for Consumer IoT Security provision 3, as listed in iot_map.md, GSMA CLP13_6.11, GSMA CLP13_7.5; cwe: CWE-347, CWE-494, CWE-345; cheatsheet: Drone_Security_Cheat_Sheet, Automotive_Security_Cheat_Sheet, Software_Supply_Chain_Security_Cheat_Sheet; attack: T1693.001, T1693; iot_top10: I4

- [ ] **IOT-UPD-002** Test the update channel for transport protection  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds update downloads over HTTP or TLS without certificate checks.  
  *Steps:*
  1. Capture an update check and download.
  2. Look at the protocol and the certificate checks.
  3. Serve a lab response from a proxy.
  4. Check what the device does.
  *Example:* `mitmproxy with a lab CA; Wireshark.`  
  *Expected:* The device gets updates over TLS with certificate validation. It rejects a proxy response.  
  *Refs:* cwe: CWE-319, CWE-295; cheatsheet: Automotive_Security_Cheat_Sheet; attack: T0830; iot_top10: I4, I7

- [ ] **IOT-UPD-003** Test anti-rollback of firmware  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds devices that accept older vulnerable firmware.  
  *Steps:*
  1. Record the current firmware version.
  2. Get an older signed package.
  3. Try to install it in a lab.
  4. Check the version counter in the bootloader.
  *Example:* `Install an older signed image on a lab unit; read the version from the console.`  
  *Expected:* The device refuses older firmware versions. A version counter in protected storage enforces this.  
  *Refs:* cwe: CWE-1329; cheatsheet: Drone_Security_Cheat_Sheet, Automotive_Security_Cheat_Sheet; iot_top10: I4

- [ ] **IOT-UPD-004** Test interrupted updates and recovery  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds devices that stay broken or unprotected after a failed update.  
  *Steps:*
  1. Start an update on a lab unit.
  2. Cut power at 50 percent.
  3. Power on again.
  4. Check the version, the state and the signature check.
  *Example:* `Controllable power switch; serial console log.`  
  *Expected:* The device boots a known good image or a signed recovery image. It never runs half-written code.  
  *Refs:* cwe: CWE-345; cheatsheet: Automotive_Security_Cheat_Sheet; attack: T0800; iot_top10: I4, I8

- [ ] **IOT-UPD-005** Check update notices and the published support period  
  *Severity if fail:* Low | *Type:* Config Review, Manual  
  *Objective:* Finds products with no update notice or published end of support.  
  *Steps:*
  1. Find the update notice in the app or the device.
  2. Read the support period in the documentation.
  3. Check the update steps for a normal user.
  4. Check the notice for the reason of the update.
  *Example:* `Document review: support policy, release notes, update UI.`  
  *Expected:* Users see update notices with the reason. The vendor publishes a minimum support period.  
  *Refs:* other: UK Code of Practice for Consumer IoT Security provision 3, as listed in iot_map.md; iot_top10: I4, I8
