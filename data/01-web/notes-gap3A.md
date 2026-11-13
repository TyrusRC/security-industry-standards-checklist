# Notes gap batch A (A1..A9)

Total: 31 tests. All validate; STE lint clean for these files.

| Topic | File | Tests | Sources read |
|---|---|---|---|
| A1 framework production config | data/01-web/gap3-fwk.yaml | WEB-FWK-001..008 | CheatSheetSeries Django_Security, Django_REST_Framework, FastAPI_Security, Laravel, Symfony, PHP_Configuration, Ruby_on_Rails, Bean_Validation |
| A2 JS runtimes and SSR | data/01-web/gap3-node.yaml | WEB-NODE-001..005 | Nextjs_Security, Nodejs_Security cheat sheets |
| A3 cookie theft and DBSC | data/01-web/gap3-dbsc.yaml | WEB-DBSC-001..003 | Cookie_Theft_Mitigation cheat sheet; sources/extra/gap3-A/webappsec-dbsc.md |
| A4 cross-site leak defenses | data/01-web/gap3-iso.yaml | WEB-ISO-001..004 | XS_Leaks cheat sheet; webappsec-fetch-metadata.md |
| A5 DNS rebinding | data/01-web/gap3-rebind.yaml | WEB-REBIND-001..003 | Webhook_Security cheat sheet; capec_latest.xml (CAPEC-275); private-network-access.md |
| A6 service and web workers | data/01-web/gap3-sw.yaml | WEB-SW-001..002 | HTML5_Security cheat sheet; ServiceWorker.md |
| A7 HTTP/2 and HTTP/3 DoS | data/01-web/gap3-h2.yaml | WEB-H2-001..002 | rfc9113.txt and rfc9114.txt, section 10.5 |
| A8 cross-platform mobile | data/03-mobile/gap3-xplat.yaml | MOB-XPLAT-001..003 | MASTG KNOW-0015, KNOW-0072, KNOW-0004, TECH-0109, TECH-0038, TECH-0098, TECH-0156, TOOL-0104, TEST-0237, TEST-0065, BEST-0012; MASWE-0057, MASWE-0035 |
| A9 task affinity | data/03-mobile/gap3-task.yaml | MOB-TASK-001 | strandhogg.md; mastg Document/0x05a-Platform-Overview.md |

## Decisions and skipped items
- A1: Mass-assignment control already exists (WEB-ARCH-006, WEB-INJ-022, WEB-AUTHZ-007). WEB-FWK-004 is a framework-guard code review and links to them with `see`. Laravel and Symfony share one test. Rails sheet has little production config text, so the test covers the session store, routes and sensitive files only. The Rails master key is not in the sheet and is not tested.
- A2: next.config rewrite, redirect, image remotePatterns and CSP nonce items were skipped (SSRF and redirect are tested elsewhere; Est was 5). The CVE-2025-29927 header trick is not written, because the cheat sheet gives no header detail.
- A3: The DBSC spec was read for registration, refresh, challenge and cross-site refresh guidance only.
- A4: Framing protection (WEB-CLIENT clickjacking test) and COOP (WEB-CLIENT-014) already exist; no new test. WEB-XSLEAK-001 touches CORP, Sec-Fetch and no-store as sub-steps; the new tests are the control checks and carry `see` links.
- A5: The Host allow-list recommendation comes from CAPEC-275 mitigations ("Reject HTTP request with a malicious Host header"). Private Network Access is a draft; browser support differs and the test notes this.
- A6: Only two tests; web worker checks are merged into WEB-SW-001.
- A7: The RFCs do not name Rapid Reset or CONTINUATION flood. Tests follow the RFC 10.5 list (PING, SETTINGS, RST_STREAM, PRIORITY, empty frames, field size, CONNECT, unknown HTTP/3 elements).
- A8: MASTG has no page on React Native OTA updates or Cordova allow-list files (config.xml). XPLAT-002 relies on the bundle-patching techniques plus MASWE-0057 (downloaded resources not verified). XPLAT-003 relies on MASTG-BEST-0012 and KNOW-0004; config file names in the example are generic tool hints. MASTG-TEST-0403 listed in the plan is about accessibility data, not cross-platform, so it was not used.
- A9: Launch mode text exists only as one line in the platform overview; the test uses the Android StrandHogg guide as the main source.
- Catalog gaps: WSTG has no SSRF-specific id other than WSTG-INJT-19 (used). CWE-16 and CWE-613 are not in the catalog, so they were not cited. Cheat sheets that sources only link to (SSRF, DoS, Secrets, CSRF, Mass Assignment) were not cited because they were not opened.
