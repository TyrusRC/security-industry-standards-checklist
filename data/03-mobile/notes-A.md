# MOB-A slice notes (MASVS STORAGE, CRYPTO, AUTH, NETWORK)

## Coverage
- Tests: 52 (storage 9, crypto 16, auth 12, network 15). Files: storage.yaml, crypto.yaml, auth.yaml, network.yaml.
- MASVS: 9/9 controls (STORAGE-1/2, CRYPTO-1/2, AUTH-1/2/3, NETWORK-1/2).
- MASTG: 76/76 non-deprecated, non-placeholder tests of `tests-beta` in the four groups.
- MASWE: 0001-0028 and 0036 all appear in refs.

## Source paths and rules
- MASWE text is in `sources/mastg/files/MASWE__weaknesses_MASVS-<G>_MASWE-NNNN.md`.
- Mobile Top 10 2024: the 2024 index links to `sources/repos/www-project-mobile-top-10/2023-risks/m*.md`. Those files are the 2024 text.
- `level`: the control files have no profile. Rule used: "MASVS L1" if any merged MASWE lists L1 in `profiles`, else "MASVS L2".
- `cwe`: taken from the `cwe` lists of the merged MASWE files and checked in the catalog. CWE-613 is not in the catalog and was dropped.
- `nist_800_53`: omitted. No source read for this slice maps NIST 800-53 controls.
- Severity: MASTG notes "hardening issue, not a critical vulnerability" for 0326, 0268, 0329, 0330. These tests are Low.
- A test can carry several MASTG ids when Android and iOS (static and dynamic) procedures are one control.

## Excluded MASTG tests
- Placeholders (empty content): MASTG-TEST-0304, 0305, 0306 (Room, DataStore), 0309, 0310 (reused IVs), 0237, 0238, 0239 (cleartext in frameworks, runtime APIs, sockets).
- MASTG v1 tests in `tests/` (status deprecated) are out of scope. They are not in the 76-test set.
- The Android keyboard cache test is deprecated v1. MOB-STORAGE-008 covers iOS only.

## Tests with no MASTG v2 test (written from MASWE text)
- MASVS-AUTH-1 has no MASTG test. MOB-AUTH-007 and MOB-AUTH-008 cover it (MASWE-0018 authentication modes, MASWE-0020 local-only enforcement, Mobile Top 10 M3).
- MASWE-0018 also lists exported components, IPC caller checks and local services. Those modes belong to the PLATFORM slice and are not tested here.
- MOB-STORAGE-009 (MASWE-0004), MOB-CRYPTO-006 (MASWE-0003 keystore part), MOB-CRYPTO-010 to 016 (MASWE-0009, 0010, 0011, 0014, 0015, 0016, 0017), MOB-AUTH-006, 009 to 012 (MASWE-0019, 0023, 0024, 0025, 0020 PIN).

## Merge decisions
- MASWE-0036 (keyboard cache) is in the PLATFORM group of the MASWE catalog, but MASTG places both iOS tests under MASVS-STORAGE. Kept in MOB-STORAGE-008.
- Hardcoded keys (MASTG 0212/0213/0214, MASWE-0003) are in MOB-CRYPTO-005. Hardcoded secrets in general (MASWE-0004) are in MOB-STORAGE-009.
- MASTG-TEST-0285 has `deprecated_since: 24` in its front matter. This is an Android API level and not a deprecation status. It is included in MOB-NETWORK-011.
- Server-side session, OAuth, TLS server and cryptography controls are in the WEB sheet. Pointers are in `see`.
- Mobile cheat sheet ids: "Certificate_and_Public_Key_Pinning" is `Pinning_Cheat_Sheet` in the catalog; "Transport_Layer_Security" is used as listed.

## Open issues
- MASTG-TEST-0244 is Android-only. The iOS MITM step in MOB-NETWORK-015 follows MASTG-TEST-0236 and MASTG-TECH-0063 and has no iOS-specific MASTG test.
- Frida and objection command hints in `example` follow MASTG-TECH-0002/0008/0043/0059/0061/0095. Check them against your tool versions.
