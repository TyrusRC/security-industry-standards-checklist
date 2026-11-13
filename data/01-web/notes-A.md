# WEB-A slice notes (ASVS V1/V2/V3/V5, WSTG 07-Injection/11-Client-side/10-Business_Logic)

## Coverage
- ASVS: 87/87 IDs covered (V1, V2, V3, V5).
- WSTG: 47/49 IDs in scope covered. 2 not testable (below).

## Not testable
- `WSTG-INJT-03` (HTTP Verb Tampering): the WSTG source file states "This content has been
  merged into: HTTP Methods (WSTG-CONF-06)". The control now lives in the Configuration and
  Deployment Management chapter, outside slice WEB-A. No test written here; see WSTG-CONF-06
  in whichever slice/category covers 02-Configuration_and_Deployment_Management.
- `WSTG-CLNT-08` (Cross Site Flashing): the WSTG source file states "This content has been
  removed." Flash/Flash Player is obsolete and no longer a viable attack surface for modern
  web applications. No test written.

## Merge decisions of note
- Reflected/Stored XSS (WSTG-INJT-01/02) merged with ASVS V1.1.1, V1.1.2, V1.2.1 encoding
  requirements into WEB-XSS-001/002, since they describe the same output-encoding control.
- Format String Injection (WSTG-INJT-13) merged with ASVS V1.3.10 into WEB-INJ-016.
- IMAP/SMTP Injection (WSTG-INJT-10) merged with ASVS V1.3.11 into WEB-INJ-012.
- File inclusion (WSTG-INJT-11 sub-page 11.1) merged with ASVS V5.3.2 (path/filename
  validation for file operations) into WEB-INJ-014, since WSTG explicitly names LFI/RFI
  under that ASVS requirement's text.
- Business logic payment tests (WSTG-BUSL-10) split across WEB-BIZ-012/013/014 (price/
  quantity tampering, discount codes, race conditions) rather than one test, because each
  covers a materially different control with a different example/payload.
- Documentation-only ASVS requirements (V2.1.1, V2.1.2, V2.1.3, V3.1.1, V5.1.1) were written
  as Info-severity Config Review tests rather than skipped, since they are verifiable by
  reviewing project documentation.

## Categories written
WEB-INJ (25), WEB-XSS (15), WEB-CLIENT (22), WEB-VAL (14), WEB-BIZ (14), WEB-FILE (13).
Total: 103 tests for this slice (WEB-A). The 405-test / 87-ASVS figures from the last
tools/validate.py run include files written by sibling agents for other WEB categories
(authn, conf, crypto, hdr, http, idm, info, mfa, pwd, sess, tls) sharing data/01-web.
