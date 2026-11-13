# Notes for slice WEB-C

Categories written: INFO, CONF, HTTP, HDR, TLS, CRYPTO, DATA, DEP, ARCH, SECRET, LOG, ERR, WEBRTC, WASM.

## Uncovered IDs (not testable here)
- WSTG-APIT-02 (API BOLA) and WSTG-APIT-04 (API BFLA): access control tests that belong to the API sheet. No test written in WEB-C.
  Object and function level authorization on the web is covered by the WEB authorization category (other slice).

## Decisions
- WSTG IDs that are merged or removed in the source (INFO-09, CONF-03, CONF-08, ERRH-02) are put in refs of the tests that carry their content.
  WSTG-CONF-08 (RIA cross domain policy) says "content removed": WEB-CONF-016 is a minimal legacy file check, mapped to A02 CWE-942.
- V4.3.1, V4.3.2 (GraphQL) kept as web-facing tests WEB-HTTP-007/008. Deeper GraphQL tests go to the API sheet.
- V4.4.x (WebSocket) kept in WEB-HTTP-009. Message-level tests for WebSocket belong to the client-side slice (WSTG-CLNT-10, not cited here).
- V15.1.x, V13.1.x, V11.1.x, V14.1.x are documentation or design checks. They have test_type Manual and use document review steps.
- V17 (WebRTC) tests use ASVS text only. No WSTG or cheat sheet file exists for WebRTC in the catalogs.
- Top 10 A08 serialized data is in WEB-DEP-006. Deserialization injection depth belongs to the injection slice.
- Reading note: for long WSTG pages (INFO-04, CONF-06, API pages, GraphQL) the tool output was trimmed (code blocks removed, lines cut). The prose, objectives and headings were read.
  Cheat sheets Cryptographic Storage, Key Management, Secrets Management, Logging, Logging Vocabulary, Denial of Service, Web Service Security, REST Security were read in part (headings and the sections used).
- Cheat sheets REST_Security and Web_Service_Security are not cited. Their API depth goes to the API sheet.
