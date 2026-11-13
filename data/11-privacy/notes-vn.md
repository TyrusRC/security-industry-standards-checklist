# Vietnam data protection pack (PRIV-VN*)
Not legal advice. These tests turn the technical parts of two Vietnamese texts into checks. A qualified lawyer must decide which text applies, which duties apply to the organisation, and what the Government implementing rules say.
Sources (OCR of signed PDFs, read in full): `sources/vn_law/13nd.ocr.txt` = Decree 13/2023/ND-CP; `sources/vn_law/91qh.ocr.txt` = Law 91/2025/QH15.
Refs use the exact text "Vietnam Decree 13/2023/ND-CP Art. N" and "Vietnam PDP Law 91/2025/QH15 Art. N". Files: `vn-rights, vn-consent, vn-sens, vn-xfer, vn-dpia, vn-breach, vn-sec, vn-proc, vn-auto, vn-mkt` (50 tests).
Which text is in force is not decided here. The Law states an effective date of 1 January 2026 (Art. 38) and a transition rule for consents and filed dossiers made under the Decree (Art. 39). Decree Art. 43(2) and 43(3) and Law Art. 38(2) and 38(3) give exemptions for small firms. Where the texts differ, each test notes both.

## Article coverage (articles cited in a test)
Decree 13/2023: 22 of 44 articles cited: 2, 3, 9, 11-18, 20-28, 38, 39. Law 91/2025: 27 of 39 articles cited: 2, 4, 7, 9-15, 17, 19-33, 37 (Art. 11, 12 and 22 are cited with Art. 28/29, 30 and 20/21).
| Topic | Decree 13/2023 | Law 91/2025 | Tests |
|---|---|---|---|
| Access / provision | 9(7), 14 | 4, 15 | VNRIGHTS-001, 002 |
| Correction | 9(3), 15 | 13 | VNRIGHTS-003 |
| Deletion | 9(5), 16 | 14 | VNRIGHTS-004, 005 |
| Restriction | 9(6) | 10 | VNRIGHTS-006 |
| Objection | 9(8) | 4(1)(d), 28(5) | VNRIGHTS-007 |
| Consent, withdrawal, notice | 11, 12, 13, 17 | 9, 10, 11, 19 | VNCONSENT-001 to 006 |
| Sensitive data, children, location, biometrics, health, recording, HR | 2(4), 18, 20, 28 | 2(3), 24, 25, 26, 31, 32, 33 | VNSENS-001 to 009 |
| Cross-border transfer | 2(14), 25 | 20, 22 | VNXFER-001 to 005 |
| Processing impact dossier | 24 | 21, 22 | VNDPIA-001 to 003 |
| Breach notice | 23 | 23, 27(1)(d) | VNBREACH-001 to 005 |
| Security, logs, scraping, sale, de-identification, AI access | 3, 22, 26, 27, 38 | 2, 7, 12, 14, 17, 30, 37 | VNSEC-001 to 006 |
| Processors, third parties | 13, 14, 38, 39 | 15, 17, 37 | VNPROC-001 to 003 |
| Profiling, AI | 2(13) | 30 | VNAUTO-001, 002 |
| Marketing, tracking, social platforms | 21 | 11, 28, 29 | VNMKT-001 to 004 |
Existing PRIV and WEB/MOB tests are linked with `see`. Vietnam tests state only the Vietnam-specific variant (72-hour limits, Mau so forms, authority filing, 60-day period).

## Skipped articles (organisational, state, definitions or penalties)
- Decree: 1, 4 (penalties), 5, 6, 7, 8 (banned acts), 10 (duties of the data subject), 19 (deceased: manual consent of relatives; not tested), 29 to 37 and 40 to 42 (state bodies, funds, general duties), 43, 44, annexes Mau so 01 to 06 (used as examples only).
- Law: 1, 3 (principles; used in other tests), 5, 6, 8 (penalties; max fine 5% of revenue for transfer violations, 3 billion VND for others, 10 times profit for sale), 16 (publication of data), 18, 34, 35, 36, 38 (SME exemptions, noted in tests), 39 (transition; noted in notes).

## OCR notes and uncertain items
- Article headings were checked in sequence: Decree Art. 1 to 44 and Law Art. 1 to 39 are complete and in order, so no article number was re-read from the PDF.
- OCR garbles diacritics. These points were read from context and should be checked against the signed PDF: Decree Art. 43(1) shows "20243" (read as the year of effect, not confirmed); Decree Art. 14(5)(a) and 14(6) wording about the form; Law Art. 22(1) "06 thang" (read as 6 months); Law Art. 10(1) reference to Art. 19; Law Art. 14(1)(a) reference to Art. 4(3).
- Law Art. 4(1) letters (a to e) and Decree Art. 2(4) letters in OCR use odd letters (for example "dd", "oe"). Tests cite articles and clauses only where the number was clear.
- Law Art. 2(2), 2(3): the lists of basic and sensitive data come from a Government catalogue that is not in the sources.

## Differences between Decree 13/2023 and Law 91/2025 (both stated in tests)
- Response time: Decree sets 72 hours for restriction, objection, provision, correction (notice of refusal) and deletion (Art. 9, 14, 15, 16). The Law sets no number; it refers to time limits in other law (Art. 4(5), 10(3)).
- Breach notice: Decree Art. 23: 72 hours after the violation happened, any violation, form Mau so 03. Law Art. 23: 72 hours from discovery, only for violations with defined harm (defence, security, order, life, health, honour, property). Contents set by later Government rules.
- Impact dossiers: Decree Art. 24 and 25: file within 60 days of the start of processing or of the transfer; tell the authority after the transfer; update on change. Law Art. 21 and 22: 60 days; one assessment for the life of the entity; update every 6 months on change and at once in listed cases; exemptions in Art. 20(6) and 21(6); data law assessments are not repeated (Art. 5(4)).
- Consent: Decree Art. 11 has a burden of proof clause (11(10)) and a list of valid forms; the Law (Art. 9) has no burden of proof sentence in Art. 9, adds "no mandatory bundling", and leaves details to the Government.
- Children: Decree Art. 20: age 7 and over needs child and parent consent; the controller must verify age; delete or destroy data on listed triggers. Law Art. 24: the representative acts; child consent from age 7 only for publishing private life; the Law does not repeat the age check or deletion duty in that article.
- Data subject notice: Decree Art. 13 sets six items; the Law has no such article.
- Logs: Decree Art. 38(2) requires system logs; the Law does not.
- New in the Law: de-identification (Art. 2, 14), AI, big data, cloud (Art. 30), location and biometrics (Art. 31), social platforms and cookies (Art. 29), advertising rules on behavioural ads (Art. 28), recruitment and staff (Art. 25), health, insurance, finance and credit data (Art. 26, 27), public recording (Art. 32, broader than Decree Art. 18).
- Sale of data: Decree Art. 3(4) and 22; Law Art. 7(6), with the Law clarifying that listed transfers are not a sale (Art. 17(2)).
- Data location: neither text read requires data to stay in Vietnam. Both require an impact assessment dossier for cross-border transfer. Any localisation duty in other laws is not in the sources.

## Open issues
- Government implementing rules for the Law (content of dossiers, breach form, time limits, catalogue of sensitive data) are not in the sources. Update the tests when they are available.
- Decree Art. 19 (deceased persons) and Law Art. 16 (publication) are testable by process review but are not written as tests.
