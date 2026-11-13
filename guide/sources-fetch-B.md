# Catalog fetch B: sources, versions, counts (retrieved 2026-11-12)

Builders: `tools/fetch/build_*.py` (run with `python3 -I`). Raw downloads: `sources/<name>/`.

| Catalog | Version | Official URL | Items |
|---|---|---|---|
| catalog/wstg.json | WSTG v4.2 checklist (master checklist.json) + 2 latest-only IDs | https://raw.githubusercontent.com/OWASP/wstg/master/checklists/checklist.json | 119 |
| catalog/cheatsheets.json | OWASP/CheatSheetSeries master @ 9c87d0a0e941 (2026-11-11) | https://github.com/OWASP/CheatSheetSeries/tree/master/cheatsheets | 137 |
| catalog/mastg.json | OWASP/mastg master @ e8183038d7a8 (2026-11-04) | https://github.com/OWASP/mastg/tree/master/tests-beta | 294 (tests-beta 202 incl. 14 placeholder; tests/ 92 deprecated) |
| catalog/maswe.json | OWASP/maswe main @ 4859052afadb (2026-09-30) | https://github.com/OWASP/maswe/tree/main/weaknesses | 78 |
| catalog/nist_csf2.json | NIST CSF 2.0, OSCAL catalog version 1.2.1 (last-modified 2026-10-22) | https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/CSF/v2.0/json/NIST_CSF_v2.0_catalog.json | 106 |
| catalog/nist_ssdf.json | NIST SP 800-218 SSDF v1.1 (Feb 2022) | https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-218.pdf | 61 (19 practices + 42 tasks; 5 "Moved to" tasks excluded) |
| catalog/pci_dss.json | PCI DSS catalog: built from the official Prioritized Approach Tool (309 requirement numbers, titles cut to 14 words). See tools/fetch/pci_from_xlsx.py.
| catalog/top10s.json | see per-list table below | see per-list table | 12 lists x 10 |

## top10s.json lists

| Key | Version | URL | Items |
|---|---|---|---|
| web_top10 | OWASP Top 10:2025 (OWASP/Top10 2025/en) | https://owasp.org/Top10/2025/ | 10 (A01-A10:2025) |
| api_top10 | OWASP API Security Top 10 2023 (OWASP/API-Security editions/2023) | https://owasp.org/API-Security/editions/2023/en/0x11-t10/ | 10 |
| mobile_top10 | OWASP Mobile Top 10 2024 (OWASP/www-project-mobile-top-10) | https://owasp.org/www-project-mobile-top-10/ | 10 |
| llm_top10 | OWASP Top 10 for LLM Applications 2025 (2_0_vulns) | https://genai.owasp.org/llm-top-10/ | 10 |
| llm_top10_2026 | OWASP GenAI LLM Top 10 2026 (GenAI-Security-Project 2026/final). Extra key, newer than the 2025 list | https://github.com/GenAI-Security-Project/GenAI-LLM-Top10/tree/main/2026/final | 10 |
| agentic_top10 | OWASP Top 10 for Agentic Applications 2026 (official PDF) | https://genai.owasp.org/download/52117/ | 10 (ASI01-ASI10, titles from the PDF) |
| k8s_top10 | OWASP Kubernetes Top Ten 2025 | https://owasp.org/www-project-kubernetes-top-ten/ | 10 |
| cicd_top10 | OWASP CI/CD Top 10 (CICD-SEC-1..10), repo master | https://owasp.org/www-project-top-10-ci-cd-security-risks/ | 10 |
| cloud_native_top10 | OWASP Cloud-Native AppSec Top 10 2022 (CNAS-1..10) | https://owasp.org/www-project-cloud-native-application-security-top-10/ | 10 |
| privacy_top10 | OWASP Top 10 Privacy Risks v2.0 (2021) (P1..P10) | https://owasp.org/www-project-top-10-privacy-risks/ | 10 |
| desktop_top10 | OWASP Desktop App Security Top 10 2021 (DA1..DA10) | https://owasp.org/www-project-desktop-app-security-top-10/ | 10 |
| iot_top10 | OWASP IoT Top 10 2018 (I1..I10) | https://owasp.org/www-project-internet-of-things/ | 10 (titles from a secondary mapping project, see gaps) |

## Notes and gaps

- **PCI DSS catalog: built from the official Prioritized Approach Tool (309 requirement numbers, titles cut to 14 words). See tools/fetch/pci_from_xlsx.py.
- **IoT 2018 titles are secondary.** The official PDF link (owasp.org/images/1/1c/OWASP-IoT-Top-10-2018-final.pdf) returns 404. Titles come from the scriptingxss OWASP-IoT-Top-10-2018-Mapping doc, which lists I1-I10 with the 2018 names. Verify against the official PDF when it is available.
- **Serverless Top 10** was skipped (optional, and no official index listing was verified).
- **WSTG:** 117 checklist.json IDs plus WSTG-CONF-08 (RIA Cross Domain Policy) and WSTG-CLNT-08 (Cross Site Flashing), which appear only in the master dev doc, tagged "(latest)". The dev doc's `13-Buffer_Overflow` page also carries WSTG-INJT-13, the same ID as Format String Injection. Only the checklist entry is kept, so there are no duplicate IDs.
- **Concurrent writer:** another process wrote `catalog/wstg.json` at 07:50 (120 items, same ID set plus a duplicate WSTG-INJT-13, source "document tree"). That copy is preserved at `sources/wstg/other_writer_wstg_catalog_0750.json`. This catalog was rebuilt from `tools/fetch/build_wstg.py`.
- **NIST CSF 2.0:** 106 subcategories. Withdrawn CSF 1.1 categories and subcategories (ID.BE, PR.IP, RS.RP, ...) are excluded.
- **SSDF:** the five "Moved to" tasks (PW.3.1, PW.3.2, PW.4.3, PW.4.5, PW.5.2) are excluded. Practice PW.3 is also excluded because it was moved. Three task titles had footnote text in the PDF text layer; those were set from the document wording (PO.2.2, PO.3.3, PS.1.1).
- **MASTG:** chapter = front-matter platform plus "beta" for tests-beta and the front-matter status (deprecated / placeholder). Two MASVS-NETWORK tests declare platform "network".
- **Cheatsheets:** the titles are the file stems with underscores replaced by spaces.
- **LLM 2025 vs 2026:** llm_top10 follows the requested 2025 IDs. The 2026 list is added as llm_top10_2026.
