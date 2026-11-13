# Security Standards Checklist

A single, de-duplicated security test checklist that maps every test to the standards it covers. Pick the domains and standards you need, then download the result as CSV, Markdown or XLSX.

**Web app:** https://tyrusrc.github.io/security-industry-standards-checklist/

## Why this exists

OWASP, PCI DSS, NIST and others describe the same controls in different words. Auditors end up with many overlapping lists. This project keeps one test per verifiable control and records every standard item that test satisfies.

## Features

- One test per control, written in ASD-STE100 Simplified Technical English.
- Each test has steps, an example, a pass criterion, a severity if it fails, and mappings to the standards it covers.
- Filter by domain, standard, severity or free text. Presets cover common scopes such as web and API, mobile, LLM and agentic AI, cloud and containers, PCI DSS, GDPR and Vietnam data law.
- Export the selection to CSV, Markdown (with checkboxes) or XLSX (one sheet per domain).
- A coverage matrix shows which tests cover each standard item.

## Domains

Web, API, mobile, cloud, Kubernetes and containers, network and hosts, LLM and AI agents, CI/CD and supply chain, PCI DSS (software requirements), NIST SP 800-53, privacy, desktop clients, IoT.

## Standards and sources

| Area | Sources |
|---|---|
| OWASP | Top 10 lists (web, API, mobile, LLM, agentic, Kubernetes, CI/CD, cloud-native, privacy, desktop, IoT), ASVS 5.0, WSTG, MASVS, MASTG, MASWE, Cheat Sheet Series, Developer Guide checklist |
| MITRE | CWE, CAPEC, ATT&CK, ATLAS |
| NIST | SP 800-53 Rev 5, SP 800-115, SP 800-63B, SSDF, CSF 2.0, AI RMF |
| PCI | PCI DSS v4.0.1 (software requirements; requirement numbers and shortened titles only) |
| Privacy law | GDPR, Vietnam Decree 13/2023/ND-CP and Law 91/2025/QH15 |
| Configuration checks | Prowler, Kubescape regolibrary, ComplianceAsCode, Microsoft cloud security benchmark, NSA/CISA Kubernetes hardening guide, Kubernetes docs |

Exact versions and retrieval dates are in `catalog/*.json` and the Sources sheet of the workbook.

## Use the checklist

1. Open the web app and choose a preset or set your own filters.
2. Download CSV, Markdown or XLSX.
3. Fill in Status, Evidence, Tester, Date and Notes while you test.

Prebuilt full exports are in `out/`.

## Repository layout

| Path | Content |
|---|---|
| `data/` | Test cases in YAML. This is the source of truth. |
| `data/mappings/` | Extra mappings from standard items to test IDs (PCI DSS, NIST, cheat sheets, tool checks). |
| `catalog/` | Normalized ID lists of every standard used. |
| `docs/` | The GitHub Pages web app (HTML, CSS, JavaScript, exported data). |
| `tools/` | Validation, lint, coverage, build and export scripts. |
| `guide/` | Test schema, style guide and severity rubric. |
| `out/` | Generated XLSX and Markdown. |

## Build and check

Requirements: Python 3 with `pyyaml` and `openpyxl`.

```
python3 tools/validate.py data      # schema, unique IDs, referenced IDs exist in catalog/ (sources_read files are checked only if sources/ exists)
python3 tools/ste_lint.py data      # sentence length and banned words
python3 tools/check_mappings.py     # mapping files point to real tests and items
python3 tools/build.py              # writes out/
python3 tools/export_site.py        # writes docs/data/tests.json for the web app
```

Check how well one standard is covered:

```
python3 tools/coverage.py data <ref-key> <catalog> [list] [prefix]
```

## Contributing

Read `CONTRIBUTING.md`. In short: write from the standard's own text, one test per control, map to every standard it covers, and make `validate.py` and `ste_lint.py` pass.

## Limitations

- CIS Benchmarks, PTES, CSA CCM, ISO 27001, ETSI EN 303 645, IEC 62443 and Wi-Fi specifications are not included.
- Mappings to PCI DSS, NIST 800-53 and ATT&CK were chosen mostly from test titles and steps, and a spot check found some loose links. Treat them as indicative and verify key controls before you use them as compliance evidence.
- Tests that rest on one source file or on common vendor practice are noted in `data/*/notes*.md`. The L2 switching, Windows service ACL and AI payment and advertising tests are examples.
- Commands in the example fields follow the source text but were not run.
- The Vietnam profile is a technical reading of OCR text from the signed PDFs. It is not legal advice.
- Some cheat sheets are left out on purpose: framework-specific ones, the glossary and two niche AI sheets.
- The test content has had spot checks, not a full manual review.

## License

- Code (`tools/`, `docs/index.html`, `docs/app.js`, `docs/style.css`): Apache-2.0, see `LICENSE`.
- Checklist content (`data/`, `catalog/`, `out/`, `docs/data/`, `guide/`): CC BY-SA 4.0, see `LICENSE-CONTENT-CC-BY-SA-4.0.txt`.

Attribution to the upstream sources is in `NOTICE.md`. This project gives no legal or compliance advice.
