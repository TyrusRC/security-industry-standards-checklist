import json
ROOT = "/home/kali/test/sec-checklist"
out = {
    "source": "PCI Security Standards Council - PCI DSS v4.0.1",
    "version": "4.0.1",
    "url": "https://docs-prv.pcisecuritystandards.org/PCI%20DSS/Standard/PCI-DSS-v4_0_1.pdf",
    "retrieved": "2026-11-12",
    "note": ("BLOCKED: the official PCI DSS v4.0.1 PDF returned HTTP 403 to automated download, so no requirement "
             "numbers were produced. Items are intentionally empty (no IDs invented). To complete: the user places "
             "PCI-DSS-v4_0_1.pdf in sources/pci_dss/ and this builder is re-run. Titles are paraphrased; verify "
             "against official PCI DSS v4.0.1."),
    "items": [],
}
json.dump(out, open(f"{ROOT}/catalog/pci_dss.json", "w"), indent=1, ensure_ascii=False)
