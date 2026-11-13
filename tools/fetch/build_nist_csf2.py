import json
ROOT = "/home/kali/test/sec-checklist"
d = json.load(open(f"{ROOT}/sources/nist_csf2/NIST_CSF_v2.0_catalog.json"))
cat = d["catalog"]
items = []
def stmt(ctl):
    for p in ctl.get("parts", []):
        if p.get("name") == "statement":
            return " ".join(p.get("prose", "").split())
    return ""
for g in cat["groups"]:
    for c in g.get("controls", []):
        for s in c.get("controls", []):
            if any(q.get("name") == "status" and q.get("value") == "withdrawn" for q in s.get("props", []) + c.get("props", [])):
                continue  # CSF 1.1 legacy (withdrawn) entries
            sid = next((p["value"] for p in s.get("props", []) if p.get("name") == "label"), s["id"])
            items.append({"id": sid, "title": stmt(s), "chapter": c["id"]})
ids = [i["id"] for i in items]
assert len(ids) == len(set(ids))
print(len(items), ids[0], ids[-1], sum(1 for i in items if not i["title"]))
md = cat["metadata"]
out = {"source": "NIST Cybersecurity Framework (CSF) 2.0 - OSCAL catalog (usnistgov/oscal-content)",
       "version": "2.0 (OSCAL catalog version " + str(md.get("version")) + ", last-modified " + str(md.get("last-modified"))[:10] + ")",
       "url": "https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/CSF/v2.0/json/NIST_CSF_v2.0_catalog.json",
       "retrieved": "2026-11-12", "items": items}
json.dump(out, open(f"{ROOT}/catalog/nist_csf2.json", "w"), indent=1, ensure_ascii=False)
