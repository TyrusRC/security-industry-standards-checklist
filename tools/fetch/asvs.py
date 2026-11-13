import json, sys
src, flat, out = sys.argv[1], sys.argv[2], sys.argv[3]
url = "https://github.com/OWASP/ASVS/releases/download/v5.0.0_release/OWASP_Application_Security_Verification_Standard_5.0.0_en.json"
d = json.load(open(src, encoding="utf-8"))
items = []
for ch in d["Requirements"]:
    for sec in ch["Items"]:
        for req in sec["Items"]:
            items.append({
                "id": req["Shortcode"],
                "title": req["Description"],
                "chapter": f'{ch["Shortcode"]} {ch["Name"]}',
                "level": "L" + str(req["L"]),
            })
# cross-check against flat file
f = json.load(open(flat, encoding="utf-8"))["requirements"]
assert [r["req_id"] for r in f] == [i["id"] for i in items], "flat/nested mismatch"
assert len(items) == len({i["id"] for i in items})
doc = {
    "source": "OWASP Application Security Verification Standard (ASVS) 5.0",
    "version": d["Version"],
    "url": url,
    "retrieved": "2026-11-12",
    "items": items,
}
json.dump(doc, open(out, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
print(len(items))
