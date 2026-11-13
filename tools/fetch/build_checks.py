import json,glob,yaml,os,re
R="sources/repos"; items=[]
for f in sorted(glob.glob(f"{R}/prowler/prowler/providers/*/services/**/*.metadata.json",recursive=True)):
    d=json.load(open(f)); p=d.get("Provider")
    items.append({"id":f"prowler:{p}:{d['CheckID']}","title":d.get("CheckTitle",""),"chapter":f"{p}/{d.get('ServiceName','')}","severity":d.get("Severity",""),"desc":re.sub(r"[*`\n]+"," ",d.get("Description",""))[:220]})
for f in sorted(glob.glob(f"{R}/regolibrary/controls/C-*.json")):
    d=json.load(open(f)); a=d.get("attributes",{})
    items.append({"id":f"kubescape:{d['controlID']}","title":d["name"],"chapter":"kubernetes/"+(d.get("category") or {}).get("name",""),"severity":str(d.get("baseScore","")),"desc":re.sub(r"\s+"," ",d.get("description",""))[:220]})
for f in sorted(glob.glob(f"{R}/ComplianceAsCode/**/rule.yml",recursive=True)):
    try: txt=open(f,encoding="utf8").read()
    except: continue
    t=re.search(r"^title:\s*(.+)$",txt,re.M); s=re.search(r"^severity:\s*(\w+)",txt,re.M)
    if not t: continue
    parts=f.split("/"); rid=parts[-2]; grp="/".join(parts[parts.index("ComplianceAsCode")+1:-2])
    items.append({"id":f"cac:{rid}","title":t.group(1).strip("'\" ").replace("{{{","").replace("}}}",""),"chapter":grp,"severity":s.group(1) if s else ""})
ids=[i["id"] for i in items]; assert len(ids)==len(set(ids)),"dup ids"
json.dump({"source":"Public security-check catalogs: Prowler (Apache-2.0), Kubescape regolibrary (Apache-2.0), ComplianceAsCode (BSD-3-Clause)","version":"master 2026-11-12","url":"https://github.com/prowler-cloud/prowler ; https://github.com/kubescape/regolibrary ; https://github.com/ComplianceAsCode/content","retrieved":"2026-11-12","items":items},open("catalog/checks.json","w"),indent=0,ensure_ascii=False)
import collections; print(len(items),collections.Counter(i["id"].split(":")[0] for i in items))
