import json, re, zipfile, io, yaml, sys, xml.etree.ElementTree as ET
R="2026-11-12"
def out(name, source, version, url, items, **extra):
    d={"source":source,"version":version,"url":url,"retrieved":R,**extra,"items":items}
    json.dump(d,open(f"catalog/{name}.json","w"),indent=1,ensure_ascii=False)
    print(name, version, len(items))

# CWE
z=zipfile.ZipFile("sources/cwe/cwec_latest.xml.zip"); xml=z.read(z.namelist()[0])
root=ET.fromstring(xml); ver=root.get("Version")
ns=root.tag.split('}')[0]+'}'
html=open("sources/cwe/top25_2025.html",encoding="utf8",errors="ignore").read()
yr="2025"
ranks={}
for i,m in enumerate(re.finditer(r'definitions/(\d+)\.html',html)):
    ranks.setdefault(m.group(1),len(ranks)+1)
ranks={k:v for k,v in ranks.items() if v<=25}
items=[]
for w in root.iter(ns+"Weakness"):
    if w.get("Status")=="Deprecated": continue
    i=w.get("ID"); it={"id":f"CWE-{i}","title":w.get("Name")}
    if i in ranks: it["top25"]=True; it["top25_rank"]=ranks[i]
    items.append(it)
out("cwe","MITRE CWE",ver,"https://cwe.mitre.org/data/xml/cwec_latest.xml.zip",items,top25_year=yr,top25_found=len(ranks))

# CAPEC
root=ET.parse("sources/capec/capec_latest.xml").getroot(); ns=root.tag.split('}')[0]+'}'
items=[{"id":f"CAPEC-{a.get('ID')}","title":a.get("Name")} for a in root.iter(ns+"Attack_Pattern") if a.get("Status") not in("Deprecated",)]
out("capec","MITRE CAPEC",root.get("Version"),"https://capec.mitre.org/data/xml/capec_latest.xml",items)

# ATT&CK
items=[]; vers=[]
for m in("enterprise","mobile","ics"):
    b=json.load(open(f"sources/attack/{m}-attack.json"))
    for o in b["objects"]:
        if o.get("type")=="x-mitre-collection": vers.append(f"{m}:{o.get('x_mitre_version')}")
        if o.get("type")!="attack-pattern" or o.get("revoked") or o.get("x_mitre_deprecated"): continue
        ex=[r["external_id"] for r in o.get("external_references",[]) if r.get("source_name","").startswith("mitre") and "external_id" in r]
        if not ex: continue
        tac=",".join(k["phase_name"] for k in o.get("kill_chain_phases",[]))
        items.append({"id":ex[0],"title":o["name"],"chapter":f"{m}: {tac}"})
out("attack","MITRE ATT&CK","; ".join(vers),"https://github.com/mitre-attack/attack-stix-data",items)

# ATLAS
a=yaml.safe_load(open("sources/atlas/ATLAS.yaml")); items=[]
for t in a["matrices"][0]["techniques"]:
    items.append({"id":t["id"],"title":t["name"],"chapter":"technique"})
for t in a.get("mitigations",[]) or a["matrices"][0].get("mitigations",[]):
    items.append({"id":t["id"],"title":t["name"],"chapter":"mitigation"})
out("atlas","MITRE ATLAS",str(a.get("version")),"https://github.com/mitre-atlas/atlas-data",items,note="source file marked deprecated upstream; newer data may exist")

# NIST 800-53
c=json.load(open("sources/nist80053/NIST_SP-800-53_rev5_catalog.json"))["catalog"]; items=[]
def lab(x):
    for p in x.get("props",[]):
        if p["name"]=="label" and "class" not in p: return p["value"]
def walk(x,fam):
    if any(p["name"]=="status" and p["value"]=="withdrawn" for p in x.get("props",[])): return
    l=lab(x)
    if l: items.append({"id":l,"title":x["title"],"chapter":fam})
    for s in x.get("controls",[]): walk(s,fam)
for g in c["groups"]:
    for x in g["controls"]: walk(x,g["id"].upper())
out("nist80053","NIST SP 800-53 Rev 5",c["metadata"].get("version"),"https://github.com/usnistgov/oscal-content",items)

# MASVS
m=yaml.safe_load(open("sources/masvs/OWASP_MASVS.yaml")); items=[]
for g in m["groups"]:
    for c_ in g.get("controls",[]):
        items.append({"id":c_["id"],"title":c_.get("statement",c_.get("title","")),"chapter":g["title"]})
out("masvs","OWASP MASVS",m["metadata"]["version"],"https://github.com/OWASP/masvs",items)
