import sys, json, glob, yaml, re, os
REQ=["id","sheet","category","title","objective","steps","expected","severity","test_type","refs","sources_read"]
SEV={"Critical","High","Medium","Low","Info"}
TT={"Manual","Automated","Config Review","Code Review"}
KEYMAP={"owasp_top10":("top10s","web_top10"),"api_top10":("top10s","api_top10"),"mobile_top10":("top10s","mobile_top10"),
"llm_top10":("top10s","llm_top10"),"agentic_top10":("top10s","agentic_top10"),"k8s_top10":("top10s","k8s_top10"),
"cicd_top10":("top10s","cicd_top10"),"cloud_native_top10":("top10s","cloud_native_top10"),"privacy_top10":("top10s","privacy_top10"),"desktop_top10":("top10s","desktop_top10"),"iot_top10":("top10s","iot_top10"),
"wstg":("wstg",),"asvs":("asvs5",),"masvs":("masvs",),"mastg":("mastg",),"maswe":("maswe",),"cheatsheet":("cheatsheets",),
"cwe":("cwe",),"tool_check":("checks",),"capec":("capec",),"attack":("attack",),"atlas":("atlas",),"pci_dss":("pci_dss",),"nist_800_53":("nist80053",)}
def load(k):
    p=f"catalog/{k[0]}.json"
    if not os.path.exists(p): return None
    d=json.load(open(p))
    if len(k)>1:
        L=d["lists"]; ks=[x for x in L if x==k[1] or x.startswith(k[1]+"_")]
        return {i["id"] for x in ks for i in L[x]["items"]}
    return {i["id"] for i in d["items"]}
cat={}
for r,k in KEYMAP.items(): cat[r]=load(k)
HAVE_SOURCES=os.path.isdir("sources")
if not HAVE_SOURCES: print("note: sources/ not found, skipping sources_read file checks")
errs=[];ids={};n=0
for f in sorted(glob.glob(sys.argv[1]+"/**/*.yaml",recursive=True)):
    for t in yaml.safe_load(open(f)) or []:
        n+=1; i=t.get("id","?")
        for r in REQ:
            if not t.get(r): errs.append(f"{i}: missing {r}")
        if i in ids: errs.append(f"{i}: duplicate (also {ids[i]})")
        ids[i]=f
        if t.get("severity") not in SEV: errs.append(f"{i}: bad severity")
        tt=t.get("test_type"); tt=tt if isinstance(tt,list) else [tt]
        if not set(tt)<=TT: errs.append(f"{i}: bad test_type")
        for s in t.get("sources_read") or []:
            if HAVE_SOURCES and not os.path.exists(s): errs.append(f"{i}: sources_read missing file {s}")
        for k,v in (t.get("refs") or {}).items():
            if k=="other": continue
            if k not in cat: errs.append(f"{i}: unknown ref key {k}"); continue
            if cat[k] is None: errs.append(f"{i}: catalog for {k} not available"); continue
            for x in v:
                if x not in cat[k]: errs.append(f"{i}: {k} id not in catalog: {x}")
print(f"{n} tests, {len(errs)} errors"); print("\n".join(errs[:200])); sys.exit(1 if errs else 0)
