import glob, json, yaml, os, re, collections
SHEETS=[("01-web","WEB"),("02-api","API"),("03-mobile","MOBILE"),("04-cloud","CLOUD"),("05-k8s","K8S"),("06-network","NETWORK"),("07-llm","LLM-AI"),("08-cicd","CICD"),("09-pci","PCI-DSS"),("10-nist","NIST"),("11-privacy","PRIVACY"),("12-desktop","DESKTOP"),("13-iot","IOT")]
STD={"owasp_top10":"OWASP Top 10 (Web)","api_top10":"OWASP API Top 10","mobile_top10":"OWASP Mobile Top 10","llm_top10":"OWASP LLM Top 10","agentic_top10":"OWASP Agentic Top 10","k8s_top10":"OWASP Kubernetes Top 10","cicd_top10":"OWASP CI/CD Top 10","cloud_native_top10":"OWASP Cloud-Native Top 10","privacy_top10":"OWASP Privacy Top 10","desktop_top10":"OWASP Desktop Top 10","iot_top10":"OWASP IoT Top 10","asvs":"OWASP ASVS 5.0","wstg":"OWASP WSTG","masvs":"OWASP MASVS","mastg":"OWASP MASTG","maswe":"OWASP MASWE","cheatsheet":"OWASP Cheat Sheets","cwe":"CWE","capec":"CAPEC","attack":"MITRE ATT&CK","atlas":"MITRE ATLAS","pci_dss":"PCI DSS v4.0.1","nist_800_53":"NIST SP 800-53 r5","tool_check":"Prowler / Kubescape / ComplianceAsCode checks"}
REFS=list(STD)+["cis","other"]
pm={}
for mf in glob.glob("data/mappings/*.json"):
    for k,v in json.load(open(mf)).items():
        for item,ids in v.items():
            for i in ids: pm.setdefault(i,{}).setdefault(k,[]).append(item)
out=[];n=0
for d,name in SHEETS:
    for f in sorted(glob.glob(f"data/{d}/*.yaml")):
        for t in yaml.safe_load(open(f)) or []:
            r={k:list(v) for k,v in (t.get("refs") or {}).items() if v}
            for k,items in pm.get(t["id"],{}).items():
                r[k]=sorted(set(r.get(k,[])+items))
            oth=[str(x) for x in r.get("other",[])]
            std=sorted({STD[k] for k in r if k in STD}|({"GDPR"} if any(x.startswith("GDPR") for x in oth) else set())|({"Vietnam data law"} if any(x.startswith("Vietnam") for x in oth) else set()))
            tt=t["test_type"]; tt=tt if isinstance(tt,list) else [tt]
            out.append({"id":t["id"],"sheet":name,"cat":t["category"],"title":t["title"],"obj":t["objective"],"pre":t.get("preconditions") or [],"steps":t["steps"],"ex":t.get("example",""),"exp":t["expected"],"sev":t["severity"],"type":tt,"lvl":t.get("level",""),"refs":r,"std":std,"see":t.get("see") or []})
json.dump({"generated":"2026-11-12","count":len(out),"stdlabels":STD,"tests":out},open("docs/data/tests.json","w"),separators=(",",":"),ensure_ascii=False)
c=collections.Counter(s for t in out for s in t["std"])
print(len(out),os.path.getsize("docs/data/tests.json")//1024,"KB"); print(c.most_common(30))
