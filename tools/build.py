import glob, os, json, yaml, collections
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment
from openpyxl.worksheet.datavalidation import DataValidation
from openpyxl.formatting.rule import CellIsRule
from openpyxl.utils import get_column_letter
SHEETS=[("01-web","WEB"),("02-api","API"),("03-mobile","MOBILE"),("04-cloud","CLOUD"),("05-k8s","K8S"),("06-network","NETWORK"),("07-llm","LLM-AI"),("08-cicd","CICD"),("09-pci","PCI-DSS"),("10-nist","NIST"),("11-privacy","PRIVACY"),("12-desktop","DESKTOP"),("13-iot","IOT")]
REFS=["owasp_top10","api_top10","mobile_top10","llm_top10","agentic_top10","k8s_top10","cicd_top10","cloud_native_top10","privacy_top10","desktop_top10","iot_top10","wstg","asvs","masvs","mastg","maswe","cheatsheet","cwe","capec","attack","atlas","pci_dss","nist_800_53","tool_check","cis","other"]
COLS=["ID","Category","Title","Objective","Preconditions","Test Steps","Example","Expected Result","Severity if Fail","Test Type","Level"]+REFS+["See Also","Status","Evidence","Tester","Date","Notes"]
def load(d):
    T=[]
    for f in sorted(glob.glob(f"data/{d}/*.yaml")): T+= yaml.safe_load(open(f)) or []
    return T
def jn(x): return "\n".join(map(str,x)) if isinstance(x,list) else (x or "")
def row(t):
    r=t.get("refs") or {}
    return [t["id"],t["category"],t["title"],t["objective"],jn(t.get("preconditions")),"\n".join(f"{i+1}. {s}" for i,s in enumerate(t["steps"])),t.get("example",""),t["expected"],t["severity"],jn(t["test_type"]).replace("\n",", "),t.get("level","")]+[", ".join(map(str,r.get(k,[]))) for k in REFS]+[", ".join(t.get("see",[]) or []),"Not Tested","","","",""]
wb=Workbook(); ws=wb.active; ws.title="README"
for l in ["Security test-case checklist (audit standard)","One sheet per domain. Each test lists every standard item it covers.","Fill Status, Evidence, Tester, Date and Notes. Do not edit other columns.","Status values: Not Tested, Pass, Fail, N/A.","Style: ASD-STE100. Sources and versions: see Sources sheet.","Tests that overlap another sheet carry 'See Also' IDs instead of a copy."]: ws.append([l])
ws["A1"].font=Font(bold=True,size=14); ws.column_dimensions["A"].width=100
hdr=PatternFill("solid",fgColor="1F3864"); alltests={}
os.makedirs("out/markdown",exist_ok=True)
sevfill={"Critical":"C00000","High":"ED7D31","Medium":"FFD966","Low":"A9D08E","Info":"BDD7EE"}
for d,name in SHEETS:
    T=load(d)
    if not T: continue
    alltests[name]=T; ws=wb.create_sheet(name); ws.append(COLS)
    for t in T: ws.append(row(t))
    for c in ws[1]: c.font=Font(bold=True,color="FFFFFF"); c.fill=hdr; c.alignment=Alignment(wrap_text=True,vertical="top")
    ws.freeze_panes="D2"; ws.auto_filter.ref=ws.dimensions
    w={"ID":16,"Title":40,"Objective":40,"Test Steps":60,"Example":50,"Expected Result":45}
    for i,c in enumerate(COLS,1): ws.column_dimensions[get_column_letter(i)].width=w.get(c,18)
    for r in ws.iter_rows(min_row=2): 
        for c in r: c.alignment=Alignment(wrap_text=True,vertical="top")
    n=len(T)+1; sc=COLS.index("Status")+1; vc=COLS.index("Severity if Fail")+1
    dv=DataValidation(type="list",formula1='"Not Tested,Pass,Fail,N/A"',allow_blank=False); ws.add_data_validation(dv); dv.add(f"{get_column_letter(sc)}2:{get_column_letter(sc)}{n}")
    for s,col in sevfill.items(): ws.conditional_formatting.add(f"{get_column_letter(vc)}2:{get_column_letter(vc)}{n}",CellIsRule(operator="equal",formula=[f'"{s}"'],fill=PatternFill("solid",bgColor=col,fgColor=col)))
    md=[f"# {name} security test cases\n",f"{len(T)} tests. Tick the box when the test passes.\n"]; cat=None
    for t in T:
        if t["category"]!=cat: cat=t["category"]; md.append(f"\n## {cat}\n")
        r=t.get("refs") or {}
        md.append(f"- [ ] **{t['id']}** {t['title']}  \n  *Severity if fail:* {t['severity']} | *Type:* {jn(t['test_type']).replace(chr(10),', ')}"+(f" | *Level:* {t['level']}" if t.get('level') else "")+f"  \n  *Objective:* {t['objective']}  \n  *Steps:*\n"+"\n".join(f"  {i+1}. {s}" for i,s in enumerate(t['steps']))+f"\n  *Example:* `{t.get('example','').replace(chr(10),' ; ')}`  \n  *Expected:* {t['expected']}  \n  *Refs:* "+"; ".join(f"{k}: {', '.join(map(str,v))}" for k,v in r.items() if v)+(f"  \n  *See:* {', '.join(t['see'])}" if t.get('see') else "")+"\n")
    open(f"out/markdown/{d}.md","w").write("\n".join(md))
# coverage matrix
cm=wb.create_sheet("Coverage Matrix"); cm.append(["Source","Item ID","Title","Test IDs","Count"])
KEYS=[("owasp_top10","top10s","web_top10"),("api_top10","top10s","api_top10"),("mobile_top10","top10s","mobile_top10"),("llm_top10","top10s","llm_top10"),("agentic_top10","top10s","agentic_top10"),("k8s_top10","top10s","k8s_top10"),("cicd_top10","top10s","cicd_top10"),("cloud_native_top10","top10s","cloud_native_top10"),("privacy_top10","top10s","privacy_top10"),("desktop_top10","top10s","desktop_top10"),("iot_top10","top10s","iot_top10"),("asvs","asvs5",None),("wstg","wstg",None),("masvs","masvs",None),("mastg","mastg",None),("maswe","maswe",None),("cwe","cwe",None),("capec","capec",None),("attack","attack",None),("atlas","atlas",None),("cheatsheet","cheatsheets",None),("tool_check","checks",None),("pci_dss","pci_dss",None),("nist_800_53","nist80053",None)]
idx=collections.defaultdict(lambda: collections.defaultdict(list))
for n,T in alltests.items():
    for t in T:
        for k,v in (t.get("refs") or {}).items():
            for x in v or []: idx[k][x].append(t["id"])
extra={}
for mf in glob.glob("data/mappings/*.json"):
    for k,v in json.load(open(mf)).items(): extra.setdefault(k,{}).update(v)
for k,v in extra.items():
    for item,ids in v.items():
        for i in ids: idx[k][item].append(i)
rowsout=0
for key,cat,lk in KEYS:
    p=f"catalog/{cat}.json"
    if not os.path.exists(p): continue
    d=json.load(open(p)); items=d["lists"][lk]["items"] if lk else d["items"]
    if key in("cwe","capec","attack","atlas","nist_800_53","mastg") and not idx[key]: continue
    for i in items:
        if key in("cwe","capec","attack","atlas","nist_800_53") and i["id"] not in idx[key] and not i.get("top25"): continue
        ids=idx[key].get(i["id"],[]); cm.append([key,i["id"],i["title"][:120],", ".join(ids),len(ids)]); rowsout+=1
cm.freeze_panes="A2"; cm.auto_filter.ref=cm.dimensions
for c,wd in zip("ABCDE",(18,16,70,80,8)): cm.column_dimensions[c].width=wd
# dashboard
db=wb.create_sheet("Dashboard",1); db.append(["Sheet","Tests","Not Tested","Pass","Fail","N/A","Critical","High","Medium","Low","Info"])
for n in alltests:
    L=f"'{n}'!"; sc=get_column_letter(COLS.index("Status")+1); vc=get_column_letter(COLS.index("Severity if Fail")+1)
    db.append([n,f"=COUNTA({L}A2:A5000)"]+[f'=COUNTIF({L}{sc}2:{sc}5000,"{s}")' for s in("Not Tested","Pass","Fail","N/A")]+[f'=COUNTIF({L}{vc}2:{vc}5000,"{s}")' for s in sevfill])
r=db.max_row; db.append(["TOTAL"]+[f"=SUM({get_column_letter(c)}2:{get_column_letter(c)}{r})" for c in range(2,12)])
for c in db[1]: c.font=Font(bold=True)
src=wb.create_sheet("Sources"); src.append(["Catalog","Source","Version","URL","Items"])
for f in sorted(glob.glob("catalog/*.json")):
    d=json.load(open(f)); src.append([os.path.basename(f),d.get("source"),str(d.get("version"))[:80],str(d.get("url"))[:100],len(d["items"]) if "items" in d else sum(len(v["items"]) for v in d["lists"].values())])
os.makedirs("out",exist_ok=True); wb.save("out/security-checklist.xlsx")
print({n:len(T) for n,T in alltests.items()}, "total",sum(len(T) for T in alltests.values()), "coverage rows",rowsout)
