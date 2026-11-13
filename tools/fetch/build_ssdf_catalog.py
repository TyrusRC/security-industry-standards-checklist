import json, re, subprocess
ROOT = "/home/kali/test/sec-checklist"
dbg = json.load(open(f"{ROOT}/sources/nist_ssdf/parsed_debug.json"))
txt = subprocess.run(["pdftotext", f"{ROOT}/sources/nist_ssdf/NIST.SP.800-218.pdf", "-"], capture_output=True, text=True).stdout
flat = re.sub(r"\s+", " ", txt)

PRACTICES = {
 "PO.1": "Define Security Requirements for Software Development",
 "PO.2": "Implement Roles and Responsibilities",
 "PO.3": "Implement Supporting Toolchains",
 "PO.4": "Define and Use Criteria for Software Security Checks",
 "PO.5": "Implement and Maintain Secure Environments for Software Development",
 "PS.1": "Protect All Forms of Code from Unauthorized Access and Tampering",
 "PS.2": "Provide a Mechanism for Verifying Software Release Integrity",
 "PS.3": "Archive and Protect Each Software Release",
 "PW.1": "Design Software to Meet Security Requirements and Mitigate Security Risks",
 "PW.2": "Review the Software Design to Verify Compliance with Security Requirements and Risk Information",
 "PW.4": "Reuse Existing, Well-Secured Software When Feasible Instead of Duplicating Functionality",
 "PW.5": "Create Source Code by Adhering to Secure Coding Practices",
 "PW.6": "Configure the Compilation, Interpreter, and Build Processes to Improve Executable Security",
 "PW.7": "Review and/or Analyze Human-Readable Code to Identify Vulnerabilities and Verify Compliance with Security Requirements",
 "PW.8": "Test Executable Code to Identify Vulnerabilities and Verify Compliance with Security Requirements",
 "PW.9": "Configure Software to Have Secure Settings by Default",
 "RV.1": "Identify and Confirm Vulnerabilities on an Ongoing Basis",
 "RV.2": "Assess, Prioritize, and Remediate Vulnerabilities",
 "RV.3": "Analyze Vulnerabilities to Identify Their Root Causes",
}
PW3 = "Verify Third-Party Software Complies with Security Requirements"  # PW.3 moved (not in catalog)

# verify practice names occur in the PDF text (names may wrap across lines; pdftotext flattening collapses whitespace)
missing = []
for k, v in PRACTICES.items():
    # tolerate hyphenation/wrap artifacts by checking word sequence
    pat = r"\s*".join(map(re.escape, v.split()))
    if not re.search(pat, flat):
        missing.append(k)
print("practice names not found verbatim:", missing)

items = []
for k, v in PRACTICES.items():
    items.append({"id": k, "title": v, "chapter": k.split(".")[0] + " " + {"PO": "Prepare the Organization", "PS": "Protect the Software", "PW": "Produce Well-Secured Software", "RV": "Respond to Vulnerabilities"}[k.split(".")[0]]})
OVERRIDES = {
    "PO.2.2": "Provide role-based training for all personnel with responsibilities that contribute to secure development. Periodically review personnel proficiency and role-based training, and update the training as needed.",
    "PO.3.3": "Configure tools to generate artifacts of their support of secure software development practices as defined by the organization.",
    "PS.1.1": "Store all forms of code – including source code, executable code, and configuration-as-code – based on the principle of least privilege so that only authorized personnel, tools, services, etc. have access.",
}
moved = []
for tid in dbg["order"]:
    parts = [p for p in dbg["tasks"][tid] if p]
    if parts and parts[0].startswith("Moved to"):
        moved.append(tid)
        continue
    title = " ".join(parts)
    title = re.sub(r"\s+", " ", title).strip()
    title = OVERRIDES.get(tid, title)  # footnote text bled into the task column for these three
    grp = tid.rsplit(".", 1)[0]
    items.append({"id": tid, "title": title, "chapter": grp})
print("moved (excluded):", moved)
items.sort(key=lambda x: [x["id"].split(".")[0], [int(n) if n.isdigit() else n for n in x["id"].split(".")[1:]]])
ids = [i["id"] for i in items]
assert len(ids) == len(set(ids))
print("practices:", sum(1 for i in items if i["id"].count(".") == 1), "tasks:", sum(1 for i in items if i["id"].count(".") == 2))
json.dump({"source": "NIST SP 800-218 Secure Software Development Framework (SSDF) Version 1.1",
           "version": "1.1 (SP 800-218, February 2022)",
           "url": "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-218.pdf",
           "retrieved": "2026-11-12",
           "items": items},
          open(f"{ROOT}/catalog/nist_ssdf.json", "w"), indent=1, ensure_ascii=False)
