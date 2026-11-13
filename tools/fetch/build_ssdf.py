import re, json, subprocess, html, sys
ROOT = "/home/kali/test/sec-checklist"
PDF = f"{ROOT}/sources/nist_ssdf/NIST.SP.800-218.pdf"
BB = f"{ROOT}/sources/nist_ssdf/bbox.html"
subprocess.run(["pdftotext", "-bbox", PDF, BB], check=True)
src = open(BB, encoding="utf-8", errors="ignore").read()
pages = re.split(r"<page ", src)[1:]
WORD = re.compile(r'<word xMin="([\d.]+)" yMin="([\d.]+)" xMax="([\d.]+)" yMax="[\d.]+">(.*?)</word>')

rows = []  # (page, y, x, text)
for pi, pg in enumerate(pages, 1):
    ws = [(float(a), float(b), float(c), html.unescape(t)) for a, b, c, t in WORD.findall(pg)]
    ids = [w for w in ws if re.match(r"^(PO|PS|PW|RV)\.\d\.\d+:$", w[3])]
    exs = [w for w in ws if w[3] == "Example"]
    if not ids or not exs:
        continue
    tcol = min(w[0] for w in ids) - 2   # task column left edge (from task IDs)
    ecol = min(w[0] for w in exs) - 2   # example column left edge (from 'Example' labels)
    pcol_right = tcol - 1
    for x, y, x2, t in ws:
        rows.append((pi, round(y, 0), x, t, tcol, ecol))

def lines_of(col):
    # group words of a column (by page and y) into text lines
    out = []
    cur = None
    for pi, y, x, t, tcol, ecol in col:
        pass
    return out

# Build per-page column text lines
tasks = []        # (id, title_parts)
practice_text = []
cur_task = None
task_re = re.compile(r"^((PO|PS|PW|RV)\.\d\.\d+):\s*(.*)$")
prac_re = re.compile(r"\(((PO|PS|PW|RV)\.\d)\)")
pages_map = {}
for pi, y, x, t, tcol, ecol in rows:
    pages_map.setdefault(pi, []).append((y, x, t, tcol, ecol))

result_tasks = {}
order = []
practice_marks = []
for pi in sorted(pages_map):
    words = pages_map[pi]
    tcol = words[0][3]; ecol = words[0][4]
    # task column lines
    tl = {}
    pl = {}
    for y, x, t, tc, ec in words:
        if x >= tc and x < ec:
            tl.setdefault(y, []).append((x, t))
        elif x < tc:
            pl.setdefault(y, []).append((x, t))
    tlines = [(y, " ".join(t for _, t in sorted(v))) for y, v in sorted(tl.items())]
    plines = [(y, " ".join(t for _, t in sorted(v))) for y, v in sorted(pl.items())]
    cur = None
    for y, txt in tlines:
        m = task_re.match(txt.strip())
        if m:
            cur = m.group(1)
            order.append(cur)
            result_tasks[cur] = [m.group(3).strip()]
        elif cur is not None and txt.strip() and not re.match(r"^\s*(Table \d|NIST SP)", txt):
            # continuation line of task title (stop at 'Moved' stubs or blank)
            if len(result_tasks[cur]) < 12:
                result_tasks[cur].append(txt.strip())
    for y, txt in plines:
        for m in prac_re.finditer(txt):
            practice_marks.append((pi, y, m.group(1), txt.strip()))
json.dump({"tasks": {k: v for k, v in result_tasks.items()}, "order": order,
           "practice_marks": practice_marks}, open(f"{ROOT}/sources/nist_ssdf/parsed_debug.json", "w"), indent=1)
print("tasks found:", len(order), "unique:", len(set(order)))
print(sorted(set(order))[:5], sorted(set(order))[-5:])
