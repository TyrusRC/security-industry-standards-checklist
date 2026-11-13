(function(){
"use strict";
var DATA=null, tests=[], sel={domains:new Set(),std:new Set(),sev:new Set()};
var SEVS=["Critical","High","Medium","Low","Info"];
var DOMAINS=["WEB","API","MOBILE","CLOUD","K8S","NETWORK","LLM-AI","CICD","PCI-DSS","NIST","PRIVACY","DESKTOP","IOT"];
var PRESETS=[
 {n:"Everything",d:DOMAINS,s:[]},
 {n:"Web app + API",d:["WEB","API"],s:[]},
 {n:"Mobile app",d:["MOBILE"],s:[]},
 {n:"LLM / agentic AI",d:["LLM-AI"],s:[]},
 {n:"Cloud, containers, CI/CD, network",d:["CLOUD","K8S","CICD","NETWORK"],s:[]},
 {n:"Card payment software (PCI DSS)",d:DOMAINS,s:["PCI DSS v4.0.1"]},
 {n:"EU personal data (GDPR)",d:DOMAINS,s:["GDPR","OWASP Privacy Top 10"]},
 {n:"Vietnam data law (Decree 13/2023, Law 91/2025)",d:DOMAINS,s:["Vietnam data law"]}
];
function $(id){return document.getElementById(id)}
function el(tag,cls,txt){var e=document.createElement(tag);if(cls)e.className=cls;if(txt!=null)e.textContent=txt;return e}
function checkbox(name,count,checked,on){
  var l=el("label","opt"),c=document.createElement("input");c.type="checkbox";c.checked=checked;
  c.addEventListener("change",function(){on(c.checked)});
  l.appendChild(c);l.appendChild(el("span",null,name));if(count!=null)l.appendChild(el("span","n",String(count)));
  l._cb=c;return l}
var domainBoxes={},stdBoxes={},sevBoxes={};
function build(){
  var cnt={},scnt={};
  tests.forEach(function(t){cnt[t.sheet]=(cnt[t.sheet]||0)+1;t.std.forEach(function(s){scnt[s]=(scnt[s]||0)+1})});
  DOMAINS.forEach(function(d){if(!cnt[d])return;var b=checkbox(d,cnt[d],true,function(v){v?sel.domains.add(d):sel.domains.delete(d);render()});domainBoxes[d]=b;$("domains").appendChild(b);sel.domains.add(d)});
  Object.keys(scnt).sort().forEach(function(s){var b=checkbox(s,scnt[s],false,function(v){v?sel.std.add(s):sel.std.delete(s);render()});stdBoxes[s]=b;$("standards").appendChild(b)});
  SEVS.forEach(function(s){var b=checkbox(s,null,true,function(v){v?sel.sev.add(s):sel.sev.delete(s);render()});sevBoxes[s]=b;$("sevs").appendChild(b);sel.sev.add(s)});
  PRESETS.forEach(function(p,i){var b=el("button","preset",p.n);b.type="button";if(p.disabled){b.disabled=true;b.title=p.title}else{b.setAttribute("aria-pressed","false");b.addEventListener("click",function(){applyPreset(i)})}$("presets").appendChild(b);p._b=b;if(p.disabled&&p.title)$("presets").appendChild(el("p","planned-note",p.title))});
  $("dAll").onclick=function(){setDomains(Object.keys(domainBoxes))};
  $("dNone").onclick=function(){setDomains([])};
  $("sClear").onclick=function(){setStd([])};
  $("q").addEventListener("input",render);
  $("dlXlsx").onclick=function(){dl("xlsx")};$("dlCsv").onclick=function(){dl("csv")};$("dlMd").onclick=function(){dl("md")};
  render();
}
function setDomains(a){sel.domains=new Set(a);Object.keys(domainBoxes).forEach(function(d){domainBoxes[d]._cb.checked=sel.domains.has(d)});render()}
function setStd(a){sel.std=new Set(a);Object.keys(stdBoxes).forEach(function(s){stdBoxes[s]._cb.checked=sel.std.has(s)});render()}
function applyPreset(i){var p=PRESETS[i];PRESETS.forEach(function(x){x._b.classList.remove("active");if(!x.disabled)x._b.setAttribute("aria-pressed","false")});p._b.classList.add("active");p._b.setAttribute("aria-pressed","true");
  sel.domains=new Set(p.d.filter(function(d){return domainBoxes[d]}));Object.keys(domainBoxes).forEach(function(d){domainBoxes[d]._cb.checked=sel.domains.has(d)});setStd(p.s)}
function filtered(){
  var q=$("q").value.trim().toLowerCase();
  return tests.filter(function(t){
    if(!sel.domains.has(t.sheet)||!sel.sev.has(t.sev))return false;
    if(sel.std.size&&!t.std.some(function(s){return sel.std.has(s)}))return false;
    if(q){var h=t._h;if(h.indexOf(q)<0)return false}
    return true});
}
var cur=[];
function render(){
  cur=filtered();var C=$("count");C.textContent="";C.appendChild(el("strong",null,cur.length.toLocaleString("en-US")));C.appendChild(document.createTextNode(" of "+tests.length.toLocaleString("en-US")+" tests selected"));
  ["dlXlsx","dlCsv","dlMd"].forEach(function(id){$(id).disabled=!cur.length});
  var L=$("list");L.textContent="";var max=100;
  cur.slice(0,max).forEach(function(t){L.appendChild(item(t))});
  $("more").textContent=cur.length>max?"Showing the first "+max+" tests. Downloads include all "+cur.length+".":(cur.length?"":"No tests match the current selection.");
}
function refsLine(t){return Object.keys(t.refs).map(function(k){return (DATA.stdlabels[k]||k)+": "+t.refs[k].join(", ")}).join("; ")}
function item(t){
  var d=document.createElement("details"),s=document.createElement("summary");
  s.appendChild(el("span","id",t.id));s.appendChild(el("span",null,t.title));s.appendChild(el("span","sev "+t.sev,t.sev));d.appendChild(s);
  var b=el("div","body");
  function sec(h,node){b.appendChild(el("h4",null,h));b.appendChild(node)}
  sec("Objective",el("div",null,t.obj));
  if(t.pre.length){var u=el("ul");t.pre.forEach(function(x){u.appendChild(el("li",null,x))});sec("Preconditions",u)}
  var o=el("ol");t.steps.forEach(function(x){o.appendChild(el("li",null,x))});sec("Steps",o);
  if(t.ex)sec("Example",el("code",null,t.ex));
  sec("Expected result",el("div",null,t.exp));
  var r=el("div","refs");Object.keys(t.refs).forEach(function(k){var sp=el("span");sp.appendChild(el("b",null,(DATA.stdlabels[k]||k)+": "));sp.appendChild(document.createTextNode(t.refs[k].join(", ")));r.appendChild(sp)});
  sec("Mapped standards",r);
  if(t.see.length)sec("See also",el("div",null,t.see.join(", ")));
  d.appendChild(b);return d}
// exports
var HDR=["ID","Domain","Category","Title","Objective","Preconditions","Steps","Example","Expected result","Severity if fail","Test type","Level","Mapped standards","See also","Status","Evidence","Tester","Date","Notes"];
function row(t){return [t.id,t.sheet,t.cat,t.title,t.obj,t.pre.join("\n"),t.steps.map(function(s,i){return (i+1)+". "+s}).join("\n"),t.ex,t.exp,t.sev,t.type.join(", "),t.lvl,refsLine(t),t.see.join(", "),"Not Tested","","","",""]}
function csvCell(v){v=String(v==null?"":v);if(/^[=+\-@\t\r]/.test(v))v="'"+v;return '"'+v.replace(/"/g,'""')+'"'}
function toCsv(L){return "﻿"+[HDR].concat(L.map(row)).map(function(r){return r.map(csvCell).join(",")}).join("\r\n")}
function toMd(L){var out=["# Security test checklist","",L.length+" tests. Generated "+DATA.generated+".",""],sheet=null,cat=null;
  L.forEach(function(t){
    if(t.sheet!==sheet){sheet=t.sheet;cat=null;out.push("","## "+sheet,"")}
    if(t.cat!==cat){cat=t.cat;out.push("","### "+cat,"")}
    out.push("- [ ] **"+t.id+"** "+t.title+"  ","  *Severity if fail:* "+t.sev+" | *Type:* "+t.type.join(", ")+(t.lvl?" | *Level:* "+t.lvl:"")+"  ","  *Objective:* "+t.obj+"  ","  *Steps:*");
    t.steps.forEach(function(s,i){out.push("  "+(i+1)+". "+s)});
    if(t.ex)out.push("  *Example:* `"+t.ex.replace(/\n/g," ; ").replace(/`/g,"'")+"`  ");
    out.push("  *Expected:* "+t.exp+"  ","  *Refs:* "+refsLine(t)+(t.see.length?"  \n  *See:* "+t.see.join(", "):""),"")});
  return out.join("\n")}
function download(name,blob){var a=document.createElement("a"),u=URL.createObjectURL(blob);a.href=u;a.download=name;document.body.appendChild(a);a.click();a.remove();setTimeout(function(){URL.revokeObjectURL(u)},2000)}
function dl(kind){
  var L=cur.slice();if(!L.length)return;var day=new Date().toISOString().slice(0,10),base="security-checklist-"+day;
  if(kind==="csv")download(base+".csv",new Blob([toCsv(L)],{type:"text/csv;charset=utf-8"}));
  else if(kind==="md")download(base+".md",new Blob([toMd(L)],{type:"text/markdown;charset=utf-8"}));
  else{
    if(!window.XLSX){alert("XLSX library failed to load. Use CSV or Markdown.");return}
    var wb=XLSX.utils.book_new(),by={};L.forEach(function(t){(by[t.sheet]=by[t.sheet]||[]).push(t)});
    DOMAINS.forEach(function(d){if(!by[d])return;var ws=XLSX.utils.aoa_to_sheet([HDR].concat(by[d].map(row)));
      ws["!cols"]=HDR.map(function(h,i){return {wch:[16,10,12,40,40,30,60,50,45,10,14,10,60,18,12,20,14,12,20][i]}});
      ws["!freeze"]={xSplit:0,ySplit:1};ws["!autofilter"]={ref:ws["!ref"]};XLSX.utils.book_append_sheet(wb,ws,d.slice(0,31))});
    XLSX.writeFile(wb,base+".xlsx")}
}
fetch("data/tests.json").then(function(r){if(!r.ok)throw new Error(r.status);return r.json()}).then(function(d){
  DATA=d;tests=d.tests;
  tests.forEach(function(t){t._h=(t.id+" "+t.title+" "+t.obj+" "+t.std.join(" ")+" "+Object.keys(t.refs).map(function(k){return t.refs[k].join(" ")}).join(" ")).toLowerCase()});
  build()}).catch(function(e){$("list").textContent="Could not load data/tests.json ("+e.message+"). Open this page through a web server, not from a local file."});
})();
