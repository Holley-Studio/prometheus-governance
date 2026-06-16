"use strict";var he=Object.create;var k=Object.defineProperty;var ue=Object.getOwnPropertyDescriptor;var pe=Object.getOwnPropertyNames;var me=Object.getPrototypeOf,ve=Object.prototype.hasOwnProperty;var ge=(t,e)=>{for(var o in e)k(t,o,{get:e[o],enumerable:!0})},Y=(t,e,o,s)=>{if(e&&typeof e=="object"||typeof e=="function")for(let n of pe(e))!ve.call(t,n)&&n!==o&&k(t,n,{get:()=>e[n],enumerable:!(s=ue(e,n))||s.enumerable});return t};var w=(t,e,o)=>(o=t!=null?he(me(t)):{},Y(e||!t||!t.__esModule?k(o,"default",{value:t,enumerable:!0}):o,t)),fe=t=>Y(k({},"__esModule",{value:!0}),t);var Be={};ge(Be,{activate:()=>ke,deactivate:()=>Fe});module.exports=fe(Be);var l=w(require("vscode")),K=require("node:path");var h=w(require("vscode")),q=require("node:path"),Q="Prometheus";function we(t){switch(t){case"BLOCKER":case"HIGH":return h.DiagnosticSeverity.Error;case"MEDIUM":return h.DiagnosticSeverity.Warning;case"LOW":return h.DiagnosticSeverity.Information;case"TECH_DEBT":return h.DiagnosticSeverity.Hint}}function X(t){let e=Math.max(0,(t.line??1)-1),o=new h.Range(e,0,e,Number.MAX_SAFE_INTEGER),s=new h.Diagnostic(o,t.suggestion?`${t.message}

Suggestion: ${t.suggestion}`:t.message,we(t.severity));return s.source=Q,s.code=t.category,s}var F=class{collection;constructor(){this.collection=h.languages.createDiagnosticCollection(Q)}setAll(e,o){let s=new Map;for(let n of e){let i=(0,q.join)(o,n.file),r=h.Uri.file(i).toString(),c=s.get(r)??[];c.push(X(n)),s.set(r,c)}this.collection.clear();for(let[n,i]of s)this.collection.set(h.Uri.parse(n),i)}setForFile(e,o){this.collection.set(e,o.map(X))}clearForFile(e){this.collection.delete(e)}clear(){this.collection.clear()}dispose(){this.collection.dispose()}};var m=w(require("vscode")),B=class{item;constructor(){this.item=m.window.createStatusBarItem(m.StatusBarAlignment.Left,100),this.item.command="prometheus.health",this.item.tooltip="Prometheus Governance \u2014 click to view health score",this.showInactive(),this.item.show()}showLoading(){this.item.text="$(sync~spin) Prometheus",this.item.tooltip="Prometheus Governance \u2014 analysing\u2026",this.item.backgroundColor=void 0}showHealth(e,o){let{score:s,grade:n}=e;n==="A+"||n==="A"?(this.item.text=`$(shield) ${n}  ${s}`,this.item.backgroundColor=void 0):n==="B"||n==="C"?(this.item.text=`$(warning) ${n}  ${s}`,this.item.backgroundColor=new m.ThemeColor("statusBarItem.warningBackground")):(this.item.text=`$(error) ${n}  ${s}`,this.item.backgroundColor=new m.ThemeColor("statusBarItem.errorBackground"));let i=o===0?"No findings":`${o} finding${o===1?"":"s"}`;this.item.tooltip=new m.MarkdownString(`**Prometheus Governance** \u2014 Health Score

Grade: **${n}**   Score: **${s}/100**

${i}

_Click to open health dashboard_`)}showScanNeeded(){this.item.text="$(warning) Prometheus: scan needed",this.item.tooltip='Prometheus Governance \u2014 run "Prometheus: Scan Repository" to start',this.item.backgroundColor=new m.ThemeColor("statusBarItem.warningBackground")}showNotInstalled(){this.item.text="$(error) Prometheus: not installed",this.item.tooltip="prometheus-governance not found \u2014 run: npm install --save-dev prometheus-governance",this.item.backgroundColor=new m.ThemeColor("statusBarItem.errorBackground")}showInactive(){this.item.text="$(shield) Prometheus",this.item.tooltip="Prometheus Governance",this.item.backgroundColor=void 0}hide(){this.item.hide()}show(){this.item.show()}dispose(){this.item.dispose()}};var d=w(require("vscode")),N=require("node:path"),Z=["BLOCKER","HIGH","MEDIUM","LOW","TECH_DEBT"],be={BLOCKER:"Blocker",HIGH:"High",MEDIUM:"Medium",LOW:"Low",TECH_DEBT:"Tech Debt"},ee={BLOCKER:"error",HIGH:"error",MEDIUM:"warning",LOW:"info",TECH_DEBT:"lightbulb"},te={BLOCKER:new d.ThemeColor("errorForeground"),HIGH:new d.ThemeColor("errorForeground"),MEDIUM:new d.ThemeColor("editorWarning.foreground"),LOW:new d.ThemeColor("editorInfo.foreground"),TECH_DEBT:new d.ThemeColor("editorHint.foreground")},H=class extends d.TreeItem{constructor(o,s,n){let i=s.length,r=`${be[o]}  (${i})`,c=i===0?d.TreeItemCollapsibleState.None:o==="BLOCKER"||o==="HIGH"||!n?d.TreeItemCollapsibleState.Expanded:d.TreeItemCollapsibleState.Collapsed;super(r,c);this.severity=o;this.findings=s;this.iconPath=new d.ThemeIcon(ee[o],te[o]),this.contextValue="severityGroup",this.description=i===0?"none":void 0}kind="group"},W=class extends d.TreeItem{constructor(o,s){super(o.message,d.TreeItemCollapsibleState.None);this.finding=o;this.description=(0,N.basename)(o.file),this.tooltip=new d.MarkdownString(`**${o.severity}** \xB7 \`${o.category}\`

${o.message}`+(o.suggestion?`

_${o.suggestion}_`:"")),this.iconPath=new d.ThemeIcon(ee[o.severity],te[o.severity]),this.contextValue="finding";let n=(0,N.join)(s,o.file),i=Math.max(0,(o.line??1)-1);this.command={command:"vscode.open",title:"Open File",arguments:[d.Uri.file(n),{selection:new d.Range(i,0,i,0),preview:!0}]}}kind="finding"},S=class extends d.TreeItem{kind="empty";constructor(e){super(e,d.TreeItemCollapsibleState.None),this.iconPath=new d.ThemeIcon("pass-filled"),this.contextValue="empty"}},M=class{_onDidChangeTreeData=new d.EventEmitter;onDidChangeTreeData=this._onDidChangeTreeData.event;findings=[];workspaceRoot="";state="idle";refresh(e,o){this.findings=e,this.workspaceRoot=o,this.state="ready",this._onDidChangeTreeData.fire()}setLoading(){this.state="loading",this._onDidChangeTreeData.fire()}setNoReport(){this.state="no-report",this._onDidChangeTreeData.fire()}setNotInstalled(){this.state="not-installed",this._onDidChangeTreeData.fire()}getTreeItem(e){return e}getChildren(e){if(e instanceof H)return e.findings.map(n=>new W(n,this.workspaceRoot));if(this.state==="loading")return[new S("Analysing\u2026")];if(this.state==="no-report")return[new S('Run "Prometheus: Scan Repository" to start')];if(this.state==="not-installed")return[new S("prometheus-governance not installed")];if(this.state==="idle")return[];if(this.findings.length===0)return[new S("All governance checks passed")];let o=this.findings.some(n=>n.severity==="BLOCKER"),s=new Map;for(let n of Z)s.set(n,[]);for(let n of this.findings)s.get(n.severity)?.push(n);return Z.filter(n=>(s.get(n)?.length??0)>0).map(n=>new H(n,s.get(n)??[],o))}dispose(){this._onDidChangeTreeData.dispose()}};var a=w(require("vscode")),ae=require("node:path"),ce=require("node:fs");var oe=require("node:child_process"),A=require("node:fs"),U=require("node:path"),se=require("node:util"),ye=(0,se.promisify)(oe.execFile),xe=45e3,Pe=10*1024*1024,b=class extends Error{constructor(e){super(`prometheus-governance not found in ${e}/node_modules/.bin/prometheus.
Run: npm install --save-dev prometheus-governance`),this.name="PrometheusNotFoundError"}},v=class extends Error{constructor(){super('.prometheus/report.json not found \u2014 run "Prometheus: Scan Repository" first.'),this.name="PrometheusReportMissingError"}},O=class extends Error{constructor(e,o){super(`Failed to parse JSON from 'prometheus ${e}':
${o.slice(0,300)}`),this.name="PrometheusParseError"}};function E(t,e){if(e&&e.trim()){if((0,A.existsSync)(e.trim()))return e.trim();throw new b(t)}let o=(0,U.join)(t,"node_modules",".bin","prometheus");if((0,A.existsSync)(o))return o;throw new b(t)}function ne(t,e){try{return E(t,e),!0}catch{return!1}}function z(t){return(0,A.existsSync)((0,U.join)(t,".prometheus","report.json"))}async function L(t,e,o){let{stdout:s}=await ye(t,e,{cwd:o,timeout:xe,maxBuffer:Pe,env:{...process.env,FORCE_COLOR:"0"}});return s}async function V(t,e,o=[]){let s=E(t,e),n=["review","--json",...o],i;try{i=await L(s,n,t)}catch(r){throw r.stderr?.includes("report.json not found")?new v:r}try{return JSON.parse(i)}catch{throw new O("review",i)}}async function j(t,e){let o=E(t,e),s;try{s=await L(o,["health","--json"],t)}catch(n){throw n.stderr?.includes("report.json not found")?new v:n}try{return JSON.parse(s)}catch{throw new O("health",s)}}async function ie(t,e){let o=E(t,e);await L(o,["scan"],t)}async function re(t,e){let o=E(t,e);await L(o,["adapters"],t)}var R=w(require("vscode")),_=class t{static instance;panel;lastHealth=null;constructor(e){this.panel=R.window.createWebviewPanel("prometheus.health","Prometheus Health",R.ViewColumn.Beside,{enableScripts:!0,retainContextWhenHidden:!0,localResourceRoots:[e]}),this.panel.onDidDispose(()=>{t.instance=void 0})}static show(e,o){t.instance||(t.instance=new t(e));let s=t.instance;return s.lastHealth=o,s.panel.webview.html=De(o),s.panel.reveal(R.ViewColumn.Beside,!0),s}dispose(){this.panel.dispose(),t.instance=void 0}};function Se(t){return t==="A+"||t==="A"?"var(--vscode-charts-green, #73c991)":t==="B"?"var(--vscode-charts-blue, #4daafc)":t==="C"?"var(--vscode-charts-yellow, #cca700)":"var(--vscode-charts-red, #f48771)"}function Ce(t){let e=Math.max(0,Math.min(100,t)),o=t>=80?"var(--vscode-charts-green, #73c991)":t>=60?"var(--vscode-charts-yellow, #cca700)":"var(--vscode-charts-red, #f48771)";return`
    <div class="score-bar-track">
      <div class="score-bar-fill" style="width:${e}%;background:${o}"></div>
    </div>`}function Te(t){return t.deductions.length===0?'<p class="muted">No deductions \u2014 excellent governance posture.</p>':t.deductions.map(e=>`<div class="deduction-row">
          <span class="deduction-label">${y(e.label)}</span>
          <span class="deduction-amount">\u2212${e.amount}</span>
          ${e.detail?`<p class="deduction-detail">${y(e.detail)}</p>`:""}
        </div>`).join(`
`)}function Ee(t){return t.bonuses.length===0?"":`
    <section class="card">
      <h2>Bonuses</h2>
      ${t.bonuses.map(e=>`<div class="bonus-row"><span>${y(e.label)}</span><span class="bonus-amount">+${e.amount}</span></div>`).join(`
`)}
    </section>`}function Re(t){return t.priorityActions.length===0?'<p class="muted">Nothing to do \u2014 your governance is in great shape.</p>':`<ol class="action-list">${t.priorityActions.map(e=>`<li>${y(e)}</li>`).join(`
`)}</ol>`}function P(t,e){let o=typeof e=="boolean"?e?"\u2713":"\u2717":String(e),s=typeof e=="boolean"?e?"good":"bad":"";return`<tr><td>${y(t)}</td><td class="${s}">${y(o)}</td></tr>`}function y(t){return String(t).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;")}function De(t){let{score:e,grade:o}=t,s=Se(o);return`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <meta http-equiv="Content-Security-Policy"
        content="default-src 'none'; style-src 'unsafe-inline';" />
  <title>Prometheus Health</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    body {
      font-family: var(--vscode-font-family, system-ui, sans-serif);
      font-size: var(--vscode-font-size, 13px);
      color: var(--vscode-foreground);
      background: var(--vscode-editor-background);
      padding: 24px;
      max-width: 720px;
    }

    /* \u2500\u2500 Header \u2500\u2500 */
    .header {
      display: flex;
      align-items: center;
      gap: 24px;
      margin-bottom: 32px;
      padding-bottom: 24px;
      border-bottom: 1px solid var(--vscode-panel-border, #3c3c3c);
    }

    .score-circle {
      width: 96px;
      height: 96px;
      border-radius: 50%;
      border: 4px solid ${s};
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      flex-shrink: 0;
    }

    .score-number {
      font-size: 28px;
      font-weight: 700;
      line-height: 1;
      color: ${s};
    }

    .score-label {
      font-size: 10px;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      opacity: 0.6;
      margin-top: 2px;
    }

    .header-meta h1 {
      font-size: 18px;
      font-weight: 600;
      margin-bottom: 4px;
    }

    .grade-badge {
      display: inline-block;
      padding: 2px 10px;
      border-radius: 12px;
      background: ${s};
      color: var(--vscode-editor-background);
      font-weight: 700;
      font-size: 13px;
      margin-bottom: 8px;
    }

    .header-meta p {
      opacity: 0.7;
      font-size: 12px;
    }

    /* \u2500\u2500 Score bar \u2500\u2500 */
    .score-bar-track {
      height: 6px;
      background: var(--vscode-progressBar-background, #3c3c3c);
      border-radius: 3px;
      overflow: hidden;
      margin-top: 10px;
    }

    .score-bar-fill {
      height: 100%;
      border-radius: 3px;
      transition: width 0.4s ease;
    }

    /* \u2500\u2500 Cards \u2500\u2500 */
    .card {
      background: var(--vscode-editorWidget-background, var(--vscode-editor-background));
      border: 1px solid var(--vscode-panel-border, #3c3c3c);
      border-radius: 6px;
      padding: 16px 20px;
      margin-bottom: 16px;
    }

    .card h2 {
      font-size: 12px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      opacity: 0.6;
      margin-bottom: 12px;
    }

    /* \u2500\u2500 Deductions \u2500\u2500 */
    .deduction-row {
      display: flex;
      align-items: baseline;
      flex-wrap: wrap;
      gap: 8px;
      padding: 6px 0;
      border-bottom: 1px solid var(--vscode-panel-border, #3c3c3c);
    }

    .deduction-row:last-child { border-bottom: none; }

    .deduction-label { flex: 1; }

    .deduction-amount {
      color: var(--vscode-charts-red, #f48771);
      font-weight: 600;
      font-size: 12px;
    }

    .deduction-detail {
      width: 100%;
      opacity: 0.6;
      font-size: 11px;
      margin-top: 2px;
    }

    /* \u2500\u2500 Bonuses \u2500\u2500 */
    .bonus-row {
      display: flex;
      justify-content: space-between;
      padding: 5px 0;
    }

    .bonus-amount {
      color: var(--vscode-charts-green, #73c991);
      font-weight: 600;
    }

    /* \u2500\u2500 Actions \u2500\u2500 */
    .action-list {
      padding-left: 18px;
    }

    .action-list li {
      padding: 4px 0;
      line-height: 1.5;
    }

    /* \u2500\u2500 Totals table \u2500\u2500 */
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 12px;
    }

    td {
      padding: 5px 0;
      border-bottom: 1px solid var(--vscode-panel-border, #3c3c3c);
    }

    tr:last-child td { border-bottom: none; }

    td:last-child {
      text-align: right;
      font-weight: 600;
    }

    .good { color: var(--vscode-charts-green, #73c991); }
    .bad  { color: var(--vscode-charts-red,   #f48771); }

    .muted { opacity: 0.6; font-size: 12px; }

    /* \u2500\u2500 Footer \u2500\u2500 */
    .footer {
      margin-top: 24px;
      opacity: 0.45;
      font-size: 11px;
      text-align: center;
    }
  </style>
</head>
<body>
  <div class="header">
    <div class="score-circle">
      <span class="score-number">${y(String(e))}</span>
      <span class="score-label">/ 100</span>
    </div>
    <div class="header-meta">
      <h1>Governance Health</h1>
      <span class="grade-badge">${y(o)}</span>
      <p>Prometheus Governance \xB7 Holley Studios</p>
      ${Ce(e)}
    </div>
  </div>

  <section class="card">
    <h2>Priority Actions</h2>
    ${Re(t)}
  </section>

  <section class="card">
    <h2>Deductions</h2>
    ${Te(t)}
  </section>

  ${Ee(t)}

  <section class="card">
    <h2>Breakdown</h2>
    <table>
      ${P("New findings",t.totals.newFindings)}
      ${P("Baselined findings",t.totals.baselineFindings)}
      ${P("Drift events",t.totals.driftEvents)}
      ${P("Suppression issues",t.totals.suppressionIssues)}
      ${P("Baseline exists",t.totals.hasBaseline)}
      ${P("Scan report exists",t.totals.hasReport)}
      ${P("Report is fresh",t.totals.reportFresh)}
    </table>
  </section>

  <p class="footer">Prometheus Governance by Holley Studios</p>
</body>
</html>`}function D(t){if(t instanceof b){a.window.showErrorMessage(`Prometheus Governance: ${t.message}`,"Install now").then(o=>{if(o==="Install now"){let s=a.window.createTerminal("Prometheus");s.sendText("npm install --save-dev prometheus-governance"),s.show()}});return}if(t instanceof v){a.window.showWarningMessage(`Prometheus Governance: ${t.message}`,"Scan now").then(o=>{o==="Scan now"&&a.commands.executeCommand("prometheus.scan")});return}let e=t instanceof Error?t.message:String(t);a.window.showErrorMessage(`Prometheus Governance: ${e}`)}function de(t,e,o,s,n){let i=[];return i.push(a.commands.registerCommand("prometheus.scan",async()=>{let r=o();r.enable&&await a.window.withProgress({location:a.ProgressLocation.Notification,title:"Prometheus: Scanning repository\u2026",cancellable:!1},async()=>{try{await ie(e,r.binaryPath||void 0),a.window.showInformationMessage("Prometheus: Scan complete. Refreshing findings\u2026"),await s()}catch(c){D(c)}})})),i.push(a.commands.registerCommand("prometheus.reviewFile",async()=>{if(!o().enable)return;let c=a.window.activeTextEditor?.document;if(!c){a.window.showWarningMessage("Prometheus: No active file to review.");return}try{await n(c.uri),a.window.showInformationMessage(`Prometheus: Review complete for ${c.fileName.split("/").pop()}`)}catch(p){D(p)}})),i.push(a.commands.registerCommand("prometheus.health",async()=>{let r=o();r.enable&&await a.window.withProgress({location:a.ProgressLocation.Notification,title:"Prometheus: Loading health score\u2026",cancellable:!1},async()=>{try{let c=await j(e,r.binaryPath||void 0);_.show(t.extensionUri,c)}catch(c){D(c)}})})),i.push(a.commands.registerCommand("prometheus.adapters",async()=>{let r=o();r.enable&&await a.window.withProgress({location:a.ProgressLocation.Notification,title:"Prometheus: Regenerating AI adapters\u2026",cancellable:!1},async()=>{try{await re(e,r.binaryPath||void 0),a.window.showInformationMessage("Prometheus: AI adapter files updated (CLAUDE.md, GEMINI.md, .cursor/rules, \u2026)")}catch(c){D(c)}})})),i.push(a.commands.registerCommand("prometheus.openConfig",async()=>{let r=(0,ae.join)(e,".prometheus","config.json");if(!(0,ce.existsSync)(r)){a.window.showWarningMessage('Prometheus: .prometheus/config.json not found. Run "Prometheus: Scan Repository" first.');return}let c=await a.workspace.openTextDocument(a.Uri.file(r));await a.window.showTextDocument(c)})),i.push(a.commands.registerCommand("prometheus.refreshFindings",async()=>{if(o().enable)try{await s()}catch(c){D(c)}})),a.Disposable.from(...i)}var C=w(require("vscode")),le=require("node:path"),Ie={BLOCKER:"\u{1F534}",HIGH:"\u{1F7E0}",MEDIUM:"\u{1F7E1}",LOW:"\u{1F535}",TECH_DEBT:"\u26AA"},G=class{constructor(e,o){this.workspaceRoot=e;this.getFindings=o}provideHover(e,o){let s=(0,le.relative)(this.workspaceRoot,e.uri.fsPath).replace(/\\/g,"/");if(s.startsWith(".."))return null;let n=o.line+1,i=this.getFindings().filter(u=>u.file===s&&(u.line??1)===n);if(i.length===0)return null;let r=new C.MarkdownString("",!0);r.isTrusted=!1;for(let u=0;u<i.length;u++){let f=i[u],x=Ie[f.severity]??"\u2B1C";r.appendMarkdown(`**${x} ${f.severity}** &nbsp;\xB7&nbsp; \`${f.category}\`

`),r.appendMarkdown(`${f.message}

`),f.suggestion&&r.appendMarkdown(`**Fix:** ${f.suggestion}

`),u<i.length-1&&r.appendMarkdown(`---

`)}r.appendMarkdown(`---
_Prometheus Governance \u2014 use the \u{1F4A1} lightbulb to suppress_`);let c=o.line,p=new C.Range(c,0,c,Number.MAX_SAFE_INTEGER);return new C.Hover(r,p)}};var g=w(require("vscode")),$e="Prometheus",I=class{static providedCodeActionKinds=[g.CodeActionKind.QuickFix];provideCodeActions(e,o,s){return s.diagnostics.filter(i=>i.source===$e&&typeof i.code=="string").flatMap(i=>{let r=i.code,c=i.range.start.line,p=e.lineAt(c).text,f=`${/^(\s*)/.exec(p)?.[1]??""}// prometheus-disable-next-line ${r} -- reason: TODO
`,x=new g.CodeAction(`Suppress: ${r} (add prometheus-disable-next-line comment)`,g.CodeActionKind.QuickFix);return x.diagnostics=[i],x.isPreferred=!1,x.edit=new g.WorkspaceEdit,x.edit.insert(e.uri,new g.Position(c,0),f),[x]})}};function T(){let t=l.workspace.getConfiguration("prometheus");return{enable:t.get("enable",!0),runOnSave:t.get("runOnSave",!0),debounceMs:t.get("debounceMs",1e3),showStatusBar:t.get("showStatusBar",!0),binaryPath:t.get("binaryPath",""),autoScan:t.get("autoScan",!1)}}var J=class{constructor(e,o){this.context=e;this.workspaceRoot=o,this.diagnostics=new F,this.statusBar=new B,this.treeProvider=new M,this.disposables.push(this.diagnostics,this.statusBar,this.treeProvider)}disposables=[];diagnostics;statusBar;treeProvider;workspaceRoot;allFindings=[];debounceTimer;async activate(){let e=T();if(!e.enable)return;let o=l.window.createTreeView("prometheus.findingsView",{treeDataProvider:this.treeProvider,showCollapseAll:!0});this.disposables.push(o),await l.commands.executeCommand("setContext","prometheus.active",!0);let s=de(this.context,this.workspaceRoot,T,()=>this.runFullReview(),p=>this.reviewSingleFile(p));this.disposables.push(s);let n=l.languages.registerHoverProvider({scheme:"file"},new G(this.workspaceRoot,()=>this.allFindings));this.disposables.push(n);let i=l.languages.registerCodeActionsProvider({scheme:"file"},new I,{providedCodeActionKinds:I.providedCodeActionKinds});this.disposables.push(i);let r=l.workspace.onDidSaveTextDocument(p=>{let u=T();!u.enable||!u.runOnSave||this.isWatchedFile(p.uri)&&(clearTimeout(this.debounceTimer),this.debounceTimer=setTimeout(()=>void this.reviewSingleFile(p.uri),u.debounceMs))});this.disposables.push(r);let c=l.workspace.onDidChangeConfiguration(p=>{p.affectsConfiguration("prometheus")&&(T().showStatusBar?this.statusBar.show():this.statusBar.hide())});this.disposables.push(c),e.showStatusBar||this.statusBar.hide(),await this.runInitialAnalysis(e)}async runInitialAnalysis(e){if(!ne(this.workspaceRoot,e.binaryPath||void 0)){this.statusBar.showNotInstalled(),this.treeProvider.setNotInstalled(),l.window.showWarningMessage("Prometheus Governance: prometheus-governance is not installed in this project.","Install","Dismiss").then(o=>{if(o==="Install"){let s=l.window.createTerminal("Prometheus");s.sendText("npm install --save-dev prometheus-governance"),s.show()}});return}if(!z(this.workspaceRoot)){this.statusBar.showScanNeeded(),this.treeProvider.setNoReport(),e.autoScan?l.commands.executeCommand("prometheus.scan"):l.window.showInformationMessage("Prometheus Governance: No scan report found.","Scan now","Dismiss").then(o=>{o==="Scan now"&&l.commands.executeCommand("prometheus.scan")});return}await this.runFullReview()}async runFullReview(){let e=T();this.statusBar.showLoading(),this.treeProvider.setLoading();try{let o=await V(this.workspaceRoot,e.binaryPath||void 0);this.allFindings=o.findings,this.diagnostics.setAll(this.allFindings,this.workspaceRoot),this.treeProvider.refresh(this.allFindings,this.workspaceRoot),await this.refreshStatusBar(e)}catch(o){this.handleAnalysisError(o)}}async reviewSingleFile(e){let o=T();if(!z(this.workspaceRoot))return;let s=(0,K.relative)(this.workspaceRoot,e.fsPath);if(!(s.startsWith("..")||s.startsWith("/")))try{let n=await V(this.workspaceRoot,o.binaryPath||void 0,[s]);this.allFindings=[...this.allFindings.filter(i=>i.file!==s),...n.findings],this.diagnostics.setForFile(e,n.findings),this.treeProvider.refresh(this.allFindings,this.workspaceRoot),await this.refreshStatusBar(o)}catch(n){n instanceof v||this.handleAnalysisError(n)}}async refreshStatusBar(e){if(e.showStatusBar)try{let o=await j(this.workspaceRoot,e.binaryPath||void 0);this.statusBar.showHealth(o,this.allFindings.length)}catch{this.statusBar.showInactive()}}handleAnalysisError(e){if(e instanceof b){this.statusBar.showNotInstalled(),this.treeProvider.setNotInstalled();return}if(e instanceof v){this.statusBar.showScanNeeded(),this.treeProvider.setNoReport();return}let o=e instanceof Error?e.message:String(e);this.statusBar.showInactive(),l.window.showErrorMessage(`Prometheus Governance: ${o}`)}isWatchedFile(e){let o=(0,K.relative)(this.workspaceRoot,e.fsPath);if(o.startsWith("..")||o.startsWith("node_modules")||o.startsWith(".git")||o.startsWith(".prometheus")||o.startsWith("dist/"))return!1;let s=e.fsPath.slice(e.fsPath.lastIndexOf("."));return[".ts",".tsx",".js",".jsx",".mjs",".cjs",".json",".mdx"].includes(s)}dispose(){clearTimeout(this.debounceTimer),l.commands.executeCommand("setContext","prometheus.active",!1);for(let e of this.disposables)e.dispose()}},$;async function ke(t){let e=l.workspace.workspaceFolders;if(!e||e.length===0)return;let o=e[0].uri.fsPath;$=new J(t,o),t.subscriptions.push($),await $.activate()}function Fe(){$?.dispose(),$=void 0}0&&(module.exports={activate,deactivate});
//# sourceMappingURL=extension.js.map
