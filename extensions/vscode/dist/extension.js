"use strict";var se=Object.create;var C=Object.defineProperty;var ne=Object.getOwnPropertyDescriptor;var ie=Object.getOwnPropertyNames;var re=Object.getPrototypeOf,ae=Object.prototype.hasOwnProperty;var ce=(t,e)=>{for(var o in e)C(t,o,{get:e[o],enumerable:!0})},G=(t,e,o,s)=>{if(e&&typeof e=="object"||typeof e=="function")for(let n of ie(e))!ae.call(t,n)&&n!==o&&C(t,n,{get:()=>e[n],enumerable:!(s=ne(e,n))||s.enumerable});return t};var f=(t,e,o)=>(o=t!=null?se(re(t)):{},G(e||!t||!t.__esModule?C(o,"default",{value:t,enumerable:!0}):o,t)),de=t=>G(C({},"__esModule",{value:!0}),t);var Pe={};ce(Pe,{activate:()=>xe,deactivate:()=>Se});module.exports=de(Pe);var l=f(require("vscode")),A=require("node:path");var h=f(require("vscode")),_=require("node:path"),U="Prometheus";function le(t){switch(t){case"BLOCKER":case"HIGH":return h.DiagnosticSeverity.Error;case"MEDIUM":return h.DiagnosticSeverity.Warning;case"LOW":return h.DiagnosticSeverity.Information;case"TECH_DEBT":return h.DiagnosticSeverity.Hint}}function W(t){let e=Math.max(0,(t.line??1)-1),o=new h.Range(e,0,e,Number.MAX_SAFE_INTEGER),s=new h.Diagnostic(o,t.suggestion?`${t.message}

Suggestion: ${t.suggestion}`:t.message,le(t.severity));return s.source=U,s.code=t.category,s}var T=class{collection;constructor(){this.collection=h.languages.createDiagnosticCollection(U)}setAll(e,o){let s=new Map;for(let n of e){let r=(0,_.join)(o,n.file),a=h.Uri.file(r).toString(),d=s.get(a)??[];d.push(W(n)),s.set(a,d)}this.collection.clear();for(let[n,r]of s)this.collection.set(h.Uri.parse(n),r)}setForFile(e,o){this.collection.set(e,o.map(W))}clearForFile(e){this.collection.delete(e)}clear(){this.collection.clear()}dispose(){this.collection.dispose()}};var u=f(require("vscode")),E=class{item;constructor(){this.item=u.window.createStatusBarItem(u.StatusBarAlignment.Left,100),this.item.command="prometheus.health",this.item.tooltip="Prometheus Governance \u2014 click to view health score",this.showInactive(),this.item.show()}showLoading(){this.item.text="$(sync~spin) Prometheus",this.item.tooltip="Prometheus Governance \u2014 analysing\u2026",this.item.backgroundColor=void 0}showHealth(e,o){let{score:s,grade:n}=e;n==="A+"||n==="A"?(this.item.text=`$(shield) ${n}  ${s}`,this.item.backgroundColor=void 0):n==="B"||n==="C"?(this.item.text=`$(warning) ${n}  ${s}`,this.item.backgroundColor=new u.ThemeColor("statusBarItem.warningBackground")):(this.item.text=`$(error) ${n}  ${s}`,this.item.backgroundColor=new u.ThemeColor("statusBarItem.errorBackground"));let r=o===0?"No findings":`${o} finding${o===1?"":"s"}`;this.item.tooltip=new u.MarkdownString(`**Prometheus Governance** \u2014 Health Score

Grade: **${n}**   Score: **${s}/100**

${r}

_Click to open health dashboard_`)}showScanNeeded(){this.item.text="$(warning) Prometheus: scan needed",this.item.tooltip='Prometheus Governance \u2014 run "Prometheus: Scan Repository" to start',this.item.backgroundColor=new u.ThemeColor("statusBarItem.warningBackground")}showNotInstalled(){this.item.text="$(error) Prometheus: not installed",this.item.tooltip="prometheus-governance not found \u2014 run: npm install --save-dev prometheus-governance",this.item.backgroundColor=new u.ThemeColor("statusBarItem.errorBackground")}showInactive(){this.item.text="$(shield) Prometheus",this.item.tooltip="Prometheus Governance",this.item.backgroundColor=void 0}hide(){this.item.hide()}show(){this.item.show()}dispose(){this.item.dispose()}};var c=f(require("vscode")),R=require("node:path"),z=["BLOCKER","HIGH","MEDIUM","LOW","TECH_DEBT"],he={BLOCKER:"Blocker",HIGH:"High",MEDIUM:"Medium",LOW:"Low",TECH_DEBT:"Tech Debt"},V={BLOCKER:"error",HIGH:"error",MEDIUM:"warning",LOW:"info",TECH_DEBT:"lightbulb"},K={BLOCKER:new c.ThemeColor("errorForeground"),HIGH:new c.ThemeColor("errorForeground"),MEDIUM:new c.ThemeColor("editorWarning.foreground"),LOW:new c.ThemeColor("editorInfo.foreground"),TECH_DEBT:new c.ThemeColor("editorHint.foreground")},I=class extends c.TreeItem{constructor(o,s,n){let r=s.length,a=`${he[o]}  (${r})`,d=r===0?c.TreeItemCollapsibleState.None:o==="BLOCKER"||o==="HIGH"||!n?c.TreeItemCollapsibleState.Expanded:c.TreeItemCollapsibleState.Collapsed;super(a,d);this.severity=o;this.findings=s;this.iconPath=new c.ThemeIcon(V[o],K[o]),this.contextValue="severityGroup",this.description=r===0?"none":void 0}kind="group"},N=class extends c.TreeItem{constructor(o,s){super(o.message,c.TreeItemCollapsibleState.None);this.finding=o;this.description=(0,R.basename)(o.file),this.tooltip=new c.MarkdownString(`**${o.severity}** \xB7 \`${o.category}\`

${o.message}`+(o.suggestion?`

_${o.suggestion}_`:"")),this.iconPath=new c.ThemeIcon(V[o.severity],K[o.severity]),this.contextValue="finding";let n=(0,R.join)(s,o.file),r=Math.max(0,(o.line??1)-1);this.command={command:"vscode.open",title:"Open File",arguments:[c.Uri.file(n),{selection:new c.Range(r,0,r,0),preview:!0}]}}kind="finding"},w=class extends c.TreeItem{kind="empty";constructor(e){super(e,c.TreeItemCollapsibleState.None),this.iconPath=new c.ThemeIcon("pass-filled"),this.contextValue="empty"}},D=class{_onDidChangeTreeData=new c.EventEmitter;onDidChangeTreeData=this._onDidChangeTreeData.event;findings=[];workspaceRoot="";state="idle";refresh(e,o){this.findings=e,this.workspaceRoot=o,this.state="ready",this._onDidChangeTreeData.fire()}setLoading(){this.state="loading",this._onDidChangeTreeData.fire()}setNoReport(){this.state="no-report",this._onDidChangeTreeData.fire()}setNotInstalled(){this.state="not-installed",this._onDidChangeTreeData.fire()}getTreeItem(e){return e}getChildren(e){if(e instanceof I)return e.findings.map(n=>new N(n,this.workspaceRoot));if(this.state==="loading")return[new w("Analysing\u2026")];if(this.state==="no-report")return[new w('Run "Prometheus: Scan Repository" to start')];if(this.state==="not-installed")return[new w("prometheus-governance not installed")];if(this.state==="idle")return[];if(this.findings.length===0)return[new w("All governance checks passed")];let o=this.findings.some(n=>n.severity==="BLOCKER"),s=new Map;for(let n of z)s.set(n,[]);for(let n of this.findings)s.get(n.severity)?.push(n);return z.filter(n=>(s.get(n)?.length??0)>0).map(n=>new I(n,s.get(n)??[],o))}dispose(){this._onDidChangeTreeData.dispose()}};var i=f(require("vscode")),Z=require("node:path"),ee=require("node:fs");var J=require("node:child_process"),B=require("node:fs"),M=require("node:path"),Y=require("node:util"),ue=(0,Y.promisify)(J.execFile),pe=45e3,me=10*1024*1024,m=class extends Error{constructor(e){super(`prometheus-governance not found in ${e}/node_modules/.bin/prometheus.
Run: npm install --save-dev prometheus-governance`),this.name="PrometheusNotFoundError"}},p=class extends Error{constructor(){super('.prometheus/report.json not found \u2014 run "Prometheus: Scan Repository" first.'),this.name="PrometheusReportMissingError"}},$=class extends Error{constructor(e,o){super(`Failed to parse JSON from 'prometheus ${e}':
${o.slice(0,300)}`),this.name="PrometheusParseError"}};function y(t,e){if(e&&e.trim()){if((0,B.existsSync)(e.trim()))return e.trim();throw new m(t)}let o=(0,M.join)(t,"node_modules",".bin","prometheus");if((0,B.existsSync)(o))return o;throw new m(t)}function q(t,e){try{return y(t,e),!0}catch{return!1}}function O(t){return(0,B.existsSync)((0,M.join)(t,".prometheus","report.json"))}async function F(t,e,o){let{stdout:s}=await ue(t,e,{cwd:o,timeout:pe,maxBuffer:me,env:{...process.env,FORCE_COLOR:"0"}});return s}async function j(t,e,o=[]){let s=y(t,e),n=["review","--json",...o],r;try{r=await F(s,n,t)}catch(a){throw a.stderr?.includes("report.json not found")?new p:a}try{return JSON.parse(r)}catch{throw new $("review",r)}}async function k(t,e){let o=y(t,e),s;try{s=await F(o,["health","--json"],t)}catch(n){throw n.stderr?.includes("report.json not found")?new p:n}try{return JSON.parse(s)}catch{throw new $("health",s)}}async function X(t,e){let o=y(t,e);await F(o,["scan"],t)}async function Q(t,e){let o=y(t,e);await F(o,["adapters"],t)}var x=f(require("vscode")),H=class t{static instance;panel;lastHealth=null;constructor(e){this.panel=x.window.createWebviewPanel("prometheus.health","Prometheus Health",x.ViewColumn.Beside,{enableScripts:!0,retainContextWhenHidden:!0,localResourceRoots:[e]}),this.panel.onDidDispose(()=>{t.instance=void 0})}static show(e,o){t.instance||(t.instance=new t(e));let s=t.instance;return s.lastHealth=o,s.panel.webview.html=ye(o),s.panel.reveal(x.ViewColumn.Beside,!0),s}dispose(){this.panel.dispose(),t.instance=void 0}};function ve(t){return t==="A+"||t==="A"?"var(--vscode-charts-green, #73c991)":t==="B"?"var(--vscode-charts-blue, #4daafc)":t==="C"?"var(--vscode-charts-yellow, #cca700)":"var(--vscode-charts-red, #f48771)"}function ge(t){let e=Math.max(0,Math.min(100,t)),o=t>=80?"var(--vscode-charts-green, #73c991)":t>=60?"var(--vscode-charts-yellow, #cca700)":"var(--vscode-charts-red, #f48771)";return`
    <div class="score-bar-track">
      <div class="score-bar-fill" style="width:${e}%;background:${o}"></div>
    </div>`}function fe(t){return t.deductions.length===0?'<p class="muted">No deductions \u2014 excellent governance posture.</p>':t.deductions.map(e=>`<div class="deduction-row">
          <span class="deduction-label">${v(e.label)}</span>
          <span class="deduction-amount">\u2212${e.amount}</span>
          ${e.detail?`<p class="deduction-detail">${v(e.detail)}</p>`:""}
        </div>`).join(`
`)}function we(t){return t.bonuses.length===0?"":`
    <section class="card">
      <h2>Bonuses</h2>
      ${t.bonuses.map(e=>`<div class="bonus-row"><span>${v(e.label)}</span><span class="bonus-amount">+${e.amount}</span></div>`).join(`
`)}
    </section>`}function be(t){return t.priorityActions.length===0?'<p class="muted">Nothing to do \u2014 your governance is in great shape.</p>':`<ol class="action-list">${t.priorityActions.map(e=>`<li>${v(e)}</li>`).join(`
`)}</ol>`}function g(t,e){let o=typeof e=="boolean"?e?"\u2713":"\u2717":String(e),s=typeof e=="boolean"?e?"good":"bad":"";return`<tr><td>${v(t)}</td><td class="${s}">${v(o)}</td></tr>`}function v(t){return String(t).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;")}function ye(t){let{score:e,grade:o}=t,s=ve(o);return`<!DOCTYPE html>
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
      <span class="score-number">${v(String(e))}</span>
      <span class="score-label">/ 100</span>
    </div>
    <div class="header-meta">
      <h1>Governance Health</h1>
      <span class="grade-badge">${v(o)}</span>
      <p>Prometheus Governance \xB7 Holley Studios</p>
      ${ge(e)}
    </div>
  </div>

  <section class="card">
    <h2>Priority Actions</h2>
    ${be(t)}
  </section>

  <section class="card">
    <h2>Deductions</h2>
    ${fe(t)}
  </section>

  ${we(t)}

  <section class="card">
    <h2>Breakdown</h2>
    <table>
      ${g("New findings",t.totals.newFindings)}
      ${g("Baselined findings",t.totals.baselineFindings)}
      ${g("Drift events",t.totals.driftEvents)}
      ${g("Suppression issues",t.totals.suppressionIssues)}
      ${g("Baseline exists",t.totals.hasBaseline)}
      ${g("Scan report exists",t.totals.hasReport)}
      ${g("Report is fresh",t.totals.reportFresh)}
    </table>
  </section>

  <p class="footer">Prometheus Governance by Holley Studios</p>
</body>
</html>`}function S(t){if(t instanceof m){i.window.showErrorMessage(`Prometheus Governance: ${t.message}`,"Install now").then(o=>{if(o==="Install now"){let s=i.window.createTerminal("Prometheus");s.sendText("npm install --save-dev prometheus-governance"),s.show()}});return}if(t instanceof p){i.window.showWarningMessage(`Prometheus Governance: ${t.message}`,"Scan now").then(o=>{o==="Scan now"&&i.commands.executeCommand("prometheus.scan")});return}let e=t instanceof Error?t.message:String(t);i.window.showErrorMessage(`Prometheus Governance: ${e}`)}function te(t,e,o,s,n){let r=[];return r.push(i.commands.registerCommand("prometheus.scan",async()=>{let a=o();a.enable&&await i.window.withProgress({location:i.ProgressLocation.Notification,title:"Prometheus: Scanning repository\u2026",cancellable:!1},async()=>{try{await X(e,a.binaryPath||void 0),i.window.showInformationMessage("Prometheus: Scan complete. Refreshing findings\u2026"),await s()}catch(d){S(d)}})})),r.push(i.commands.registerCommand("prometheus.reviewFile",async()=>{if(!o().enable)return;let d=i.window.activeTextEditor?.document;if(!d){i.window.showWarningMessage("Prometheus: No active file to review.");return}try{await n(d.uri),i.window.showInformationMessage(`Prometheus: Review complete for ${d.fileName.split("/").pop()}`)}catch(oe){S(oe)}})),r.push(i.commands.registerCommand("prometheus.health",async()=>{let a=o();a.enable&&await i.window.withProgress({location:i.ProgressLocation.Notification,title:"Prometheus: Loading health score\u2026",cancellable:!1},async()=>{try{let d=await k(e,a.binaryPath||void 0);H.show(t.extensionUri,d)}catch(d){S(d)}})})),r.push(i.commands.registerCommand("prometheus.adapters",async()=>{let a=o();a.enable&&await i.window.withProgress({location:i.ProgressLocation.Notification,title:"Prometheus: Regenerating AI adapters\u2026",cancellable:!1},async()=>{try{await Q(e,a.binaryPath||void 0),i.window.showInformationMessage("Prometheus: AI adapter files updated (CLAUDE.md, GEMINI.md, .cursor/rules, \u2026)")}catch(d){S(d)}})})),r.push(i.commands.registerCommand("prometheus.openConfig",async()=>{let a=(0,Z.join)(e,".prometheus","config.json");if(!(0,ee.existsSync)(a)){i.window.showWarningMessage('Prometheus: .prometheus/config.json not found. Run "Prometheus: Scan Repository" first.');return}let d=await i.workspace.openTextDocument(i.Uri.file(a));await i.window.showTextDocument(d)})),r.push(i.commands.registerCommand("prometheus.refreshFindings",async()=>{if(o().enable)try{await s()}catch(d){S(d)}})),i.Disposable.from(...r)}function b(){let t=l.workspace.getConfiguration("prometheus");return{enable:t.get("enable",!0),runOnSave:t.get("runOnSave",!0),debounceMs:t.get("debounceMs",1e3),showStatusBar:t.get("showStatusBar",!0),binaryPath:t.get("binaryPath",""),autoScan:t.get("autoScan",!1)}}var L=class{constructor(e,o){this.context=e;this.workspaceRoot=o,this.diagnostics=new T,this.statusBar=new E,this.treeProvider=new D,this.disposables.push(this.diagnostics,this.statusBar,this.treeProvider)}disposables=[];diagnostics;statusBar;treeProvider;workspaceRoot;allFindings=[];debounceTimer;async activate(){let e=b();if(!e.enable)return;let o=l.window.createTreeView("prometheus.findingsView",{treeDataProvider:this.treeProvider,showCollapseAll:!0});this.disposables.push(o),await l.commands.executeCommand("setContext","prometheus.active",!0);let s=te(this.context,this.workspaceRoot,b,()=>this.runFullReview(),a=>this.reviewSingleFile(a));this.disposables.push(s);let n=l.workspace.onDidSaveTextDocument(a=>{let d=b();!d.enable||!d.runOnSave||this.isWatchedFile(a.uri)&&(clearTimeout(this.debounceTimer),this.debounceTimer=setTimeout(()=>void this.reviewSingleFile(a.uri),d.debounceMs))});this.disposables.push(n);let r=l.workspace.onDidChangeConfiguration(a=>{a.affectsConfiguration("prometheus")&&(b().showStatusBar?this.statusBar.show():this.statusBar.hide())});this.disposables.push(r),e.showStatusBar||this.statusBar.hide(),await this.runInitialAnalysis(e)}async runInitialAnalysis(e){if(!q(this.workspaceRoot,e.binaryPath||void 0)){this.statusBar.showNotInstalled(),this.treeProvider.setNotInstalled(),l.window.showWarningMessage("Prometheus Governance: prometheus-governance is not installed in this project.","Install","Dismiss").then(o=>{if(o==="Install"){let s=l.window.createTerminal("Prometheus");s.sendText("npm install --save-dev prometheus-governance"),s.show()}});return}if(!O(this.workspaceRoot)){this.statusBar.showScanNeeded(),this.treeProvider.setNoReport(),e.autoScan?l.commands.executeCommand("prometheus.scan"):l.window.showInformationMessage("Prometheus Governance: No scan report found.","Scan now","Dismiss").then(o=>{o==="Scan now"&&l.commands.executeCommand("prometheus.scan")});return}await this.runFullReview()}async runFullReview(){let e=b();this.statusBar.showLoading(),this.treeProvider.setLoading();try{let o=await j(this.workspaceRoot,e.binaryPath||void 0);this.allFindings=o.findings,this.diagnostics.setAll(this.allFindings,this.workspaceRoot),this.treeProvider.refresh(this.allFindings,this.workspaceRoot),await this.refreshStatusBar(e)}catch(o){this.handleAnalysisError(o)}}async reviewSingleFile(e){let o=b();if(!O(this.workspaceRoot))return;let s=(0,A.relative)(this.workspaceRoot,e.fsPath);if(!(s.startsWith("..")||s.startsWith("/")))try{let n=await j(this.workspaceRoot,o.binaryPath||void 0,[s]);this.allFindings=[...this.allFindings.filter(r=>r.file!==s),...n.findings],this.diagnostics.setForFile(e,n.findings),this.treeProvider.refresh(this.allFindings,this.workspaceRoot),await this.refreshStatusBar(o)}catch(n){n instanceof p||this.handleAnalysisError(n)}}async refreshStatusBar(e){if(e.showStatusBar)try{let o=await k(this.workspaceRoot,e.binaryPath||void 0);this.statusBar.showHealth(o,this.allFindings.length)}catch{this.statusBar.showInactive()}}handleAnalysisError(e){if(e instanceof m){this.statusBar.showNotInstalled(),this.treeProvider.setNotInstalled();return}if(e instanceof p){this.statusBar.showScanNeeded(),this.treeProvider.setNoReport();return}let o=e instanceof Error?e.message:String(e);this.statusBar.showInactive(),l.window.showErrorMessage(`Prometheus Governance: ${o}`)}isWatchedFile(e){let o=(0,A.relative)(this.workspaceRoot,e.fsPath);if(o.startsWith("..")||o.startsWith("node_modules")||o.startsWith(".git")||o.startsWith(".prometheus")||o.startsWith("dist/"))return!1;let s=e.fsPath.slice(e.fsPath.lastIndexOf("."));return[".ts",".tsx",".js",".jsx",".mjs",".cjs",".json",".mdx"].includes(s)}dispose(){clearTimeout(this.debounceTimer),l.commands.executeCommand("setContext","prometheus.active",!1);for(let e of this.disposables)e.dispose()}},P;async function xe(t){let e=l.workspace.workspaceFolders;if(!e||e.length===0)return;let o=e[0].uri.fsPath;P=new L(t,o),t.subscriptions.push(P),await P.activate()}function Se(){P?.dispose(),P=void 0}0&&(module.exports={activate,deactivate});
//# sourceMappingURL=extension.js.map
