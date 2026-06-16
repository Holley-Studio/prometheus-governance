/**
 * Prometheus Governance — VS Code Extension
 * by Holley Studios
 *
 * Entry point. Wires together all subsystems:
 *   - DiagnosticsManager  → inline squiggles per file
 *   - StatusBarManager    → health grade always visible
 *   - FindingsTreeProvider → grouped findings in Explorer
 *   - HealthPanel         → webview dashboard
 *   - Commands            → palette + tree view actions
 *   - File watcher        → debounced re-review on save
 *
 * Activation: triggered automatically when a workspace contains
 * .prometheus/config.json (declared in package.json activationEvents).
 *
 * Lifecycle:
 *   activate()   → build subsystems, run initial analysis
 *   deactivate() → VS Code calls this; all disposables auto-clean
 */

import * as vscode from 'vscode';
import { relative } from 'node:path';

import { DiagnosticsManager } from './diagnostics.js';
import { StatusBarManager } from './statusBar.js';
import { FindingsTreeProvider } from './treeView.js';
import { registerCommands } from './commands.js';
import { PrometheusHoverProvider } from './hover.js';
import { PrometheusCodeActionProvider } from './codeAction.js';
import {
  runReview,
  runHealth,
  isInstalled,
  hasReport,
  PrometheusNotFoundError,
  PrometheusReportMissingError,
} from './runner.js';

import type { ExtensionConfig, Finding } from './types.js';

// ── Config helper ─────────────────────────────────────────────────────────────

function readConfig(): ExtensionConfig {
  const cfg = vscode.workspace.getConfiguration('prometheus');
  return {
    enable: cfg.get<boolean>('enable', true),
    runOnSave: cfg.get<boolean>('runOnSave', true),
    debounceMs: cfg.get<number>('debounceMs', 1000),
    showStatusBar: cfg.get<boolean>('showStatusBar', true),
    binaryPath: cfg.get<string>('binaryPath', ''),
    autoScan: cfg.get<boolean>('autoScan', false),
  };
}

// ── Extension class ───────────────────────────────────────────────────────────

class PrometheusExtension implements vscode.Disposable {
  private readonly disposables: vscode.Disposable[] = [];
  private readonly diagnostics: DiagnosticsManager;
  private readonly statusBar: StatusBarManager;
  private readonly treeProvider: FindingsTreeProvider;

  private workspaceRoot: string;
  private allFindings: Finding[] = [];
  private debounceTimer: ReturnType<typeof setTimeout> | undefined;

  constructor(
    private readonly context: vscode.ExtensionContext,
    workspaceRoot: string,
  ) {
    this.workspaceRoot = workspaceRoot;

    this.diagnostics = new DiagnosticsManager();
    this.statusBar = new StatusBarManager();
    this.treeProvider = new FindingsTreeProvider();

    this.disposables.push(this.diagnostics, this.statusBar, this.treeProvider);
  }

  async activate(): Promise<void> {
    const cfg = readConfig();
    if (!cfg.enable) return;

    // Register tree view
    const treeView = vscode.window.createTreeView('prometheus.findingsView', {
      treeDataProvider: this.treeProvider,
      showCollapseAll: true,
    });
    this.disposables.push(treeView);

    // Set context flag so tree view & menus are visible
    await vscode.commands.executeCommand(
      'setContext',
      'prometheus.active',
      true,
    );

    // Register all commands
    const commands = registerCommands(
      this.context,
      this.workspaceRoot,
      readConfig,
      () => this.runFullReview(),
      (uri) => this.reviewSingleFile(uri),
    );
    this.disposables.push(commands);

    // Hover provider — rich tooltips on findings
    const hoverProvider = vscode.languages.registerHoverProvider(
      { scheme: 'file' },
      new PrometheusHoverProvider(this.workspaceRoot, () => this.allFindings),
    );
    this.disposables.push(hoverProvider);

    // Code action provider — suppress quick-fix lightbulbs
    const codeActionProvider = vscode.languages.registerCodeActionsProvider(
      { scheme: 'file' },
      new PrometheusCodeActionProvider(),
      { providedCodeActionKinds: PrometheusCodeActionProvider.providedCodeActionKinds },
    );
    this.disposables.push(codeActionProvider);

    // File save watcher (debounced)
    const saveWatcher = vscode.workspace.onDidSaveTextDocument((doc) => {
      const cfg = readConfig();
      if (!cfg.enable || !cfg.runOnSave) return;
      if (!this.isWatchedFile(doc.uri)) return;

      clearTimeout(this.debounceTimer);
      this.debounceTimer = setTimeout(
        () => void this.reviewSingleFile(doc.uri),
        cfg.debounceMs,
      );
    });
    this.disposables.push(saveWatcher);

    // Config change watcher
    const cfgWatcher = vscode.workspace.onDidChangeConfiguration((e) => {
      if (e.affectsConfiguration('prometheus')) {
        const updated = readConfig();
        if (updated.showStatusBar) {
          this.statusBar.show();
        } else {
          this.statusBar.hide();
        }
      }
    });
    this.disposables.push(cfgWatcher);

    // Hide status bar if disabled in config
    if (!cfg.showStatusBar) {
      this.statusBar.hide();
    }

    // Initial analysis
    await this.runInitialAnalysis(cfg);
  }

  private async runInitialAnalysis(cfg: ExtensionConfig): Promise<void> {
    if (!isInstalled(this.workspaceRoot, cfg.binaryPath || undefined)) {
      this.statusBar.showNotInstalled();
      this.treeProvider.setNotInstalled();

      void vscode.window.showWarningMessage(
        'Prometheus Governance: prometheus-governance is not installed in this project.',
        'Install',
        'Dismiss',
      ).then((choice) => {
        if (choice === 'Install') {
          const terminal = vscode.window.createTerminal('Prometheus');
          terminal.sendText('npm install --save-dev prometheus-governance');
          terminal.show();
        }
      });
      return;
    }

    if (!hasReport(this.workspaceRoot)) {
      this.statusBar.showScanNeeded();
      this.treeProvider.setNoReport();

      if (cfg.autoScan) {
        void vscode.commands.executeCommand('prometheus.scan');
      } else {
        void vscode.window.showInformationMessage(
          'Prometheus Governance: No scan report found.',
          'Scan now',
          'Dismiss',
        ).then((choice) => {
          if (choice === 'Scan now') {
            void vscode.commands.executeCommand('prometheus.scan');
          }
        });
      }
      return;
    }

    await this.runFullReview();
  }

  /** Runs a full repository review and refreshes all UI surfaces. */
  async runFullReview(): Promise<void> {
    const cfg = readConfig();
    this.statusBar.showLoading();
    this.treeProvider.setLoading();

    try {
      const output = await runReview(
        this.workspaceRoot,
        cfg.binaryPath || undefined,
      );
      this.allFindings = output.findings;

      // Update diagnostics for all files
      this.diagnostics.setAll(this.allFindings, this.workspaceRoot);

      // Update tree view
      this.treeProvider.refresh(this.allFindings, this.workspaceRoot);

      // Update status bar with health score
      await this.refreshStatusBar(cfg);
    } catch (err) {
      this.handleAnalysisError(err);
    }
  }

  /** Reviews a single file on save; updates only that file's diagnostics. */
  async reviewSingleFile(uri: vscode.Uri): Promise<void> {
    const cfg = readConfig();
    if (!hasReport(this.workspaceRoot)) return;

    const relPath = relative(this.workspaceRoot, uri.fsPath);
    if (relPath.startsWith('..') || relPath.startsWith('/')) return;

    try {
      const output = await runReview(
        this.workspaceRoot,
        cfg.binaryPath || undefined,
        [relPath],
      );

      // Merge: replace this file's findings in the global list
      this.allFindings = [
        ...this.allFindings.filter((f) => f.file !== relPath),
        ...output.findings,
      ];

      this.diagnostics.setForFile(uri, output.findings);
      this.treeProvider.refresh(this.allFindings, this.workspaceRoot);

      await this.refreshStatusBar(cfg);
    } catch (err) {
      if (!(err instanceof PrometheusReportMissingError)) {
        this.handleAnalysisError(err);
      }
    }
  }

  private async refreshStatusBar(cfg: ExtensionConfig): Promise<void> {
    if (!cfg.showStatusBar) return;

    try {
      const health = await runHealth(
        this.workspaceRoot,
        cfg.binaryPath || undefined,
      );
      this.statusBar.showHealth(health, this.allFindings.length);
    } catch {
      // Health score is a nice-to-have; don't surface the error
      this.statusBar.showInactive();
    }
  }

  private handleAnalysisError(err: unknown): void {
    if (err instanceof PrometheusNotFoundError) {
      this.statusBar.showNotInstalled();
      this.treeProvider.setNotInstalled();
      return;
    }

    if (err instanceof PrometheusReportMissingError) {
      this.statusBar.showScanNeeded();
      this.treeProvider.setNoReport();
      return;
    }

    const message = err instanceof Error ? err.message : String(err);
    this.statusBar.showInactive();
    void vscode.window.showErrorMessage(`Prometheus Governance: ${message}`);
  }

  /**
   * Returns true for TypeScript, JavaScript, JSX, TSX, MDX, and JSON files
   * that live inside the workspace (not in node_modules / .git).
   */
  private isWatchedFile(uri: vscode.Uri): boolean {
    const relPath = relative(this.workspaceRoot, uri.fsPath);

    if (relPath.startsWith('..')) return false;
    if (relPath.startsWith('node_modules')) return false;
    if (relPath.startsWith('.git')) return false;
    if (relPath.startsWith('.prometheus')) return false;
    if (relPath.startsWith('dist/')) return false;

    const ext = uri.fsPath.slice(uri.fsPath.lastIndexOf('.'));
    return ['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.json', '.mdx'].includes(ext);
  }

  dispose(): void {
    clearTimeout(this.debounceTimer);
    void vscode.commands.executeCommand('setContext', 'prometheus.active', false);
    for (const d of this.disposables) {
      d.dispose();
    }
  }
}

// ── VS Code entry points ──────────────────────────────────────────────────────

let extension: PrometheusExtension | undefined;

export async function activate(
  context: vscode.ExtensionContext,
): Promise<void> {
  const folders = vscode.workspace.workspaceFolders;
  if (!folders || folders.length === 0) return;

  const workspaceRoot = folders[0].uri.fsPath;

  extension = new PrometheusExtension(context, workspaceRoot);
  context.subscriptions.push(extension);

  await extension.activate();
}

export function deactivate(): void {
  extension?.dispose();
  extension = undefined;
}
