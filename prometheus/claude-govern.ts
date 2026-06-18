/**
 * Claude Code governance hooks — intercepts Write/Edit tool calls in Auto Mode
 * and blocks BLOCKER-severity Prometheus violations before they land on disk.
 *
 * Integration points:
 *   1. `prometheus claude:govern install` — writes hooks to .claude/settings.json
 *   2. `prometheus claude:govern check`   — run by Claude Code as a PreToolUse hook
 *   3. permissions.ts — preserves hooks when autopilot overwrites settings
 *
 * Hook behavior:
 *   - PreToolUse (Write/Edit): blocks if content has any BLOCKER finding → exit 2
 *   - Stop: runs `prometheus drift` to catch adapter drift at session end
 */
import {
  existsSync,
  readFileSync,
  writeFileSync,
  mkdirSync,
} from 'node:fs';
import { join, dirname, extname } from 'node:path';
import { PROMETHEUS_RULES } from './rules/registry.js';
import { loadConfig, CONFIG_DEFAULTS } from './config.js';
import type { ScanResult, DetectInput, Finding } from './types.js';

// ── Constants ─────────────────────────────────────────────────────────────────

export const GOVERNANCE_VERSION = '1.0.0';
const GOVERNANCE_MARKER = '_prometheus_governance';

const HOOK_COMMAND_CHECK = 'npx --no-install prometheus claude:govern check';
const HOOK_COMMAND_DRIFT = 'npx --no-install prometheus drift --quiet 2>&1 || true';

const GOVERNANCE_HOOKS = {
  PreToolUse: [
    {
      matcher: 'Write',
      hooks: [{ type: 'command', command: HOOK_COMMAND_CHECK }],
    },
    {
      matcher: 'Edit',
      hooks: [{ type: 'command', command: HOOK_COMMAND_CHECK }],
    },
  ],
  Stop: [
    {
      hooks: [{ type: 'command', command: HOOK_COMMAND_DRIFT }],
    },
  ],
};

// ── Status type ───────────────────────────────────────────────────────────────

export interface GovernanceHookStatus {
  installed: boolean;
  version: string | null;
  preToolUseWrite: boolean;
  preToolUseEdit: boolean;
  stopDrift: boolean;
  settingsPath: string;
}

// ── Settings file helpers ─────────────────────────────────────────────────────

function settingsPath(root: string): string {
  return join(root, '.claude', 'settings.json');
}

function readSettings(root: string): Record<string, unknown> {
  const p = settingsPath(root);
  if (!existsSync(p)) return {};
  try {
    return JSON.parse(readFileSync(p, 'utf8')) as Record<string, unknown>;
  } catch {
    return {};
  }
}

function writeSettings(root: string, settings: Record<string, unknown>): void {
  const p = settingsPath(root);
  mkdirSync(dirname(p), { recursive: true });
  writeFileSync(p, JSON.stringify(settings, null, 2) + '\n', 'utf8');
}

// ── Install / uninstall ───────────────────────────────────────────────────────

export function installGovernanceHooks(root: string): void {
  const settings = readSettings(root);
  const merged = mergeGovernanceHooks(settings);
  writeSettings(root, merged);
}

export function uninstallGovernanceHooks(root: string): void {
  const settings = readSettings(root);
  const hooks = settings['hooks'] as Record<string, unknown[]> | undefined;
  if (!hooks) return;

  // Remove only the prometheus entries from PreToolUse
  if (Array.isArray(hooks['PreToolUse'])) {
    hooks['PreToolUse'] = (hooks['PreToolUse'] as unknown[]).filter((entry) => {
      const e = entry as { hooks?: Array<{ command?: string }> };
      return !e.hooks?.some((h) => h.command === HOOK_COMMAND_CHECK);
    });
    if (hooks['PreToolUse'].length === 0) delete hooks['PreToolUse'];
  }

  // Remove only the prometheus drift entry from Stop
  if (Array.isArray(hooks['Stop'])) {
    hooks['Stop'] = (hooks['Stop'] as unknown[]).filter((entry) => {
      const e = entry as { hooks?: Array<{ command?: string }> };
      return !e.hooks?.some((h) => h.command === HOOK_COMMAND_DRIFT);
    });
    if (hooks['Stop'].length === 0) delete hooks['Stop'];
  }

  if (Object.keys(hooks).length === 0) delete settings['hooks'];
  delete settings[GOVERNANCE_MARKER];

  writeSettings(root, settings);
}

// ── Status ────────────────────────────────────────────────────────────────────

export function getGovernanceHooksStatus(root: string): GovernanceHookStatus {
  const settings = readSettings(root);
  const hooks = settings['hooks'] as Record<string, unknown[]> | undefined;
  const version = typeof settings[GOVERNANCE_MARKER] === 'string'
    ? settings[GOVERNANCE_MARKER] as string
    : null;

  const preToolUse = (hooks?.['PreToolUse'] ?? []) as Array<{ matcher?: string; hooks?: Array<{ command?: string }> }>;
  const stop = (hooks?.['Stop'] ?? []) as Array<{ hooks?: Array<{ command?: string }> }>;

  const hasCheck = (matcher: string) =>
    preToolUse.some((e) => e.matcher === matcher && e.hooks?.some((h) => h.command === HOOK_COMMAND_CHECK));

  const hasStopDrift = stop.some((e) => e.hooks?.some((h) => h.command === HOOK_COMMAND_DRIFT));

  const installed = hasCheck('Write') && hasCheck('Edit') && hasStopDrift;

  return {
    installed,
    version,
    preToolUseWrite: hasCheck('Write'),
    preToolUseEdit: hasCheck('Edit'),
    stopDrift: hasStopDrift,
    settingsPath: settingsPath(root),
  };
}

// ── Merge / extract (used by permissions.ts to preserve hooks) ────────────────

/**
 * Merges governance hooks into an existing settings object (non-destructive).
 * Called by autopilot's writePermissionProfile to preserve hooks across sessions.
 */
export function mergeGovernanceHooks(
  settings: Record<string, unknown>,
): Record<string, unknown> {
  const result = { ...settings };
  const existing = (result['hooks'] as Record<string, unknown[]> | undefined) ?? {};
  const merged: Record<string, unknown[]> = { ...existing };

  // Merge PreToolUse — deduplicate by matcher + command
  const existingPre = (merged['PreToolUse'] ?? []) as Array<{ matcher?: string; hooks?: unknown[] }>;
  for (const entry of GOVERNANCE_HOOKS.PreToolUse) {
    const alreadyPresent = existingPre.some(
      (e) =>
        e.matcher === entry.matcher &&
        (e.hooks as Array<{ command?: string }>).some((h) => h.command === HOOK_COMMAND_CHECK),
    );
    if (!alreadyPresent) existingPre.push(entry);
  }
  merged['PreToolUse'] = existingPre;

  // Merge Stop — deduplicate by command
  const existingStop = (merged['Stop'] ?? []) as Array<{ hooks?: Array<{ command?: string }> }>;
  const stopAlreadyPresent = existingStop.some((e) =>
    e.hooks?.some((h) => h.command === HOOK_COMMAND_DRIFT),
  );
  if (!stopAlreadyPresent) existingStop.push(...GOVERNANCE_HOOKS.Stop);
  merged['Stop'] = existingStop;

  result['hooks'] = merged;
  result[GOVERNANCE_MARKER] = GOVERNANCE_VERSION;
  return result;
}

/**
 * Extracts only the governance-related hooks from a settings object.
 * Returns the hooks sub-object, or null if no governance hooks are present.
 * Used by permissions.ts to pull hooks out of existing settings before overwriting.
 */
export function extractGovernanceHooks(
  settings: Record<string, unknown>,
): Record<string, unknown[]> | null {
  const hooks = settings['hooks'] as Record<string, unknown[]> | undefined;
  if (!hooks) return null;

  const preToolUse = ((hooks['PreToolUse'] ?? []) as Array<{ hooks?: Array<{ command?: string }> }>).filter((e) =>
    e.hooks?.some((h) => h.command === HOOK_COMMAND_CHECK),
  );
  const stop = ((hooks['Stop'] ?? []) as Array<{ hooks?: Array<{ command?: string }> }>).filter((e) =>
    e.hooks?.some((h) => h.command === HOOK_COMMAND_DRIFT),
  );

  if (preToolUse.length === 0 && stop.length === 0) return null;

  const extracted: Record<string, unknown[]> = {};
  if (preToolUse.length > 0) extracted['PreToolUse'] = preToolUse;
  if (stop.length > 0) extracted['Stop'] = stop;
  return extracted;
}

// ── PreToolUse hook check (stdin → exit 0 or exit 2) ─────────────────────────

/** Minimal ScanResult skeleton — rules read from changedFiles, not scan metadata. */
function emptyScan(): ScanResult {
  return {
    _generatedSections: [],
    generatedAt: new Date().toISOString(),
    scanVersion: '0',
    pages: [],
    apiRoutes: [],
    componentCount: 0,
    sharedUiFiles: [],
    designSystemFiles: [],
    storeFiles: [],
    testFiles: [],
    largeFiles: [],
    riskyFiles: [],
    scriptFiles: [],
    envFiles: [],
    clientBoundaryRisks: [],
    languages: [],
    detectedStacks: [],
  };
}

/**
 * Run by Claude Code as a PreToolUse hook.
 * Reads tool input from stdin, scans file content for BLOCKER violations.
 * Exits 2 (block) if any found; exits 0 (allow) otherwise.
 * Exits 0 on any error — never block due to internal failure.
 */
export async function runPreToolCheck(root: string): Promise<void> {
  let raw = '';
  try {
    raw = await readStdin();
  } catch {
    process.exit(0); // no stdin — allow
  }

  if (!raw.trim()) process.exit(0);

  let input: { tool_name?: string; tool_input?: Record<string, unknown> };
  try {
    input = JSON.parse(raw) as typeof input;
  } catch {
    process.exit(0); // malformed JSON — allow
  }

  const toolName = input.tool_name;
  if (toolName !== 'Write' && toolName !== 'Edit') process.exit(0);

  const toolInput = input.tool_input ?? {};
  const filePath = typeof toolInput['file_path'] === 'string' ? toolInput['file_path'] : '';
  if (!filePath) process.exit(0);

  // For Write: scan full content. For Edit: scan only the new_string being introduced.
  const content =
    toolName === 'Write'
      ? (typeof toolInput['content'] === 'string' ? toolInput['content'] : '')
      : (typeof toolInput['new_string'] === 'string' ? toolInput['new_string'] : '');

  if (!content.trim()) process.exit(0);

  // Ignore unrecognized file types (binary, lock files, etc.)
  const ext = extname(filePath).toLowerCase();
  const KNOWN_EXTS = new Set([
    '.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs',
    '.py', '.go', '.rb', '.rs', '.java', '.kt', '.swift',
    '.graphql', '.gql', '.tf', '.tfvars',
    '.vue', '.svelte', '.astro',
    '.json', '.yaml', '.yml', '.toml',
    '.sh', '.bash', '.zsh',
    '.env', '.env.local', '.env.production',
  ]);
  if (ext && !KNOWN_EXTS.has(ext)) process.exit(0);

  // Load config (graceful fallback to defaults if not in a prometheus project)
  let config = CONFIG_DEFAULTS;
  try {
    config = loadConfig(root);
  } catch {
    // not a prometheus project — use defaults
  }

  // Run only BLOCKER-severity rules
  const blockerRules = PROMETHEUS_RULES.filter((r) => r.severity === 'BLOCKER');

  const detectInput: DetectInput = {
    scan: emptyScan(),
    config,
    changedFiles: [{ path: filePath, content }],
  };

  const findings: Finding[] = [];
  for (const rule of blockerRules) {
    try {
      findings.push(...rule.detect(detectInput));
    } catch {
      // rule failed — skip it, never block on error
    }
  }

  if (findings.length === 0) process.exit(0);

  // Format block message for Claude Code to show to the user
  const lines: string[] = ['🚫 Prometheus blocked this write — BLOCKER violation(s) found:\n'];
  for (const f of findings) {
    lines.push(`  [${f.category.toUpperCase()}] ${f.message}`);
    if (f.line) lines.push(`  File: ${f.file}:${f.line}`);
    if (f.suggestion) lines.push(`  Fix:  ${f.suggestion}`);
    lines.push('');
  }
  lines.push('Resolve the violation(s) above before writing this file.');

  process.stdout.write(lines.join('\n'));
  process.exit(2);
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function readStdin(): Promise<string> {
  return new Promise((resolve, reject) => {
    if (process.stdin.isTTY) {
      resolve('');
      return;
    }
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (chunk) => { data += chunk; });
    process.stdin.on('end', () => resolve(data));
    process.stdin.on('error', reject);
  });
}
