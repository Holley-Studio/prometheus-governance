/**
 * Prometheus CLI entry point.
 * Dispatches to command handlers; each handler is a thin wrapper over core modules.
 *
 * Usage:  vite-node bin/cli.ts <command> [flags] [files...]
 */

import { cmdInit } from './commands/init.ts';
import { cmdScan } from './commands/scan.ts';
import { cmdReview } from './commands/review.ts';
import { cmdValidate } from './commands/validate.ts';
import { cmdAudit } from './commands/audit.ts';
import { cmdDoctor } from './commands/doctor.ts';
import { cmdAdapters } from './commands/adapters.ts';
import { cmdCiCheck } from './commands/ci-check.ts';
import { cmdCatalog } from './commands/catalog.ts';
import { cmdAgentCreate } from './commands/agent-create.ts';
import { cmdSkillCreate } from './commands/skill-create.ts';
import { cmdDrift } from './commands/drift.ts';
import { cmdBaseline } from './commands/baseline.ts';
import { cmdExplain } from './commands/explain.ts';
import { cmdSuppressions } from './commands/suppressions.ts';
import { cmdMetrics } from './commands/metrics.ts';
import { cmdPacks } from './commands/packs.ts';
import { cmdHealth } from './commands/health.ts';
import { cmdCiGate } from './commands/ci-gate.ts';
import { cmdFix } from './commands/fix.ts';
import { cmdUpdate } from './commands/update.ts';
import { cmdHooks } from './commands/hooks.ts';
import { cmdWatch } from './commands/watch.ts';
import { cmdDiff } from './commands/diff.ts';
import { cmdReport } from './commands/report.ts';
import { cmdAiLint } from './commands/ai-lint.ts';
import { cmdPackCreate } from './commands/pack-create.ts';
import { cmdPackPublish } from './commands/pack-publish.ts';
import { cmdAutopilot } from './commands/autopilot.ts';
import { cmdClaudeGovern } from './commands/claude-govern.ts';

const COMMANDS: Record<string, (argv: string[]) => Promise<void>> = {
  init: cmdInit,
  scan: cmdScan,
  review: cmdReview,
  validate: cmdValidate,
  audit: cmdAudit,
  doctor: cmdDoctor,
  adapters: cmdAdapters,
  'ci-check': cmdCiCheck,
  drift: cmdDrift,
  'baseline:create': (argv) => cmdBaseline('create', argv),
  'baseline:update': (argv) => cmdBaseline('update', argv),
  'baseline:report': (argv) => cmdBaseline('report', argv),
  explain: cmdExplain,
  'suppressions:audit': (argv) => cmdSuppressions('audit', argv),
  metrics: cmdMetrics,
  'pack:list': (argv) => cmdPacks('list', argv),
  'pack:validate': (argv) => cmdPacks('validate', argv),
  'pack:create': cmdPackCreate,
  'pack:publish': cmdPackPublish,
  health: cmdHealth,
  ci: cmdCiGate,
  fix: cmdFix,
  report: cmdReport,
  'ai-lint': cmdAiLint,
  'ai-lint:init': (argv) => cmdAiLint(['--from-ai-config', ...argv]),
  update: cmdUpdate,
  watch: cmdWatch,
  diff: cmdDiff,
  'hooks': (argv) => cmdHooks(['install', ...argv]),
  'hooks:install':   (argv) => cmdHooks(['install',   ...argv]),
  'hooks:uninstall': (argv) => cmdHooks(['uninstall', ...argv]),
  'hooks:status':    (argv) => cmdHooks(['status',    ...argv]),
  'catalog:list': (argv) => cmdCatalog(['list', ...argv]),
  'catalog:validate': (argv) => cmdCatalog(['validate', ...argv]),
  'catalog:enable': (argv) => cmdCatalog(['enable', ...argv]),
  'catalog:disable': (argv) => cmdCatalog(['disable', ...argv]),
  'catalog:profiles': (argv) => cmdCatalog(['profiles', ...argv]),
  'agent:create': cmdAgentCreate,
  'skill:create': cmdSkillCreate,
  'autopilot': (argv) => cmdAutopilot(argv),
  'autopilot:validate': (argv) => cmdAutopilot(['validate', ...argv]),
  'autopilot:start': (argv) => cmdAutopilot(['start', ...argv]),
  'autopilot:resume': (argv) => cmdAutopilot(['resume', ...argv]),
  'autopilot:cancel': () => cmdAutopilot(['cancel']),
  'autopilot:status': () => cmdAutopilot(['status']),
  'autopilot:revert': (argv) => cmdAutopilot(['revert', ...argv]),
  'autopilot:open-pr':  (argv) => cmdAutopilot(['open-pr', ...argv]),
  'autopilot:generate': (argv) => cmdAutopilot(['generate', ...argv]),
  'autopilot:review':   (argv) => cmdAutopilot(['review', ...argv]),
  'autopilot:stats':    ()     => cmdAutopilot(['stats']),
  'claude:govern':          (argv) => cmdClaudeGovern(argv),
  'claude:govern:install':  ()     => cmdClaudeGovern(['install']),
  'claude:govern:uninstall': ()    => cmdClaudeGovern(['uninstall']),
  'claude:govern:status':   ()     => cmdClaudeGovern(['status']),
  'claude:govern:check':    ()     => cmdClaudeGovern(['check']),
};

const argv = process.argv.slice(2); // ['command', ...flags]
const command = argv[0];

if (!command || command === '--help' || command === 'help') {
  console.log(`
Prometheus — AI Repo Governance

  A governance layer for AI coding assistants (Claude, Gemini, Cursor, Copilot, Codex).
  Detects unsafe patterns, keeps adapter files fresh, and gates CI automatically.

SETUP
  init                     Scaffold .prometheus/ governance folder
  init --interactive        Interactive wizard — detect framework, pick adapters, configure CI
  init --from-ai-config    Read CLAUDE.md/.cursorrules and generate .prometheus/config.json
  scan                     Analyse repo structure → .prometheus/report.json
  adapters                 Regenerate all AI adapter files (CLAUDE.md, etc.)
  update                   Convenience: scan + adapters + drift check in one command
  watch                    Real-time review — re-runs on every file change
    --clear                  Clear terminal on each update
    --debounce=<ms>          Debounce delay (default: 400ms)

HOOKS  (governance checks in git hooks — no extra dependencies)
  hooks install            Install pre-commit + pre-push hooks in .git/hooks/
  hooks install --husky    Install in .husky/ (committed, team-wide)
  hooks uninstall          Remove prometheus blocks from hooks
  hooks status             Show current hook state

CLAUDE CODE AUTO MODE  (real-time governance when Claude Code runs autonomously)
  claude:govern install    Install PreToolUse + Stop hooks into .claude/settings.json
  claude:govern uninstall  Remove governance hooks
  claude:govern status     Show hook installation state

REVIEW & VALIDATE
  review                   Run all rules, print findings
  validate                 Run rules, exit 1 on BLOCKER/HIGH (use in CI)
    --base=<branch>          Only check files changed vs. <branch>
    --no-baseline            Ignore baseline when computing exit code
  validate --json          Machine-readable findings
  validate --sarif         SARIF 2.1.0 output (GitHub Code Scanning, VS Code, JetBrains)
  validate --markdown      Markdown summary for PR comments

REPORT
  report                   Generate a visual governance report
  report --html            Self-contained HTML report (default)
  report --out=<path>      Write to file (default: .prometheus/report.html)
  report --open            Open in browser after writing
  report --json            Machine-readable findings JSON
  report --markdown        Markdown summary

BASELINES  (suppress known debt, focus CI on new issues)
  baseline:create          Snapshot current findings as baseline
    --force                  Overwrite existing baseline
  baseline:update          Update baseline with resolved/new findings
  baseline:report          Show baselined findings

DIFF
  diff                     Compare stored findings baseline vs. current scan
    --baseline=<path>        Path to baseline findings JSON (default: .prometheus/findings.json)
    --base=<branch>          Only review files changed vs. <branch>
    --all                    Review all files (default: scan-based checks only)
    --fail-on=<severity>     Exit 1 when new findings meet this severity (default: BLOCKER)
    --save                   Save current findings as the new baseline after diffing
    --json                   Machine-readable JSON output

DRIFT DETECTION
  drift                    Detect stale adapters and missing required files
  drift --json

GOVERNANCE HEALTH
  health                   Governance score 0–100 with grade and priority actions
    --fail --threshold=<n>   Exit 1 if score is below n (default 60)
  health --json
  ci                       Combined gate: validate + drift + suppressions + health
    --base=<branch>
    --no-baseline
    --health-threshold=<n>
  ci --json

AI BEHAVIOR FILE LINTER
  ai-lint                  Lint CLAUDE.md/.cursorrules/GEMINI.md for governance gaps
    --json                   Machine-readable JSON
    --markdown               Markdown report
  ai-lint --from-ai-config Detect stack from AI config and generate .prometheus/config.json
    --dry-run                Preview without writing

SUPPRESSIONS
  suppressions:audit       Find expired, missing-reason, or blanket suppressions
  suppressions:audit --json

EXPLAIN & DISCOVER
  explain <rule-id>        Why a rule exists, examples, agents, skills
  explain <category>       Explain by category name
  explain file <path>      Rules active on a specific file
  explain finding <fp>     Rule for a baseline fingerprint
  explain --list           All rules with severity and description

FIX
  fix                      Auto-fix safe violations (dry-run by default)
    --apply                  Write changes to disk
    --rule=<id>              Fix only this rule

METRICS
  metrics                  Governance analytics (local-first, no telemetry)
  metrics --record         Append snapshot to .prometheus/metrics-history.jsonl
  metrics --history        Show trend over last N snapshots
  metrics --json

PACKS
  pack:list                Show installed rule packs
  pack:validate            Validate pack manifests
  pack:create <@scope/name>  Scaffold a new pack with rules/, agents/, skills/
    --author="My Org"        Set author field in pack.json
    --dry-run                Preview files without writing
  pack:publish [name]       Compile, validate, and npm publish a pack
    --compile                  Run tsup to compile rules/index.ts first
    --dry-run                  Preview without publishing
    --access=<level>           npm publish access (default: public)
    --tag=<tag>                npm dist-tag (e.g. --tag=beta)

CATALOG
  catalog:list             List all agents and skills
  catalog:validate         Validate catalog frontmatter
  catalog:enable           Enable agents/skills into .prometheus/registry.json
  catalog:disable          Disable agents/skills
  catalog:profiles         List profiles
  agent:create             Scaffold a new agent file
  skill:create             Scaffold a new skill file

AUTOPILOT  (disabled by default — enable in .prometheus/config.json)
  autopilot validate <plan>     Validate plan file, generate .review.md
  autopilot start <plan>        Run plan autonomously (prompts CONFIRMED)
    --yes                         Skip CONFIRMED prompt (warnings still shown)
    --dry-run                     Parse and display without executing
  autopilot resume <plan>       Resume from last completed task
  autopilot cancel              Stop running session after current task
  autopilot status              Show current session state
  autopilot revert [session]    Delete autopilot branch, archive journal
  autopilot open-pr [session]   Push branch, create draft PR

DIAGNOSTICS
  doctor                   Check installation health
  audit                    Detailed file-level audit report
  ci-check                 Adapter freshness CI check (legacy; use 'ci' instead)

GLOBAL FLAGS
  --json                   Machine-readable JSON output
  --markdown               Markdown output (great for PR comments)
  --dry-run                Preview changes without writing files

EXAMPLES
  prometheus scan && prometheus validate --base=main
  prometheus ci --base=main --health-threshold=75
  prometheus explain missing_api_auth
  prometheus baseline:create && prometheus validate
  prometheus metrics --record
  prometheus fix --apply
`);
  process.exit(0);
}

const handler = COMMANDS[command];
if (!handler) {
  process.stderr.write(`prometheus: unknown command "${command}"\n`);
  process.stderr.write(`Available: ${Object.keys(COMMANDS).join(', ')}\n`);
  process.exit(1);
}

handler(argv.slice(1)).catch((err: unknown) => {
  const msg = err instanceof Error ? err.message : String(err);
  process.stderr.write(`prometheus ${command}: ${msg}\n`);
  process.exit(1);
});
