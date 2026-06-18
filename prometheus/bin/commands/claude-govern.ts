/**
 * prometheus claude:govern — install/uninstall/status/check Claude Code governance hooks.
 *
 * Subcommands:
 *   claude:govern install     Write PreToolUse + Stop hooks to .claude/settings.json
 *   claude:govern uninstall   Remove prometheus hooks from .claude/settings.json
 *   claude:govern status      Show current hook installation state
 *   claude:govern check       Internal: run by the PreToolUse hook — reads stdin, exits 0 or 2
 */
import {
  installGovernanceHooks,
  uninstallGovernanceHooks,
  getGovernanceHooksStatus,
  runPreToolCheck,
  GOVERNANCE_VERSION,
} from '../../claude-govern.js';

export async function cmdClaudeGovern(argv: string[]): Promise<void> {
  const sub = argv[0];
  const root = process.cwd();

  switch (sub) {
    case 'install': {
      installGovernanceHooks(root);
      const status = getGovernanceHooksStatus(root);
      console.log(`\nPrometheus governance hooks installed (v${GOVERNANCE_VERSION})`);
      console.log(`  Settings: ${status.settingsPath}`);
      console.log('\n  PreToolUse (Write)  ✓  blocks BLOCKER violations before writes');
      console.log('  PreToolUse (Edit)   ✓  blocks BLOCKER violations before edits');
      console.log('  Stop                ✓  checks adapter drift after each session');
      console.log('\nClaude Code Auto Mode is now governed by Prometheus.\n');
      break;
    }

    case 'uninstall': {
      uninstallGovernanceHooks(root);
      console.log('\nPrometheus governance hooks removed from .claude/settings.json\n');
      break;
    }

    case 'status': {
      const status = getGovernanceHooksStatus(root);
      console.log('\nPrometheus Claude Code Governance\n');
      console.log(`  Settings:           ${status.settingsPath}`);
      console.log(`  Version:            ${status.version ?? 'not installed'}`);
      console.log('');
      console.log(`  PreToolUse (Write): ${status.preToolUseWrite ? '✓ installed' : '✗ missing'}`);
      console.log(`  PreToolUse (Edit):  ${status.preToolUseEdit ? '✓ installed' : '✗ missing'}`);
      console.log(`  Stop (drift):       ${status.stopDrift ? '✓ installed' : '✗ missing'}`);
      console.log('');
      if (status.installed) {
        console.log('  Auto Mode is governed — Prometheus blocks BLOCKER violations in real time.\n');
      } else {
        console.log('  Run `prometheus claude:govern install` to enable Auto Mode governance.\n');
        process.exitCode = 1;
      }
      break;
    }

    case 'check': {
      // Called by Claude Code as a PreToolUse hook — reads stdin, exits 0 or 2
      await runPreToolCheck(root);
      break;
    }

    default: {
      console.error(
        'Usage: prometheus claude:govern <install|uninstall|status|check>\n\n' +
        '  install    Install governance hooks into .claude/settings.json\n' +
        '  uninstall  Remove governance hooks\n' +
        '  status     Show current hook state\n' +
        '  check      [internal] PreToolUse hook — reads stdin, blocks on violations\n',
      );
      process.exitCode = 1;
    }
  }
}
