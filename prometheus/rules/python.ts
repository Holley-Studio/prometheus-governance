/**
 * Python Security Rules — PY_001–025
 *
 * Targets the predictable security failure modes of AI-generated Python code.
 * Covers FastAPI, Flask, Django, LangChain, and the OpenAI/Anthropic SDK.
 *
 * Research basis: same vibe-coding failure patterns as JavaScript — eval(), no
 * auth, SSRF, SQL injection — but expressed in Python idioms. AI assistants
 * generate functionally-correct Python but consistently skip rate limiting,
 * input validation, auth middleware, and safe deserialization.
 */

import type { PrometheusRule, DetectInput, Finding } from '../types';
import { classifySeverity } from '../severity';

// ── Helpers ───────────────────────────────────────────────────────────────────

function isPyFile(p: string) { return p.endsWith('.py'); }
function isPyTest(p: string) { return /(?:^|\/)(?:tests?|conftest|test_|_test)\b/.test(p); }

function lineOf(content: string, re: RegExp): number | undefined {
  const idx = content.split('\n').findIndex((l) => re.test(l));
  return idx >= 0 ? idx + 1 : undefined;
}

// ── Rules ─────────────────────────────────────────────────────────────────────

export const PYTHON_RULES: PrometheusRule[] = [

  // ── PY_001: eval() / exec() ──────────────────────────────────────────────
  {
    id: 'PY_001',
    category: 'py_eval_exec',
    description: 'eval() or exec() called with a non-literal argument — remote code execution risk.',
    severity: 'BLOCKER',
    tags: ['security', 'python', 'rce', 'vibe-coding'],
    sinceVersion: '1.2.0',
    explain: {
      why: 'eval() and exec() execute arbitrary Python code at runtime. When the argument is user-controlled or LLM-generated, an attacker can run any Python on the server — read secrets, spawn shells, or pivot to other systems. AI assistants frequently use eval() to "parse" JSON or expressions.',
      commonViolations: [
        'eval(request.json()["formula"])',
        'exec(llm_response.content)',
        'result = eval(f"calculate({user_input})")',
      ],
      goodExample: 'import ast\nresult = ast.literal_eval(user_input)  # safe: only literals',
      badExample: 'result = eval(user_input)  # ❌ RCE if user_input is malicious',
    },
    detect({ changedFiles = [], config }: DetectInput): Finding[] {
      const sev = classifySeverity('py_eval_exec', config.severityRules);
      const findings: Finding[] = [];
      const EVAL_RE = /\b(?:eval|exec)\s*\(\s*(?!['"](?:[^'"\\]|\\.)*['"])/;
      for (const { path, content } of changedFiles) {
        if (!isPyFile(path) || isPyTest(path)) continue;
        const lines = content.split('\n');
        lines.forEach((line, i) => {
          if (EVAL_RE.test(line) && !/^\s*#/.test(line)) {
            findings.push({
              severity: sev, category: 'py_eval_exec', file: path, line: i + 1,
              message: 'eval() or exec() called with a dynamic argument — potential RCE if user-controlled.',
              suggestion: 'Remove eval/exec. Use ast.literal_eval() for safe literal parsing or structured data models.',
            });
          }
        });
      }
      return findings;
    },
  },

  // ── PY_002: SQL injection via f-string / % formatting ────────────────────
  {
    id: 'PY_002',
    category: 'py_sql_injection',
    description: 'SQL query built with f-string or % formatting — SQL injection risk.',
    severity: 'BLOCKER',
    tags: ['security', 'python', 'sql-injection', 'vibe-coding'],
    sinceVersion: '1.2.0',
    explain: {
      why: 'Building SQL queries with f-strings or % string formatting allows attackers to escape the query context and run arbitrary SQL. AI assistants generate f-string SQL routinely because it reads naturally — but it is the #1 Python injection pattern.',
      commonViolations: [
        'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
        'db.execute("SELECT * FROM %s" % table_name)',
        'session.execute(text(f"DELETE FROM {table} WHERE id = {row_id}"))',
      ],
      goodExample: 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
      badExample: 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")  # ❌ SQL injection',
    },
    detect({ changedFiles = [], config }: DetectInput): Finding[] {
      const sev = classifySeverity('py_sql_injection', config.severityRules);
      const findings: Finding[] = [];
      // f-string in execute() OR string followed by % operator (string % variable)
      const SQL_RE = /\.execute\s*\(\s*f['"]|\.execute\s*\(\s*['"][^'"]*['"]\s*%\s*\w/;
      const RAW_RE = /(?:text|raw)\s*\(\s*f['"]/;
      for (const { path, content } of changedFiles) {
        if (!isPyFile(path) || isPyTest(path)) continue;
        const lines = content.split('\n');
        lines.forEach((line, i) => {
          if ((SQL_RE.test(line) || RAW_RE.test(line)) && !/^\s*#/.test(line)) {
            findings.push({
              severity: sev, category: 'py_sql_injection', file: path, line: i + 1,
              message: 'SQL query built with f-string or % formatting — vulnerable to SQL injection.',
              suggestion: 'Use parameterized queries: cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
            });
          }
        });
      }
      return findings;
    },
  },

  // ── PY_003: Hardcoded secrets ─────────────────────────────────────────────
  {
    id: 'PY_003',
    category: 'py_hardcoded_secret',
    description: 'Hardcoded secret, API key, or password found in Python source.',
    severity: 'BLOCKER',
    tags: ['security', 'python', 'secrets', 'vibe-coding'],
    sinceVersion: '1.2.0',
    explain: {
      why: 'Hardcoded credentials are permanently in git history even after deletion. They are extracted by automated scanners, leaked in CI logs, and shared in forks. AI assistants generate placeholder values like api_key = "sk-test-..." that users often ship unchanged.',
      commonViolations: [
        'OPENAI_API_KEY = "sk-abc123..."',
        'DATABASE_PASSWORD = "hunter2"',
        'client = OpenAI(api_key="sk-...")',
      ],
      goodExample: 'import os\nclient = OpenAI(api_key=os.environ["OPENAI_API_KEY"])',
      badExample: 'OPENAI_API_KEY = "sk-proj-abc123..."  # ❌ hardcoded credential',
    },
    detect({ changedFiles = [], config }: DetectInput): Finding[] {
      const sev = classifySeverity('py_hardcoded_secret', config.severityRules);
      const findings: Finding[] = [];
      const SECRET_VAR = /(?:api_?key|secret|password|passwd|token|credential|private_?key)\s*=\s*['"][^'"]{6,}['"]/i;
      const OPENAI_KEY = /sk-[a-zA-Z0-9]{20,}/;
      const ANTHROPIC_KEY = /sk-ant-[a-zA-Z0-9-]{20,}/;
      for (const { path, content } of changedFiles) {
        if (!isPyFile(path) || isPyTest(path)) continue;
        const lines = content.split('\n');
        lines.forEach((line, i) => {
          if (/^\s*#/.test(line)) return;
          if (SECRET_VAR.test(line) || OPENAI_KEY.test(line) || ANTHROPIC_KEY.test(line)) {
            findings.push({
              severity: sev, category: 'py_hardcoded_secret', file: path, line: i + 1,
              message: 'Hardcoded secret or API key detected.',
              suggestion: 'Use os.environ.get("API_KEY") or a secrets manager. Never commit credentials.',
            });
          }
        });
      }
      return findings;
    },
  },

  // ── PY_004: SSRF via requests with user-controlled URL ───────────────────
  {
    id: 'PY_004',
    category: 'py_ssrf',
    description: 'requests.get/post called with a variable URL — potential SSRF if user-controlled.',
    severity: 'BLOCKER',
    tags: ['security', 'python', 'ssrf', 'vibe-coding'],
    sinceVersion: '1.2.0',
    explain: {
      why: 'Server-Side Request Forgery lets attackers redirect server HTTP requests to internal services, the AWS metadata endpoint (169.254.169.254), or private networks. AI assistants generate proxy/fetch patterns like requests.get(url) where url comes from user input without destination validation.',
      commonViolations: [
        'url = request.args.get("url"); requests.get(url)',
        'response = httpx.get(body["webhook_url"])',
        'aiohttp.ClientSession().get(user_provided_endpoint)',
      ],
      goodExample: 'from urllib.parse import urlparse\nif urlparse(url).hostname not in ALLOWED_HOSTS:\n    raise ValueError("Disallowed host")\nrequests.get(url, timeout=10)',
      badExample: 'url = request.args.get("url")\nrequests.get(url)  # ❌ SSRF',
    },
    detect({ changedFiles = [], config }: DetectInput): Finding[] {
      const sev = classifySeverity('py_ssrf', config.severityRules);
      const findings: Finding[] = [];
      const SSRF_RE = /(?:requests|httpx|aiohttp\.ClientSession\(\))\s*\.(?:get|post|put|delete|request|fetch)\s*\(\s*(?!['"](?:https?:\/\/(?:api\.|cdn\.|static\.)))/;
      const URL_VALIDATE = /urlparse|validate_url|allowed_domains|is_safe_url|urllib\.parse/;
      for (const { path, content } of changedFiles) {
        if (!isPyFile(path)) continue;
        if (!SSRF_RE.test(content)) continue;
        if (URL_VALIDATE.test(content)) continue;
        const line = lineOf(content, SSRF_RE);
        findings.push({
          severity: sev, category: 'py_ssrf', file: path, line,
          message: 'HTTP request with potentially user-controlled URL — validate and allowlist destinations before making requests.',
          suggestion: 'Validate URLs against an allowlist: urllib.parse.urlparse(url).hostname in ALLOWED_HOSTS',
        });
      }
      return findings;
    },
  },

  // ── PY_005: FastAPI/Flask route with no auth ─────────────────────────────
  {
    id: 'PY_005',
    category: 'py_missing_auth',
    description: 'FastAPI or Flask route decorator with no authentication dependency or login_required.',
    severity: 'HIGH',
    tags: ['security', 'python', 'auth', 'fastapi', 'flask', 'vibe-coding'],
    sinceVersion: '1.2.0',
    explain: {
      why: 'AI assistants generate route handlers that implement the happy path (accept data, process it) but forget the auth check. Mutating endpoints (POST/PUT/PATCH/DELETE) without authentication allow any anonymous caller on the internet to modify data.',
      commonViolations: [
        '@app.post("/users") async def create_user(data: CreateUser): ...',
        '@router.delete("/items/{id}") async def delete_item(id: int): ...',
        '@app.put("/profile") async def update_profile(body: dict): ...',
      ],
      goodExample: '@router.post("/users")\nasync def create_user(\n    data: CreateUser,\n    current_user: User = Depends(get_current_user)\n): ...',
      badExample: '@app.post("/users")\nasync def create_user(data: CreateUser):  # ❌ no auth\n    await db.insert(data)',
    },
    detect({ changedFiles = [], config }: DetectInput): Finding[] {
      const sev = classifySeverity('py_missing_auth', config.severityRules);
      const findings: Finding[] = [];
      const ROUTE_RE = /(?:@app|@router|@blueprint)\s*\.\s*(?:post|put|patch|delete)\s*\(/;
      const AUTH_RE = /Depends\s*\(|login_required|require_auth|current_user|get_current_user|authenticate|security|HTTPBearer|OAuth2/;
      for (const { path, content } of changedFiles) {
        if (!isPyFile(path) || isPyTest(path)) continue;
        const lines = content.split('\n');
        for (let i = 0; i < lines.length; i++) {
          if (!ROUTE_RE.test(lines[i]!)) continue;
          const window = lines.slice(i, i + 10).join('\n');
          if (!AUTH_RE.test(window)) {
            findings.push({
              severity: sev, category: 'py_missing_auth', file: path, line: i + 1,
              message: 'Mutating route (POST/PUT/PATCH/DELETE) has no visible authentication.',
              suggestion: 'Add: async def handler(current_user: User = Depends(get_current_user)) — or use @login_required in Flask.',
            });
          }
        }
      }
      return findings;
    },
  },

  // ── PY_006: Shell injection via subprocess / os.system ───────────────────
  {
    id: 'PY_006',
    category: 'py_shell_injection',
    description: 'subprocess or os.system called with a dynamic string — shell injection risk.',
    severity: 'BLOCKER',
    tags: ['security', 'python', 'shell-injection', 'rce'],
    sinceVersion: '1.2.0',
    explain: {
      why: 'Passing user input to shell commands via os.system() or subprocess with shell=True allows attackers to inject shell metacharacters (;, |, &, $()) and execute arbitrary commands on the host. This is a full server takeover vector.',
      commonViolations: [
        'os.system(f"ffmpeg -i {filename} output.mp4")',
        'subprocess.call(f"convert {user_file}", shell=True)',
        'os.popen(f"identify {path}").read()',
      ],
      goodExample: 'subprocess.run(["ffmpeg", "-i", filename, "output.mp4"], shell=False)',
      badExample: 'os.system(f"ffmpeg -i {filename} output.mp4")  # ❌ shell injection',
    },
    detect({ changedFiles = [], config }: DetectInput): Finding[] {
      const sev = classifySeverity('py_shell_injection', config.severityRules);
      const findings: Finding[] = [];
      const SHELL_RE = /(?:subprocess\.(?:call|run|Popen|check_output|check_call)\s*\([^)]*shell\s*=\s*True|os\.system\s*\(\s*(?!['"]))/;
      const OS_POPEN = /os\.popen\s*\(\s*(?!['"])/;
      for (const { path, content } of changedFiles) {
        if (!isPyFile(path) || isPyTest(path)) continue;
        const lines = content.split('\n');
        lines.forEach((line, i) => {
          if (/^\s*#/.test(line)) return;
          if (SHELL_RE.test(line) || OS_POPEN.test(line)) {
            findings.push({
              severity: sev, category: 'py_shell_injection', file: path, line: i + 1,
              message: 'subprocess/os.system with shell=True or dynamic argument — potential shell injection.',
              suggestion: 'Use subprocess.run(["cmd", arg1, arg2], shell=False) with a list of arguments.',
            });
          }
        });
      }
      return findings;
    },
  },

  // ── PY_007: Pickle deserialization of untrusted data ─────────────────────
  {
    id: 'PY_007',
    category: 'py_pickle_deserialization',
    description: 'pickle.loads() or pickle.load() on data that may come from user input.',
    severity: 'BLOCKER',
    tags: ['security', 'python', 'deserialization', 'rce'],
    sinceVersion: '1.2.0',
    explain: {
      why: "pickle.loads() executes arbitrary Python code embedded in the serialized payload. Malicious pickle data can run shell commands, read files, and exfiltrate data. Even trusted-looking sources (S3, Redis) can be poisoned upstream — never unpickle data you didn't serialize yourself in the same process.",
      commonViolations: [
        'model = pickle.loads(request.body)',
        'obj = pickle.load(open(uploaded_file, "rb"))',
        'data = pickle.loads(redis_client.get(key))',
      ],
      goodExample: '# Use JSON or msgpack for data exchange\nimport json\ndata = json.loads(request.body)',
      badExample: 'data = pickle.loads(request.body)  # ❌ RCE if body is malicious',
    },
    detect({ changedFiles = [], config }: DetectInput): Finding[] {
      const sev = classifySeverity('py_pickle_deserialization', config.severityRules);
      const findings: Finding[] = [];
      const PICKLE_RE = /pickle\.loads?\s*\(/;
      for (const { path, content } of changedFiles) {
        if (!isPyFile(path) || isPyTest(path)) continue;
        const lines = content.split('\n');
        lines.forEach((line, i) => {
          if (PICKLE_RE.test(line) && !/^\s*#/.test(line)) {
            findings.push({
              severity: sev, category: 'py_pickle_deserialization', file: path, line: i + 1,
              message: 'pickle.loads() can execute arbitrary code — never deserialize untrusted data with pickle.',
              suggestion: 'Use json.loads(), msgpack, or a schema-validated format (Pydantic). Sign payloads if you must use pickle.',
            });
          }
        });
      }
      return findings;
    },
  },

  // ── PY_008: yaml.load() without safe Loader ──────────────────────────────
  {
    id: 'PY_008',
    category: 'py_yaml_load_unsafe',
    description: 'yaml.load() without a safe Loader — can execute arbitrary Python via !!python/object.',
    severity: 'HIGH',
    tags: ['security', 'python', 'deserialization'],
    sinceVersion: '1.2.0',
    explain: {
      why: "yaml.load() without Loader=yaml.SafeLoader supports the !!python/object YAML tag, which can instantiate arbitrary Python classes and execute code. The PyYAML docs explicitly warn against this. AI assistants use yaml.load() because it reads naturally.",
      commonViolations: [
        'config = yaml.load(open("config.yaml"))',
        'data = yaml.load(request.data)',
        'obj = yaml.load(content)',
      ],
      goodExample: 'config = yaml.safe_load(open("config.yaml"))',
      badExample: 'config = yaml.load(content)  # ❌ can execute !!python/object payloads',
    },
    detect({ changedFiles = [], config }: DetectInput): Finding[] {
      const sev = classifySeverity('py_yaml_load_unsafe', config.severityRules);
      const findings: Finding[] = [];
      const YAML_RE = /\byaml\.load\s*\(/;
      const SAFE_LOADER = /Loader\s*=\s*yaml\.(?:Safe|Base)Loader/;
      for (const { path, content } of changedFiles) {
        if (!isPyFile(path) || isPyTest(path)) continue;
        const lines = content.split('\n');
        lines.forEach((line, i) => {
          if (YAML_RE.test(line) && !SAFE_LOADER.test(line) && !/^\s*#/.test(line)) {
            findings.push({
              severity: sev, category: 'py_yaml_load_unsafe', file: path, line: i + 1,
              message: 'yaml.load() without Loader=yaml.SafeLoader can execute arbitrary Python objects.',
              suggestion: 'Replace with yaml.safe_load(data) or yaml.load(data, Loader=yaml.SafeLoader).',
            });
          }
        });
      }
      return findings;
    },
  },

  // ── PY_009: Path traversal ────────────────────────────────────────────────
  {
    id: 'PY_009',
    category: 'py_path_traversal',
    description: 'File opened with a path from request/user input without traversal protection.',
    severity: 'BLOCKER',
    tags: ['security', 'python', 'path-traversal', 'vibe-coding'],
    sinceVersion: '1.2.0',
    explain: {
      why: 'Path traversal (../../../etc/passwd) lets attackers read or write arbitrary files on the server. AI-generated file-serving endpoints pass user-supplied filenames directly to open() without checking that the resolved path stays inside the intended directory.',
      commonViolations: [
        'open(request.args.get("file"))',
        'with open(filename) as f:  # filename from query param',
        'Path(base_dir) / user_path  # no resolution check',
      ],
      goodExample: 'from pathlib import Path\nbase = Path("/var/uploads").resolve()\nsafe = (base / user_path).resolve()\nassert safe.is_relative_to(base)\nwith open(safe) as f: ...',
      badExample: 'with open(filename) as f:  # ❌ path traversal if filename is "../../../etc/passwd"',
    },
    detect({ changedFiles = [], config }: DetectInput): Finding[] {
      const sev = classifySeverity('py_path_traversal', config.severityRules);
      const findings: Finding[] = [];
      const OPEN_VAR = /\bopen\s*\(\s*(?:filename|filepath|path|file_path|name|user_file|request\.|body\.|data\[|params\[)/;
      const TRAVERSAL_GUARD = /\.resolve\(\)|\.is_relative_to\(|os\.path\.abspath|startswith\(/;
      for (const { path: filePath, content } of changedFiles) {
        if (!isPyFile(filePath) || isPyTest(filePath)) continue;
        if (!OPEN_VAR.test(content)) continue;
        if (TRAVERSAL_GUARD.test(content)) continue;
        const line = lineOf(content, OPEN_VAR);
        findings.push({
          severity: sev, category: 'py_path_traversal', file: filePath, line,
          message: 'File opened with a user-controlled path without traversal protection.',
          suggestion: 'Use pathlib: safe_path = (base_dir / user_path).resolve(); assert safe_path.is_relative_to(base_dir)',
        });
      }
      return findings;
    },
  },

  // ── PY_010: CORS wildcard in FastAPI ─────────────────────────────────────
  {
    id: 'PY_010',
    category: 'py_cors_wildcard',
    description: 'CORSMiddleware configured with allow_origins=["*"] — permits any origin.',
    severity: 'HIGH',
    tags: ['security', 'python', 'cors', 'fastapi', 'vibe-coding'],
    sinceVersion: '1.2.0',
    explain: {
      why: 'A CORS wildcard allows any website to make cross-origin requests to your API from a browser. Combined with credentials (cookies, auth headers), this can enable CSRF-like attacks where a malicious site reads protected data from authenticated users.',
      commonViolations: [
        'app.add_middleware(CORSMiddleware, allow_origins=["*"])',
        'origins = ["*"]; app.add_middleware(CORSMiddleware, allow_origins=origins)',
      ],
      goodExample: 'app.add_middleware(CORSMiddleware, allow_origins=["https://yourdomain.com"])',
      badExample: 'app.add_middleware(CORSMiddleware, allow_origins=["*"])  # ❌ CORS wildcard',
    },
    detect({ changedFiles = [], config }: DetectInput): Finding[] {
      const sev = classifySeverity('py_cors_wildcard', config.severityRules);
      const findings: Finding[] = [];
      const CORS_RE = /CORSMiddleware|add_middleware.*CORS/;
      const WILDCARD_RE = /allow_origins\s*=\s*\[\s*['"][*]['"]|allow_origins\s*=\s*\[\s*"[*]"/;
      for (const { path, content } of changedFiles) {
        if (!isPyFile(path)) continue;
        if (!CORS_RE.test(content) || !WILDCARD_RE.test(content)) continue;
        const line = lineOf(content, WILDCARD_RE);
        findings.push({
          severity: sev, category: 'py_cors_wildcard', file: path, line,
          message: 'CORS wildcard (allow_origins=["*"]) allows any domain to make cross-origin requests.',
          suggestion: 'Specify explicit origins: allow_origins=["https://yourdomain.com"]',
        });
      }
      return findings;
    },
  },

  // ── PY_011: Missing request timeout on HTTP calls ─────────────────────────
  {
    id: 'PY_011',
    category: 'py_no_request_timeout',
    description: 'requests.get/post with no timeout — server can hang indefinitely on slow upstream.',
    severity: 'MEDIUM',
    tags: ['reliability', 'python', 'availability'],
    sinceVersion: '1.2.0',
    explain: {
      why: "HTTP requests without a timeout block the worker thread indefinitely if the upstream server is slow or unresponsive. In production, this exhausts the thread pool and causes cascading failures across the entire application.",
      commonViolations: [
        'response = requests.get(url)',
        'data = requests.post(api_url, json=payload)',
        'r = httpx.get(endpoint)',
      ],
      goodExample: 'response = requests.get(url, timeout=10)',
      badExample: 'response = requests.get(url)  # ❌ hangs indefinitely',
    },
    detect({ changedFiles = [], config }: DetectInput): Finding[] {
      const sev = classifySeverity('py_no_request_timeout', config.severityRules);
      const findings: Finding[] = [];
      const TIMEOUT_RE = /timeout\s*=/;
      for (const { path, content } of changedFiles) {
        if (!isPyFile(path) || isPyTest(path)) continue;
        const lines = content.split('\n');
        lines.forEach((line, i) => {
          if (/^\s*#/.test(line)) return;
          if (/\brequests\s*\.\s*(?:get|post|put|patch|delete|request)\s*\(/.test(line) && !TIMEOUT_RE.test(line)) {
            findings.push({
              severity: sev, category: 'py_no_request_timeout', file: path, line: i + 1,
              message: 'HTTP request without timeout — will block indefinitely if upstream is slow.',
              suggestion: 'Add timeout: requests.get(url, timeout=10)',
            });
          }
        });
      }
      return findings;
    },
  },

  // ── PY_012: Debug mode left on in Flask/FastAPI ───────────────────────────
  {
    id: 'PY_012',
    category: 'py_debug_mode',
    description: 'Flask/uvicorn debug=True — exposes interactive debugger and verbose error pages in production.',
    severity: 'HIGH',
    tags: ['security', 'python', 'flask', 'fastapi', 'configuration'],
    sinceVersion: '1.2.0',
    explain: {
      why: "Flask's Werkzeug debugger exposes an interactive Python console in the browser when debug=True. Any error page becomes a remote code execution surface — attackers can run arbitrary Python in the process by triggering any exception.",
      commonViolations: [
        'app.run(debug=True)',
        'uvicorn.run(app, host="0.0.0.0", debug=True)',
        'app.run(host="0.0.0.0", port=8000, debug=True)',
      ],
      goodExample: 'debug = os.environ.get("DEBUG", "false").lower() == "true"\napp.run(debug=debug)',
      badExample: 'app.run(debug=True)  # ❌ never in production',
    },
    detect({ changedFiles = [], config }: DetectInput): Finding[] {
      const sev = classifySeverity('py_debug_mode', config.severityRules);
      const findings: Finding[] = [];
      const DEBUG_RE = /(?:app\.run|uvicorn\.run|hypercorn\.run)\s*\([^)]*debug\s*=\s*True/;
      for (const { path, content } of changedFiles) {
        if (!isPyFile(path)) continue;
        const line = lineOf(content, DEBUG_RE);
        if (line !== undefined) {
          findings.push({
            severity: sev, category: 'py_debug_mode', file: path, line,
            message: 'debug=True left on — never run with debug mode in production.',
            suggestion: 'Use: debug=os.environ.get("DEBUG", "false").lower() == "true"',
          });
        }
      }
      return findings;
    },
  },

  // ── PY_013: Insecure random for security-sensitive values ─────────────────
  {
    id: 'PY_013',
    category: 'py_insecure_random',
    description: 'random module used for tokens, keys, or passwords — not cryptographically secure.',
    severity: 'HIGH',
    tags: ['security', 'python', 'cryptography'],
    sinceVersion: '1.2.0',
    explain: {
      why: "Python's random module uses a Mersenne Twister PRNG that is not cryptographically secure. Its output is predictable if an attacker observes enough values. Tokens, session IDs, passwords, and OTPs generated with random can be forged.",
      commonViolations: [
        'token = str(random.randint(100000, 999999))',
        'session_id = random.choices(string.ascii_letters, k=32)',
        'reset_key = "".join(random.choice(chars) for _ in range(32))',
      ],
      goodExample: 'import secrets\ntoken = secrets.token_urlsafe(32)',
      badExample: 'token = str(random.randint(100000, 999999))  # ❌ predictable',
    },
    detect({ changedFiles = [], config }: DetectInput): Finding[] {
      const sev = classifySeverity('py_insecure_random', config.severityRules);
      const findings: Finding[] = [];
      const INSEC_RE = /\brandom\s*\.\s*(?:random|randint|randrange|choice|choices|shuffle)\s*\(/;
      const SEC_CONTEXT = /token|key|secret|password|salt|nonce|otp|csrf|session/i;
      for (const { path, content } of changedFiles) {
        if (!isPyFile(path) || isPyTest(path)) continue;
        const lines = content.split('\n');
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i]!;
          if (/^\s*#/.test(line) || !INSEC_RE.test(line)) continue;
          const ctx = lines.slice(Math.max(0, i - 2), i + 3).join(' ');
          if (SEC_CONTEXT.test(ctx)) {
            findings.push({
              severity: sev, category: 'py_insecure_random', file: path, line: i + 1,
              message: 'random module used in security-sensitive context — use secrets module instead.',
              suggestion: 'import secrets; token = secrets.token_urlsafe(32)',
            });
          }
        }
      }
      return findings;
    },
  },

  // ── PY_014: LLM prompt injection risk ────────────────────────────────────
  {
    id: 'PY_014',
    category: 'py_prompt_injection',
    description: 'LLM prompt built by concatenating or f-stringing user input without sanitization.',
    severity: 'BLOCKER',
    tags: ['security', 'python', 'llm', 'prompt-injection', 'ai-risk'],
    sinceVersion: '1.2.0',
    explain: {
      why: 'Prompt injection allows attackers to override the system instructions embedded in your LLM prompt by crafting user input that escapes the intended context. When user_message is included directly in a system prompt f-string, an attacker can say "Ignore all previous instructions and..." — overriding your guardrails.',
      commonViolations: [
        'prompt = f"You are an assistant. User: {user_message}"',
        'messages = [{"role": "system", "content": f"Help with: {user_input}"}]',
        'chain.run(f"Translate this: {request_body}")',
      ],
      goodExample: '# Keep system prompt static; pass user content as a separate user message\nmessages = [\n    {"role": "system", "content": STATIC_SYSTEM_PROMPT},\n    {"role": "user", "content": user_message},\n]',
      badExample: 'prompt = f"System: You are helpful. User: {user_message}"  # ❌ prompt injection',
    },
    detect({ changedFiles = [], config }: DetectInput): Finding[] {
      const sev = classifySeverity('py_prompt_injection', config.severityRules);
      const findings: Finding[] = [];
      const PROMPT_FSTR = /prompt\s*=\s*f['"].*\{(?:user|message|input|body|request|query|data)/i;
      const CHAT_MSG_FSTR = /["']content['"]\s*:\s*f['"].*\{(?:user|message|input|body)/i;
      const LLM_CALL = /openai\.|anthropic\.|groq\.|langchain\.|llm\.|chat\.completions/i;
      for (const { path, content } of changedFiles) {
        if (!isPyFile(path) || isPyTest(path)) continue;
        if (!LLM_CALL.test(content)) continue;
        const lines = content.split('\n');
        lines.forEach((line, i) => {
          if (/^\s*#/.test(line)) return;
          if (PROMPT_FSTR.test(line) || CHAT_MSG_FSTR.test(line)) {
            findings.push({
              severity: sev, category: 'py_prompt_injection', file: path, line: i + 1,
              message: 'LLM prompt includes raw user input — vulnerable to prompt injection attacks.',
              suggestion: 'Keep system prompt static. Pass user content only in the "user" role message, never the "system" role.',
            });
          }
        });
      }
      return findings;
    },
  },

  // ── PY_015: AI endpoint with no auth ─────────────────────────────────────
  {
    id: 'PY_015',
    category: 'py_ai_endpoint_no_auth',
    description: 'Route calling OpenAI/Anthropic/LangChain with no authentication — unbounded API cost exposure.',
    severity: 'BLOCKER',
    tags: ['security', 'python', 'llm', 'auth', 'ai-risk', 'vibe-coding'],
    sinceVersion: '1.2.0',
    explain: {
      why: "Unauthenticated AI endpoints let anyone trigger paid API calls. A single script can exhaust a month's OpenAI budget in minutes. AI assistants build the LLM integration first and defer auth — leaving a period where the endpoint is publicly exploitable.",
      commonViolations: [
        '@app.post("/chat") async def chat(message: str): response = client.chat.completions.create(...)',
        '@router.get("/generate") async def generate(prompt: str): return llm.invoke(prompt)',
      ],
      goodExample: '@router.post("/chat")\nasync def chat(\n    message: str,\n    user: User = Depends(get_current_user)\n):\n    return client.chat.completions.create(...)',
      badExample: '@app.post("/chat")\nasync def chat(message: str):  # ❌ no auth — anyone can call this\n    return client.chat.completions.create(...)',
    },
    detect({ changedFiles = [], config }: DetectInput): Finding[] {
      const sev = classifySeverity('py_ai_endpoint_no_auth', config.severityRules);
      const findings: Finding[] = [];
      const LLM_CALL = /openai\.|anthropic\.|groq\.|langchain\.|llm\.|chat\.completions\.|generate_content/;
      const AUTH_RE = /Depends\s*\(|login_required|require_auth|current_user|get_current_user|authenticate|HTTPBearer|OAuth2|api_key_header/i;
      const ROUTE_RE = /(?:@app|@router|@blueprint)\s*\.\s*(?:get|post|put|patch|delete|route)\s*\(/;
      for (const { path, content } of changedFiles) {
        if (!isPyFile(path) || isPyTest(path)) continue;
        if (!LLM_CALL.test(content)) continue;
        const lines = content.split('\n');
        for (let i = 0; i < lines.length; i++) {
          if (!ROUTE_RE.test(lines[i]!)) continue;
          const window = lines.slice(i, i + 15).join('\n');
          if (LLM_CALL.test(window) && !AUTH_RE.test(window)) {
            findings.push({
              severity: sev, category: 'py_ai_endpoint_no_auth', file: path, line: i + 1,
              message: 'Route calls an LLM API with no authentication — anyone can trigger paid API calls.',
              suggestion: 'Add authentication: async def handler(user: User = Depends(get_current_user))',
            });
          }
        }
      }
      return findings;
    },
  },

  // ── PY_016: Unvalidated LLM response used directly ───────────────────────
  {
    id: 'PY_016',
    category: 'py_llm_response_unvalidated',
    description: 'LLM response content used directly as code, SQL, or HTML without validation.',
    severity: 'HIGH',
    tags: ['security', 'python', 'llm', 'ai-risk'],
    sinceVersion: '1.2.0',
    explain: {
      why: 'LLM outputs are unreliable and can be manipulated via prompt injection. Using LLM-generated content directly in eval(), exec(), or SQL queries creates a secondary injection vector — the AI becomes an attack surface amplifier.',
      commonViolations: [
        'exec(llm.invoke(prompt).content)',
        'cursor.execute(gpt_response.choices[0].message.content)',
        'render_template_string(ai_output)',
      ],
      goodExample: '# Parse structured output; never execute raw LLM text\nimport json\nresult = json.loads(llm_response.content)  # validate schema with Pydantic',
      badExample: 'exec(llm_response.choices[0].message.content)  # ❌ LLM-generated RCE',
    },
    detect({ changedFiles = [], config }: DetectInput): Finding[] {
      const sev = classifySeverity('py_llm_response_unvalidated', config.severityRules);
      const findings: Finding[] = [];
      const LLM_EXTRACT = /\.choices\[0\]\.message\.content|\.content\[0\]\.text|result\.text|response\.text/;
      const DANGER_USE = /\beval\s*\(|exec\s*\(|cursor\.execute\s*\(|render_template_string\s*\(/;
      for (const { path, content } of changedFiles) {
        if (!isPyFile(path) || isPyTest(path)) continue;
        if (!LLM_EXTRACT.test(content) || !DANGER_USE.test(content)) continue;
        const line = lineOf(content, DANGER_USE);
        findings.push({
          severity: sev, category: 'py_llm_response_unvalidated', file: path, line,
          message: 'LLM response used directly in eval/exec/SQL/template — validate and sanitize before use.',
          suggestion: 'Parse LLM output as structured data (JSON schema, Pydantic) before using. Never exec() LLM-generated code.',
        });
      }
      return findings;
    },
  },

  // ── PY_017: Unvalidated redirect ─────────────────────────────────────────
  {
    id: 'PY_017',
    category: 'py_unvalidated_redirect',
    description: 'redirect() called with a URL from request parameters without validation.',
    severity: 'HIGH',
    tags: ['security', 'python', 'redirect', 'flask', 'fastapi'],
    sinceVersion: '1.2.0',
    explain: {
      why: 'Open redirect vulnerabilities allow attackers to craft URLs on your trusted domain (https://yoursite.com/login?next=https://evil.com) that redirect users to phishing pages. Users trust links to your domain and will not notice the redirect.',
      commonViolations: [
        'return redirect(request.args.get("next", "/"))',
        'return RedirectResponse(url=request.query_params.get("redirect"))',
        'return redirect(body.get("return_to"))',
      ],
      goodExample: 'next_url = request.args.get("next", "/")\nif not next_url.startswith("/") or next_url.startswith("//"):\n    next_url = "/"\nreturn redirect(next_url)',
      badExample: 'return redirect(request.args.get("next"))  # ❌ open redirect',
    },
    detect({ changedFiles = [], config }: DetectInput): Finding[] {
      const sev = classifySeverity('py_unvalidated_redirect', config.severityRules);
      const findings: Finding[] = [];
      const REDIRECT_RE = /(?:redirect|RedirectResponse)\s*\(\s*(?:url\s*=\s*)?(?:request\.|url|next|target|dest|location)/;
      const URL_VALIDATE = /is_safe_url|urlparse|allowed_urls|startswith\(['"]http|startswith\(['"]\/'\)/;
      for (const { path, content } of changedFiles) {
        if (!isPyFile(path) || isPyTest(path)) continue;
        if (!REDIRECT_RE.test(content)) continue;
        if (URL_VALIDATE.test(content)) continue;
        const line = lineOf(content, REDIRECT_RE);
        findings.push({
          severity: sev, category: 'py_unvalidated_redirect', file: path, line,
          message: 'Redirect target comes from request without validation — open redirect vulnerability.',
          suggestion: 'Validate redirect targets: only allow relative paths or pre-approved absolute domains.',
        });
      }
      return findings;
    },
  },

  // ── PY_018: No rate limiting on public endpoints ──────────────────────────
  {
    id: 'PY_018',
    category: 'py_no_rate_limit',
    description: 'FastAPI/Flask app has routes but no rate-limiting middleware.',
    severity: 'HIGH',
    tags: ['security', 'python', 'rate-limiting', 'vibe-coding'],
    sinceVersion: '1.2.0',
    explain: {
      why: 'Without rate limiting, any endpoint can be called thousands of times per second by a single attacker — enabling credential stuffing, API scraping, DoS, and exhaustion of paid third-party API quotas. This is consistently missing in AI-generated Python APIs.',
      commonViolations: [
        'app = FastAPI() with @app.post routes and no Limiter',
        'Flask app with no flask_limiter configuration',
        'Multiple @router.post handlers with no slowapi integration',
      ],
      goodExample: 'from slowapi import Limiter\nfrom slowapi.util import get_remote_address\nlimiter = Limiter(key_func=get_remote_address)\napp.state.limiter = limiter\n\n@router.post("/chat")\n@limiter.limit("10/minute")\nasync def chat(...): ...',
      badExample: 'app = FastAPI()\n@app.post("/chat")\nasync def chat(message: str): ...  # ❌ no rate limit',
    },
    detect({ changedFiles = [], config }: DetectInput): Finding[] {
      const sev = classifySeverity('py_no_rate_limit', config.severityRules);
      const findings: Finding[] = [];
      const HAS_APP = /app\s*=\s*(?:FastAPI|Flask|APIRouter)\s*\(/;
      const HAS_ROUTES = /(?:@app|@router)\s*\.\s*(?:post|put|delete|get)\s*\(/;
      const HAS_RATE_LIMIT = /slowapi|flask_limiter|Limiter|RateLimiter|rate_limit|@limiter/i;
      for (const { path, content } of changedFiles) {
        if (!isPyFile(path) || isPyTest(path)) continue;
        if (!HAS_APP.test(content) || !HAS_ROUTES.test(content)) continue;
        if (HAS_RATE_LIMIT.test(content)) continue;
        const line = lineOf(content, HAS_APP);
        findings.push({
          severity: sev, category: 'py_no_rate_limit', file: path, line,
          message: 'FastAPI/Flask app has no rate-limiting middleware — endpoints are open to abuse and DoS.',
          suggestion: 'Add slowapi (FastAPI) or Flask-Limiter: from slowapi import Limiter; limiter = Limiter(key_func=get_remote_address)',
        });
      }
      return findings;
    },
  },

  // ── PY_019: Hardcoded database connection string ──────────────────────────
  {
    id: 'PY_019',
    category: 'py_hardcoded_connection_string',
    description: 'Database connection string with credentials hardcoded in source.',
    severity: 'BLOCKER',
    tags: ['security', 'python', 'secrets', 'database'],
    sinceVersion: '1.2.0',
    explain: {
      why: 'Connection strings with embedded passwords are a common source of credential leaks. They end up in git history, CI logs, Docker image layers, and error messages. AI assistants fill in example credentials that developers leave in production code.',
      commonViolations: [
        'engine = create_engine("postgresql://admin:password@localhost/mydb")',
        'client = MongoClient("mongodb://user:secret@host:27017/db")',
        'redis = Redis.from_url("redis://:password@host:6379/0")',
      ],
      goodExample: 'engine = create_engine(os.environ["DATABASE_URL"])',
      badExample: 'engine = create_engine("postgresql://user:password@host/db")  # ❌ hardcoded credentials',
    },
    detect({ changedFiles = [], config }: DetectInput): Finding[] {
      const sev = classifySeverity('py_hardcoded_connection_string', config.severityRules);
      const findings: Finding[] = [];
      const CONN_RE = /(?:postgresql|mysql|mongodb|redis|sqlite)\+?:\/\/[^{}\s'"]+:[^{}\s'"@]+@/i;
      for (const { path, content } of changedFiles) {
        if (!isPyFile(path)) continue;
        const lines = content.split('\n');
        lines.forEach((line, i) => {
          if (/^\s*#/.test(line)) return;
          if (CONN_RE.test(line) && !/{[^}]+}/.test(line)) {
            findings.push({
              severity: sev, category: 'py_hardcoded_connection_string', file: path, line: i + 1,
              message: 'Database connection string with credentials hardcoded.',
              suggestion: 'Use: os.environ.get("DATABASE_URL") or a secrets manager.',
            });
          }
        });
      }
      return findings;
    },
  },

  // ── PY_020: Bare except clause ────────────────────────────────────────────
  {
    id: 'PY_020',
    category: 'py_bare_except',
    description: 'Bare except: clause catches SystemExit, KeyboardInterrupt, and hides all errors.',
    severity: 'MEDIUM',
    tags: ['quality', 'python', 'error-handling'],
    sinceVersion: '1.2.0',
    explain: {
      why: "A bare except: clause catches BaseException, including SystemExit and KeyboardInterrupt — making your process impossible to stop cleanly. It also hides bugs by silently swallowing unexpected exceptions, causing hard-to-debug silent failures.",
      commonViolations: [
        'try:\n    do_thing()\nexcept:\n    pass',
        'try:\n    result = parse(data)\nexcept:\n    result = None',
      ],
      goodExample: 'try:\n    result = parse(data)\nexcept (ValueError, KeyError) as e:\n    logger.error("parse failed", exc_info=e)\n    result = None',
      badExample: 'try:\n    result = parse(data)\nexcept:  # ❌ catches everything including SystemExit\n    result = None',
    },
    detect({ changedFiles = [], config }: DetectInput): Finding[] {
      const sev = classifySeverity('py_bare_except', config.severityRules);
      const findings: Finding[] = [];
      const BARE_EXCEPT = /^\s*except\s*:/;
      for (const { path, content } of changedFiles) {
        if (!isPyFile(path)) continue;
        const lines = content.split('\n');
        lines.forEach((line, i) => {
          if (BARE_EXCEPT.test(line)) {
            findings.push({
              severity: sev, category: 'py_bare_except', file: path, line: i + 1,
              message: 'Bare except: catches everything including SystemExit and KeyboardInterrupt.',
              suggestion: 'Catch specific exceptions: except (ValueError, KeyError) as e: — or at minimum: except Exception as e:',
            });
          }
        });
      }
      return findings;
    },
  },

  // ── PY_021: Error details returned to client ──────────────────────────────
  {
    id: 'PY_021',
    category: 'py_error_detail_leak',
    description: 'Exception message or traceback returned in API response — information disclosure.',
    severity: 'MEDIUM',
    tags: ['security', 'python', 'error-handling', 'information-disclosure'],
    sinceVersion: '1.2.0',
    explain: {
      why: "Returning exception messages or tracebacks to API callers reveals internal implementation details: file paths, library versions, SQL table names, and error context that attackers use to craft more targeted exploits.",
      commonViolations: [
        'return jsonify({"error": str(e)})',
        'raise HTTPException(detail=traceback.format_exc())',
        'return {"message": exception.args[0]}',
      ],
      goodExample: 'logger.error("database error", exc_info=e)\nraise HTTPException(status_code=500, detail="Internal server error")',
      badExample: 'return jsonify({"error": str(e), "traceback": traceback.format_exc()})  # ❌ leaks internals',
    },
    detect({ changedFiles = [], config }: DetectInput): Finding[] {
      const sev = classifySeverity('py_error_detail_leak', config.severityRules);
      const findings: Finding[] = [];
      const LEAK_RE = /(?:return|jsonify|JSONResponse|raise HTTPException)\s*\([^)]*(?:str\s*\(\s*e\)|traceback\.format_exc\(\)|exception\.args)/;
      for (const { path, content } of changedFiles) {
        if (!isPyFile(path) || isPyTest(path)) continue;
        const lines = content.split('\n');
        lines.forEach((line, i) => {
          if (LEAK_RE.test(line) && !/^\s*#/.test(line)) {
            findings.push({
              severity: sev, category: 'py_error_detail_leak', file: path, line: i + 1,
              message: 'Exception details or traceback returned to API caller — leaks internal implementation.',
              suggestion: 'Log the exception server-side and return a generic error message to clients.',
            });
          }
        });
      }
      return findings;
    },
  },

  // ── PY_022: Missing input validation on POST body ─────────────────────────
  {
    id: 'PY_022',
    category: 'py_missing_input_validation',
    description: 'FastAPI route reads raw request.json() instead of a typed Pydantic model.',
    severity: 'HIGH',
    tags: ['security', 'python', 'validation', 'fastapi', 'vibe-coding'],
    sinceVersion: '1.2.0',
    explain: {
      why: "Reading raw request.json() or request.form[] skips type validation, coercion, and field presence checks. This allows attackers to pass unexpected types (None, objects, very large strings) that cause crashes, type errors, or unexpected behavior in business logic.",
      commonViolations: [
        'data = await request.json(); name = data["name"]',
        'body = request.get_json(); user_id = body["user_id"]',
        'form = request.form["email"]',
      ],
      goodExample: 'class CreateUser(BaseModel):\n    name: str\n    email: EmailStr\n\n@app.post("/users")\nasync def create_user(data: CreateUser): ...',
      badExample: 'data = await request.json()\nname = data["name"]  # ❌ no type or presence validation',
    },
    detect({ changedFiles = [], config }: DetectInput): Finding[] {
      const sev = classifySeverity('py_missing_input_validation', config.severityRules);
      const findings: Finding[] = [];
      const RAW_JSON = /await\s+request\.json\(\)|request\.get_json\(\)|request\.form\[/;
      const HAS_PYDANTIC = /BaseModel|from\s+pydantic/;
      for (const { path, content } of changedFiles) {
        if (!isPyFile(path) || isPyTest(path)) continue;
        if (!RAW_JSON.test(content) || HAS_PYDANTIC.test(content)) continue;
        const line = lineOf(content, RAW_JSON);
        findings.push({
          severity: sev, category: 'py_missing_input_validation', file: path, line,
          message: 'Request body read as raw dict without Pydantic validation — missing type safety and input validation.',
          suggestion: 'Define a Pydantic model and use it as the route parameter type.',
        });
      }
      return findings;
    },
  },

  // ── PY_023: Timing attack in secret comparison ────────────────────────────
  {
    id: 'PY_023',
    category: 'py_timing_attack',
    description: 'Secret or token compared with == operator — vulnerable to timing attacks.',
    severity: 'HIGH',
    tags: ['security', 'python', 'cryptography', 'timing-attack'],
    sinceVersion: '1.2.0',
    explain: {
      why: "Python's == operator short-circuits on the first differing byte. By measuring response time, an attacker can determine matching bytes one at a time, eventually recovering the correct token without brute force. hmac.compare_digest() takes constant time regardless of match position.",
      commonViolations: [
        'if token == stored_token: authenticate()',
        'if api_key == os.environ["API_KEY"]: allow()',
        'if provided_signature == expected_signature: proceed()',
      ],
      goodExample: 'import hmac\nif hmac.compare_digest(provided_token, stored_token):\n    authenticate()',
      badExample: 'if token == stored_token:  # ❌ timing attack\n    authenticate()',
    },
    detect({ changedFiles = [], config }: DetectInput): Finding[] {
      const sev = classifySeverity('py_timing_attack', config.severityRules);
      const findings: Finding[] = [];
      const TIMING_RE = /(?:token|secret|key|password|api_key|signature)\s*==\s*|==\s*(?:token|secret|key|password|api_key|signature)/i;
      const SAFE_COMPARE = /hmac\.compare_digest|secrets\.compare_digest/;
      for (const { path, content } of changedFiles) {
        if (!isPyFile(path) || isPyTest(path)) continue;
        if (!TIMING_RE.test(content) || SAFE_COMPARE.test(content)) continue;
        const line = lineOf(content, TIMING_RE);
        findings.push({
          severity: sev, category: 'py_timing_attack', file: path, line,
          message: 'Secret compared with == operator — use hmac.compare_digest() to prevent timing attacks.',
          suggestion: 'import hmac; hmac.compare_digest(provided_token, stored_token)',
        });
      }
      return findings;
    },
  },

  // ── PY_024: Missing HTTPS enforcement ────────────────────────────────────
  {
    id: 'PY_024',
    category: 'py_no_https_redirect',
    description: 'FastAPI app with no HTTPS redirect or HTTPSRedirectMiddleware.',
    severity: 'MEDIUM',
    tags: ['security', 'python', 'https', 'fastapi'],
    sinceVersion: '1.2.0',
    explain: {
      why: 'Without HTTPS enforcement, tokens and session cookies can be intercepted in plaintext by network attackers (coffee shop Wi-Fi, ISPs). HTTPSRedirectMiddleware ensures HTTP requests are permanently redirected to HTTPS before any sensitive data is transmitted.',
      commonViolations: [
        'app = FastAPI() with no middleware for HTTPS',
        'Missing talisman or flask-talisman in Flask',
      ],
      goodExample: 'from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware\napp.add_middleware(HTTPSRedirectMiddleware)',
      badExample: 'app = FastAPI()  # ❌ no HTTPS redirect in production code',
    },
    detect({ changedFiles = [], config }: DetectInput): Finding[] {
      const sev = classifySeverity('py_no_https_redirect', config.severityRules);
      const findings: Finding[] = [];
      const HAS_APP = /app\s*=\s*FastAPI\s*\(/;
      const HTTPS_REDIRECT = /HTTPSRedirectMiddleware|talisman|force_https|PREFERRED_URL_SCHEME/;
      for (const { path, content } of changedFiles) {
        if (!isPyFile(path) || isPyTest(path)) continue;
        if (!HAS_APP.test(content) || HTTPS_REDIRECT.test(content)) continue;
        if (/127\.0\.0\.1|localhost|0\.0\.0\.0/.test(content)) continue;
        const line = lineOf(content, HAS_APP);
        findings.push({
          severity: sev, category: 'py_no_https_redirect', file: path, line,
          message: 'FastAPI app has no HTTPS redirect middleware — HTTP traffic is unencrypted.',
          suggestion: 'Add: from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware; app.add_middleware(HTTPSRedirectMiddleware)',
        });
      }
      return findings;
    },
  },

  // ── PY_025: Missing auth on LangChain agent endpoint ─────────────────────
  {
    id: 'PY_025',
    category: 'py_langchain_no_auth',
    description: 'LangChain agent or chain invoked in a route with no authentication.',
    severity: 'BLOCKER',
    tags: ['security', 'python', 'langchain', 'llm', 'auth', 'ai-risk'],
    sinceVersion: '1.2.0',
    explain: {
      why: "LangChain agents can browse the web, execute code, query databases, and call external APIs on behalf of whoever invokes them. Without authentication, any anonymous user can trigger your agent — causing unbounded API costs, data exfiltration, and potential tool misuse.",
      commonViolations: [
        '@app.post("/agent") async def run_agent(query: str): return agent.run(query)',
        '@router.get("/chain") async def chain(prompt: str): return chain.invoke(prompt)',
      ],
      goodExample: '@router.post("/agent")\nasync def run_agent(\n    query: str,\n    user: User = Depends(get_current_user)\n):\n    return agent.run(query)',
      badExample: '@app.post("/agent")\nasync def run_agent(query: str):  # ❌ unauthenticated LangChain agent\n    return agent.run(query)',
    },
    detect({ changedFiles = [], config }: DetectInput): Finding[] {
      const sev = classifySeverity('py_langchain_no_auth', config.severityRules);
      const findings: Finding[] = [];
      const LANGCHAIN_RE = /(?:agent\.run|chain\.invoke|chain\.run|agent_executor\.invoke|llm_chain\.predict|ConversationChain|AgentExecutor)/;
      const AUTH_RE = /Depends\s*\(|login_required|require_auth|current_user|get_current_user|Bearer|api_key/i;
      const ROUTE_RE = /(?:@app|@router)\s*\.\s*(?:post|get|put)\s*\(/;
      for (const { path, content } of changedFiles) {
        if (!isPyFile(path) || isPyTest(path)) continue;
        if (!LANGCHAIN_RE.test(content)) continue;
        const lines = content.split('\n');
        for (let i = 0; i < lines.length; i++) {
          if (!ROUTE_RE.test(lines[i]!)) continue;
          const window = lines.slice(i, i + 15).join('\n');
          if (LANGCHAIN_RE.test(window) && !AUTH_RE.test(window)) {
            findings.push({
              severity: sev, category: 'py_langchain_no_auth', file: path, line: i + 1,
              message: 'LangChain agent or chain is called from an unauthenticated route — unlimited free access to your AI agent.',
              suggestion: 'Add authentication: async def handler(user: User = Depends(get_current_user))',
            });
          }
        }
      }
      return findings;
    },
  },

];
