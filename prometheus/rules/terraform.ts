import type { PrometheusRule, Finding, DetectInput } from '../types.js';
import { classifySeverity } from '../severity.js';

const isTerraformFile = (p: string) => /\.tf$/.test(p);
const isTerraformVars = (p: string) => /\.tfvars$/.test(p);
const isTerraformOrVars = (p: string) => /\.tf$|\.tfvars$/.test(p);

export const TERRAFORM_RULES: PrometheusRule[] = [
  // ── TF_001: S3 bucket with public ACL ────────────────────────────────────
  {
    id: 'TF_001',
    category: 'tf_s3_public_acl',
    description: 'S3 bucket resource with a public-read or public-read-write ACL — publicly exposes all bucket objects.',
    severity: 'BLOCKER',
    tags: ['security', 'terraform', 'aws', 's3', 'iac'],
    sinceVersion: '1.6.0',
    explain: {
      why: 'Setting acl = "public-read" or "public-read-write" on an S3 bucket makes every object in the bucket accessible to anyone on the internet. Even if current objects are safe, future uploads inherit the ACL. Use bucket policies for controlled, per-path access instead.',
      commonViolations: [
        'acl = "public-read"',
        'acl = "public-read-write"',
      ],
      goodExample: '# Remove the acl argument and use a bucket policy for controlled access\nresource "aws_s3_bucket_policy" "example" {\n  bucket = aws_s3_bucket.example.id\n  policy = data.aws_iam_policy_document.example.json\n}',
      badExample: 'resource "aws_s3_bucket" "example" {\n  bucket = "my-bucket"\n  acl    = "public-read" # BLOCKER: publicly exposes all objects\n}',
    },
    detect({ changedFiles = [], config }: DetectInput): Finding[] {
      const sev = classifySeverity('tf_s3_public_acl', config.severityRules);
      const findings: Finding[] = [];
      const ACL_RE = /^\s*acl\s*=\s*["']public-read(?:-write)?["']/;
      const S3_RESOURCE_RE = /resource\s+["']aws_s3_bucket["']/;
      for (const { path, content } of changedFiles) {
        if (!isTerraformFile(path)) continue;
        const lines = content.split('\n');
        for (let i = 0; i < lines.length; i++) {
          if (!ACL_RE.test(lines[i]!)) continue;
          // Check within 20 lines before for aws_s3_bucket resource
          const start = Math.max(0, i - 20);
          const window = lines.slice(start, i + 1).join('\n');
          if (S3_RESOURCE_RE.test(window)) {
            findings.push({
              severity: sev, category: 'tf_s3_public_acl', file: path, line: i + 1,
              message: 'S3 bucket has a public ACL — all objects are publicly readable/writable.',
              suggestion: 'Remove the acl argument. Use aws_s3_bucket_policy with an explicit policy for controlled access.',
            });
          }
        }
      }
      return findings;
    },
  },

  // ── TF_002: Security group ingress open to 0.0.0.0/0 on sensitive ports ──
  {
    id: 'TF_002',
    category: 'tf_sg_open_to_world',
    description: 'Security group allows inbound traffic from 0.0.0.0/0 on sensitive ports (SSH, database ports).',
    severity: 'BLOCKER',
    tags: ['security', 'terraform', 'aws', 'networking', 'iac'],
    sinceVersion: '1.6.0',
    explain: {
      why: 'Exposing SSH (22), MySQL (3306), PostgreSQL (5432), Redis (6379), MongoDB (27017), or Oracle (1521) to the entire internet allows brute-force, credential stuffing, and exploit scanning. Databases should never be directly reachable from the internet.',
      commonViolations: [
        'cidr_blocks = ["0.0.0.0/0"] with from_port = 22',
        'cidr_blocks = ["0.0.0.0/0"] with from_port = 3306',
      ],
      goodExample: 'ingress {\n  from_port   = 22\n  to_port     = 22\n  protocol    = "tcp"\n  cidr_blocks = ["10.0.0.0/8"] # restrict to internal network\n}',
      badExample: 'ingress {\n  from_port   = 22\n  to_port     = 22\n  protocol    = "tcp"\n  cidr_blocks = ["0.0.0.0/0"] # BLOCKER: SSH open to the internet\n}',
    },
    detect({ changedFiles = [], config }: DetectInput): Finding[] {
      const sev = classifySeverity('tf_sg_open_to_world', config.severityRules);
      const findings: Finding[] = [];
      const OPEN_CIDR_RE = /cidr_blocks\s*=\s*\[\s*["']0\.0\.0\.0\/0["']/;
      const SENSITIVE_PORT_RE = /(?:from_port|port)\s*=\s*(?:22|3306|5432|6379|27017|1521)\b/;
      const WINDOW = 10;
      for (const { path, content } of changedFiles) {
        if (!isTerraformFile(path)) continue;
        const lines = content.split('\n');
        for (let i = 0; i < lines.length; i++) {
          if (!OPEN_CIDR_RE.test(lines[i]!)) continue;
          const start = Math.max(0, i - WINDOW);
          const end = Math.min(lines.length, i + WINDOW + 1);
          const window = lines.slice(start, end).join('\n');
          if (SENSITIVE_PORT_RE.test(window)) {
            findings.push({
              severity: sev, category: 'tf_sg_open_to_world', file: path, line: i + 1,
              message: 'Security group allows 0.0.0.0/0 access on a sensitive port (SSH/database).',
              suggestion: 'Restrict cidr_blocks to specific trusted IP ranges. Never expose databases to the internet.',
            });
          }
        }
      }
      return findings;
    },
  },

  // ── TF_003: RDS instance with publicly_accessible = true ─────────────────
  {
    id: 'TF_003',
    category: 'tf_rds_publicly_accessible',
    description: 'RDS instance or cluster with publicly_accessible = true — database is internet-reachable.',
    severity: 'HIGH',
    tags: ['security', 'terraform', 'aws', 'rds', 'database', 'iac'],
    sinceVersion: '1.6.0',
    explain: {
      why: 'Setting publicly_accessible = true attaches a public IP to the RDS instance and allows connections from outside the VPC (subject to security groups). Even with a strong password, internet-exposed databases are subject to brute-force and exploit scanning.',
      commonViolations: [
        'publicly_accessible = true',
      ],
      goodExample: 'resource "aws_db_instance" "example" {\n  # ...\n  publicly_accessible = false\n}',
      badExample: 'resource "aws_db_instance" "example" {\n  # ...\n  publicly_accessible = true # HIGH: database reachable from internet\n}',
    },
    detect({ changedFiles = [], config }: DetectInput): Finding[] {
      const sev = classifySeverity('tf_rds_publicly_accessible', config.severityRules);
      const findings: Finding[] = [];
      const PUBLIC_RE = /^\s*publicly_accessible\s*=\s*true\b/;
      for (const { path, content } of changedFiles) {
        if (!isTerraformFile(path)) continue;
        const lines = content.split('\n');
        for (let i = 0; i < lines.length; i++) {
          if (PUBLIC_RE.test(lines[i]!)) {
            findings.push({
              severity: sev, category: 'tf_rds_publicly_accessible', file: path, line: i + 1,
              message: 'RDS instance has publicly_accessible = true — database is internet-reachable.',
              suggestion: 'Set publicly_accessible = false. Access RDS from within the VPC via a bastion host or VPN.',
            });
          }
        }
      }
      return findings;
    },
  },

  // ── TF_004: RDS instance without storage encryption ──────────────────────
  {
    id: 'TF_004',
    category: 'tf_rds_no_encryption',
    description: 'RDS instance or cluster without storage_encrypted = true — data at rest is unencrypted.',
    severity: 'HIGH',
    tags: ['security', 'terraform', 'aws', 'rds', 'encryption', 'iac'],
    sinceVersion: '1.6.0',
    explain: {
      why: 'Without storage encryption, anyone who gains physical or API access to the underlying EBS volume can read database contents. AWS RDS encryption is free and has no performance impact — there is no reason not to enable it.',
      commonViolations: [
        'resource "aws_db_instance" without storage_encrypted = true',
      ],
      goodExample: 'resource "aws_db_instance" "example" {\n  # ...\n  storage_encrypted = true\n}',
      badExample: 'resource "aws_db_instance" "example" {\n  engine         = "mysql"\n  instance_class = "db.t3.micro"\n  # HIGH: missing storage_encrypted = true\n}',
    },
    detect({ changedFiles = [], config }: DetectInput): Finding[] {
      const sev = classifySeverity('tf_rds_no_encryption', config.severityRules);
      const findings: Finding[] = [];
      const RDS_RESOURCE_RE = /^\s*resource\s+["']aws_(?:db_instance|rds_cluster)["']/;
      const ENCRYPTED_RE = /storage_encrypted\s*=\s*true/;
      const SCAN_LINES = 30;
      for (const { path, content } of changedFiles) {
        if (!isTerraformFile(path)) continue;
        const lines = content.split('\n');
        for (let i = 0; i < lines.length; i++) {
          if (!RDS_RESOURCE_RE.test(lines[i]!)) continue;
          const end = Math.min(lines.length, i + SCAN_LINES);
          const block = lines.slice(i, end).join('\n');
          if (!ENCRYPTED_RE.test(block)) {
            findings.push({
              severity: sev, category: 'tf_rds_no_encryption', file: path, line: i + 1,
              message: 'RDS instance/cluster declared without storage_encrypted = true — data at rest is unencrypted.',
              suggestion: 'Add storage_encrypted = true to the aws_db_instance or aws_rds_cluster resource.',
            });
          }
        }
      }
      return findings;
    },
  },

  // ── TF_005: IAM policy with wildcard action ("*") ────────────────────────
  {
    id: 'TF_005',
    category: 'tf_iam_wildcard_action',
    description: 'IAM policy statement grants all actions ("*") — full AWS admin access.',
    severity: 'BLOCKER',
    tags: ['security', 'terraform', 'aws', 'iam', 'iac'],
    sinceVersion: '1.6.0',
    explain: {
      why: 'actions = ["*"] or Action: "*" is equivalent to granting full AWS administrator access. Any entity with this policy can create/delete any resource, exfiltrate data, or escalate privileges to other accounts.',
      commonViolations: [
        'actions = ["*"]',
        '"Action": "*"',
      ],
      goodExample: 'statement {\n  actions   = ["s3:GetObject", "s3:PutObject"]\n  resources = ["arn:aws:s3:::my-bucket/*"]\n}',
      badExample: 'statement {\n  actions   = ["*"] # BLOCKER: full admin access\n  resources = ["*"]\n}',
    },
    detect({ changedFiles = [], config }: DetectInput): Finding[] {
      const sev = classifySeverity('tf_iam_wildcard_action', config.severityRules);
      const findings: Finding[] = [];
      const WILDCARD_ACTION_RE = /actions\s*=\s*\[\s*["']\*["']\s*\]/;
      const JSON_ACTION_RE = /["']Action["']\s*:\s*["']\*["']/;
      for (const { path, content } of changedFiles) {
        if (!isTerraformFile(path)) continue;
        const lines = content.split('\n');
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i]!;
          if (WILDCARD_ACTION_RE.test(line) || JSON_ACTION_RE.test(line)) {
            findings.push({
              severity: sev, category: 'tf_iam_wildcard_action', file: path, line: i + 1,
              message: 'IAM policy grants all actions ("*") — equivalent to full admin access.',
              suggestion: 'Enumerate only the specific actions required. Follow principle of least privilege.',
            });
          }
        }
      }
      return findings;
    },
  },

  // ── TF_006: IAM policy statement with wildcard resource ──────────────────
  {
    id: 'TF_006',
    category: 'tf_iam_wildcard_resource',
    description: 'IAM policy statement uses resources = ["*"] — policy applies to all AWS resources.',
    severity: 'HIGH',
    tags: ['security', 'terraform', 'aws', 'iam', 'iac'],
    sinceVersion: '1.6.0',
    explain: {
      why: 'resources = ["*"] makes the policy apply to every resource in the account. Combined with write or delete actions this allows account-wide destructive operations. Always scope resources to specific ARNs.',
      commonViolations: [
        'resources = ["*"]',
      ],
      goodExample: 'statement {\n  actions   = ["s3:GetObject"]\n  resources = ["arn:aws:s3:::my-bucket/*"]\n}',
      badExample: 'statement {\n  actions   = ["s3:DeleteObject"]\n  resources = ["*"] # HIGH: applies to every S3 bucket\n}',
    },
    detect({ changedFiles = [], config }: DetectInput): Finding[] {
      const sev = classifySeverity('tf_iam_wildcard_resource', config.severityRules);
      const findings: Finding[] = [];
      const WILDCARD_RESOURCE_RE = /resources\s*=\s*\[\s*["']\*["']\s*\]/;
      for (const { path, content } of changedFiles) {
        if (!isTerraformFile(path)) continue;
        const lines = content.split('\n');
        for (let i = 0; i < lines.length; i++) {
          if (WILDCARD_RESOURCE_RE.test(lines[i]!)) {
            findings.push({
              severity: sev, category: 'tf_iam_wildcard_resource', file: path, line: i + 1,
              message: 'IAM policy statement targets all resources ("*") — policy has account-wide blast radius.',
              suggestion: 'Scope resources to specific ARNs: resources = ["arn:aws:s3:::my-bucket/*"].',
            });
          }
        }
      }
      return findings;
    },
  },

  // ── TF_007: S3 bucket without versioning enabled ─────────────────────────
  {
    id: 'TF_007',
    category: 'tf_s3_no_versioning',
    description: 'S3 bucket resource without versioning enabled — objects cannot be recovered after deletion or overwrite.',
    severity: 'MEDIUM',
    tags: ['security', 'terraform', 'aws', 's3', 'data-protection', 'iac'],
    sinceVersion: '1.6.0',
    explain: {
      why: 'Without versioning, deleting or overwriting an S3 object is permanent. Versioning protects against accidental deletion, ransomware attacks, and application bugs that corrupt data.',
      commonViolations: [
        'resource "aws_s3_bucket" without a versioning { enabled = true } block',
      ],
      goodExample: 'resource "aws_s3_bucket" "example" {\n  bucket = "my-bucket"\n  versioning {\n    enabled = true\n  }\n}',
      badExample: 'resource "aws_s3_bucket" "example" {\n  bucket = "my-bucket"\n  # MEDIUM: no versioning block\n}',
    },
    detect({ changedFiles = [], config }: DetectInput): Finding[] {
      const sev = classifySeverity('tf_s3_no_versioning', config.severityRules);
      const findings: Finding[] = [];
      const S3_RESOURCE_RE = /^\s*resource\s+["']aws_s3_bucket["']/;
      const VERSIONING_RE = /versioning\s*\{/;
      const SCAN_LINES = 30;
      for (const { path, content } of changedFiles) {
        if (!isTerraformFile(path)) continue;
        const lines = content.split('\n');
        for (let i = 0; i < lines.length; i++) {
          if (!S3_RESOURCE_RE.test(lines[i]!)) continue;
          const end = Math.min(lines.length, i + SCAN_LINES);
          const block = lines.slice(i, end).join('\n');
          if (!VERSIONING_RE.test(block)) {
            findings.push({
              severity: sev, category: 'tf_s3_no_versioning', file: path, line: i + 1,
              message: 'S3 bucket declared without a versioning block — objects cannot be recovered after deletion.',
              suggestion: 'Add a versioning block with enabled = true inside the aws_s3_bucket resource.',
            });
          }
        }
      }
      return findings;
    },
  },

  // ── TF_008: Hardcoded credentials in Terraform files ─────────────────────
  {
    id: 'TF_008',
    category: 'tf_hardcoded_credentials',
    description: 'Hardcoded password, secret, or API key found in Terraform configuration.',
    severity: 'BLOCKER',
    tags: ['security', 'terraform', 'secrets', 'credentials', 'iac'],
    sinceVersion: '1.6.0',
    explain: {
      why: 'Hardcoded credentials end up in version control, Terraform state files, and CI logs. Anyone with access to these artifacts can extract the credentials. Use variables, SSM Parameter Store, or Secrets Manager references instead.',
      commonViolations: [
        'password = "mysupersecret123"',
        'api_key  = "sk-abc123xyz"',
      ],
      goodExample: 'resource "aws_db_instance" "example" {\n  password = var.db_password\n}',
      badExample: 'resource "aws_db_instance" "example" {\n  password = "mysupersecret123" # BLOCKER: hardcoded credential\n}',
    },
    detect({ changedFiles = [], config }: DetectInput): Finding[] {
      const sev = classifySeverity('tf_hardcoded_credentials', config.severityRules);
      const findings: Finding[] = [];
      const CRED_RE = /(?:password|secret|api_key|access_key|private_key|auth_token)\s*=\s*["'][^"'$]{8,}["']/i;
      for (const { path, content } of changedFiles) {
        if (!isTerraformOrVars(path)) continue;
        const lines = content.split('\n');
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i]!;
          if (/^\s*#/.test(line)) continue; // skip comment lines
          if (CRED_RE.test(line)) {
            // Skip placeholder-only values (all asterisks)
            const match = line.match(/["']([^"'$]+)["']\s*$/);
            if (match && /^\*+$/.test(match[1]!)) continue;
            findings.push({
              severity: sev, category: 'tf_hardcoded_credentials', file: path, line: i + 1,
              message: 'Hardcoded credential or secret found in Terraform config.',
              suggestion: 'Use var.* references, data.aws_ssm_parameter, or data.aws_secretsmanager_secret_version.',
            });
          }
        }
      }
      return findings;
    },
  },

  // ── TF_009: EC2 instance without IMDSv2 enforcement ──────────────────────
  {
    id: 'TF_009',
    category: 'tf_ec2_imds_v1',
    description: 'EC2 instance without IMDSv2 enforcement — vulnerable to SSRF-to-metadata attacks.',
    severity: 'MEDIUM',
    tags: ['security', 'terraform', 'aws', 'ec2', 'ssrf', 'iac'],
    sinceVersion: '1.6.0',
    explain: {
      why: 'IMDSv1 allows any code running on the instance (including SSRF exploits) to fetch IAM credentials from 169.254.169.254 with a simple HTTP GET. IMDSv2 requires a PUT request with a session token, blocking SSRF-based metadata theft.',
      commonViolations: [
        'resource "aws_instance" without metadata_options { http_tokens = "required" }',
      ],
      goodExample: 'resource "aws_instance" "example" {\n  ami           = "ami-12345"\n  instance_type = "t3.micro"\n  metadata_options {\n    http_tokens = "required"\n  }\n}',
      badExample: 'resource "aws_instance" "example" {\n  ami           = "ami-12345"\n  instance_type = "t3.micro"\n  # MEDIUM: no metadata_options block — IMDSv1 enabled\n}',
    },
    detect({ changedFiles = [], config }: DetectInput): Finding[] {
      const sev = classifySeverity('tf_ec2_imds_v1', config.severityRules);
      const findings: Finding[] = [];
      const INSTANCE_RE = /^\s*resource\s+["']aws_instance["']/;
      const HTTP_TOKENS_RE = /http_tokens\s*=\s*["']required["']/;
      const SCAN_LINES = 20;
      for (const { path, content } of changedFiles) {
        if (!isTerraformFile(path)) continue;
        const lines = content.split('\n');
        for (let i = 0; i < lines.length; i++) {
          if (!INSTANCE_RE.test(lines[i]!)) continue;
          const end = Math.min(lines.length, i + SCAN_LINES);
          const block = lines.slice(i, end).join('\n');
          if (!HTTP_TOKENS_RE.test(block)) {
            findings.push({
              severity: sev, category: 'tf_ec2_imds_v1', file: path, line: i + 1,
              message: 'EC2 instance declared without IMDSv2 enforcement — SSRF can steal IAM credentials.',
              suggestion: 'Add metadata_options { http_tokens = "required" } to enforce IMDSv2.',
            });
          }
        }
      }
      return findings;
    },
  },

  // ── TF_010: CloudWatch log group without retention policy ─────────────────
  {
    id: 'TF_010',
    category: 'tf_log_group_no_retention',
    description: 'CloudWatch log group without retention_in_days — logs are retained indefinitely, increasing cost and compliance risk.',
    severity: 'MEDIUM',
    tags: ['security', 'terraform', 'aws', 'cloudwatch', 'logging', 'iac'],
    sinceVersion: '1.6.0',
    explain: {
      why: 'Without a retention policy, CloudWatch log groups keep logs forever at increasing cost. Many compliance frameworks (HIPAA, PCI-DSS) require log data to be purged after a defined retention period. Setting a reasonable retention period also limits exposure of sensitive data in logs.',
      commonViolations: [
        'resource "aws_cloudwatch_log_group" without retention_in_days',
      ],
      goodExample: 'resource "aws_cloudwatch_log_group" "example" {\n  name              = "/aws/lambda/my-function"\n  retention_in_days = 90\n}',
      badExample: 'resource "aws_cloudwatch_log_group" "example" {\n  name = "/aws/lambda/my-function"\n  # MEDIUM: no retention_in_days — logs kept forever\n}',
    },
    detect({ changedFiles = [], config }: DetectInput): Finding[] {
      const sev = classifySeverity('tf_log_group_no_retention', config.severityRules);
      const findings: Finding[] = [];
      const LOG_GROUP_RE = /^\s*resource\s+["']aws_cloudwatch_log_group["']/;
      const RETENTION_RE = /retention_in_days/;
      const SCAN_LINES = 10;
      for (const { path, content } of changedFiles) {
        if (!isTerraformFile(path)) continue;
        const lines = content.split('\n');
        for (let i = 0; i < lines.length; i++) {
          if (!LOG_GROUP_RE.test(lines[i]!)) continue;
          const end = Math.min(lines.length, i + SCAN_LINES);
          const block = lines.slice(i, end).join('\n');
          if (!RETENTION_RE.test(block)) {
            findings.push({
              severity: sev, category: 'tf_log_group_no_retention', file: path, line: i + 1,
              message: 'CloudWatch log group without retention_in_days — logs kept indefinitely.',
              suggestion: 'Add retention_in_days = 90 (or your compliance requirement) to the aws_cloudwatch_log_group resource.',
            });
          }
        }
      }
      return findings;
    },
  },

  // ── TF_011: Security group with all ports open (0-65535) ──────────────────
  {
    id: 'TF_011',
    category: 'tf_security_group_all_ports',
    description: 'Security group ingress/egress with from_port = 0 and to_port = 65535 — all TCP/UDP ports open.',
    severity: 'BLOCKER',
    tags: ['security', 'terraform', 'aws', 'networking', 'iac'],
    sinceVersion: '1.6.0',
    explain: {
      why: 'Allowing traffic on all 65535 ports defeats the purpose of a security group. Every service running on the instance is exposed — including administration ports, debug endpoints, and internal APIs not intended for external access.',
      commonViolations: [
        'from_port = 0 and to_port = 65535',
      ],
      goodExample: 'ingress {\n  from_port   = 443\n  to_port     = 443\n  protocol    = "tcp"\n  cidr_blocks = ["0.0.0.0/0"]\n}',
      badExample: 'ingress {\n  from_port   = 0\n  to_port     = 65535 # BLOCKER: all ports open\n  protocol    = "tcp"\n  cidr_blocks = ["0.0.0.0/0"]\n}',
    },
    detect({ changedFiles = [], config }: DetectInput): Finding[] {
      const sev = classifySeverity('tf_security_group_all_ports', config.severityRules);
      const findings: Finding[] = [];
      const FROM_PORT_ZERO_RE = /from_port\s*=\s*0\b/;
      const TO_PORT_ALL_RE = /to_port\s*=\s*(?:65535|0)\b/;
      const WINDOW = 10;
      for (const { path, content } of changedFiles) {
        if (!isTerraformFile(path)) continue;
        const lines = content.split('\n');
        for (let i = 0; i < lines.length; i++) {
          if (!FROM_PORT_ZERO_RE.test(lines[i]!)) continue;
          const start = Math.max(0, i - WINDOW);
          const end = Math.min(lines.length, i + WINDOW + 1);
          const window = lines.slice(start, end).join('\n');
          if (TO_PORT_ALL_RE.test(window)) {
            findings.push({
              severity: sev, category: 'tf_security_group_all_ports', file: path, line: i + 1,
              message: 'Security group rule opens all ports (from_port = 0, to_port = 65535) — entire port range exposed.',
              suggestion: 'Restrict to the specific ports your service requires (e.g. 443 for HTTPS only).',
            });
          }
        }
      }
      return findings;
    },
  },

  // ── TF_012: EBS volume without encryption ────────────────────────────────
  {
    id: 'TF_012',
    category: 'tf_unencrypted_ebs',
    description: 'EBS volume declared without encrypted = true — data at rest is unencrypted.',
    severity: 'HIGH',
    tags: ['security', 'terraform', 'aws', 'ebs', 'encryption', 'iac'],
    sinceVersion: '1.6.0',
    explain: {
      why: 'Unencrypted EBS volumes can be detached and mounted to another instance or accessed via snapshot sharing, exposing all stored data. EBS encryption has no performance penalty and is free — enable it by default.',
      commonViolations: [
        'resource "aws_ebs_volume" without encrypted = true',
      ],
      goodExample: 'resource "aws_ebs_volume" "example" {\n  availability_zone = "us-east-1a"\n  size              = 40\n  encrypted         = true\n}',
      badExample: 'resource "aws_ebs_volume" "example" {\n  availability_zone = "us-east-1a"\n  size              = 40\n  # HIGH: no encrypted = true\n}',
    },
    detect({ changedFiles = [], config }: DetectInput): Finding[] {
      const sev = classifySeverity('tf_unencrypted_ebs', config.severityRules);
      const findings: Finding[] = [];
      const EBS_RESOURCE_RE = /^\s*resource\s+["']aws_ebs_volume["']/;
      const ENCRYPTED_RE = /encrypted\s*=\s*true/;
      const SCAN_LINES = 15;
      for (const { path, content } of changedFiles) {
        if (!isTerraformFile(path)) continue;
        const lines = content.split('\n');
        for (let i = 0; i < lines.length; i++) {
          if (!EBS_RESOURCE_RE.test(lines[i]!)) continue;
          const end = Math.min(lines.length, i + SCAN_LINES);
          const block = lines.slice(i, end).join('\n');
          if (!ENCRYPTED_RE.test(block)) {
            findings.push({
              severity: sev, category: 'tf_unencrypted_ebs', file: path, line: i + 1,
              message: 'EBS volume declared without encrypted = true — data at rest is unencrypted.',
              suggestion: 'Add encrypted = true to the aws_ebs_volume resource.',
            });
          }
        }
      }
      return findings;
    },
  },
];
