import json
import re
import importlib.util
import shutil
import subprocess
import sys
import urllib.parse
import urllib.request
from datetime import datetime
from pathlib import Path, PurePosixPath
from uuid import uuid4
# ---------------- CONFIGURATION ----------------
BASE_DIR = Path(__file__).resolve().parent
BASE_WORKSPACE = BASE_DIR / "scan_runs"
HISTORY_DIR = BASE_DIR / "scan_history"
LATEST_REPORT = BASE_DIR / "security_report.md"
CUSTOM_RULES_FILE = BASE_DIR / "scanner_custom_rules.yml"
# AI/Ollama configuration is intentionally unchanged.
OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "llama3.2:latest"
MAX_FILES = 500
MAX_FILE_SIZE = 1_000_000  # 1 MB per file
REQUEST_TIMEOUT = 30
OLLAMA_TIMEOUT = 180
SEMGREP_TIMEOUT = 600
OTHER_TOOL_TIMEOUT = 300
# Use explicit general security/secrets rules, then add the framework pack
# that matches the repository. This avoids relying only on automatic pack
# selection. The scanner still records rule/parser errors in the report.
SEMGREP_BASE_CONFIGS = ["p/security-audit", "p/secrets"]
SEMGREP_LANGUAGE_CONFIGS = {
    ".py": "p/python", ".pyi": "p/python", ".ipynb": "p/python",
    ".js": "p/javascript", ".jsx": "p/javascript", ".mjs": "p/javascript", ".cjs": "p/javascript",
    ".ts": "p/typescript", ".tsx": "p/typescript",
    ".java": "p/java", ".cs": "p/csharp",
    ".go": "p/golang", ".rb": "p/ruby", ".php": "p/php",
    ".kt": "p/kotlin", ".kts": "p/kotlin", ".rs": "p/rust",
    ".swift": "p/swift", ".c": "p/c", ".h": "p/c", ".cpp": "p/c", ".hpp": "p/c",
    ".scala": "p/scala", ".ex": "p/elixir", ".exs": "p/elixir",
}
SEMGREP_FRAMEWORK_CONFIGS = {
    "flask": "p/flask",
    "django": "p/django",
}
# Local rules supplement Semgrep's maintained rulesets for patterns that are
# easy to miss in small applications. Findings are deliberately phrased as
# review prompts where static analysis cannot prove exploitability.
CUSTOM_SEMGREP_RULES = r'''rules:
  - id: local.python.hardcoded-flask-secret-key
    languages: [python]
    severity: ERROR
    message: >-
      A literal value is assigned to a Flask SECRET_KEY/secret_key setting.
      Load a strong, unique secret from a protected environment/configuration
      source and rotate the exposed value. This rule detects literals, not
      whether a runtime-provided value is strong.
    patterns:
      - pattern-either:
          - pattern: $APP.secret_key = $VALUE
          - pattern: $APP.config["SECRET_KEY"] = $VALUE
          - pattern: $APP.config['SECRET_KEY'] = $VALUE
          - pattern: $APP.config.update(SECRET_KEY=$VALUE, ...)
      - metavariable-regex:
          metavariable: $VALUE
          regex: ^["'][^"']{4,}["']$
  - id: local.python.hardcoded-database-password
    languages: [python]
    severity: ERROR
    message: >-
      A database connection appears to use a literal password argument.
      Load credentials from a secret manager or protected environment
      variables, and rotate any credential committed to source control.
    patterns:
      - pattern-either:
          - pattern: mysql.connector.connect(..., password=$VALUE, ...)
          - pattern: pymysql.connect(..., password=$VALUE, ...)
          - pattern: psycopg2.connect(..., password=$VALUE, ...)
          - pattern: psycopg.connect(..., password=$VALUE, ...)
          - pattern: sqlite3.connect(..., password=$VALUE, ...)
      - metavariable-regex:
          metavariable: $VALUE
          regex: ^["'][^"']+["']$
  - id: local.python.password-column-written-to-database
    languages: [python]
    severity: WARNING
    message: >-
      A SQL INSERT/UPDATE appears to write to a password-like database column.
      Verify the value is a modern password hash (for example Argon2id, scrypt,
      or bcrypt), not the original password. This is a review finding and does
      not by itself prove plaintext storage.
    patterns:
      - pattern: $CURSOR.execute($QUERY, $PARAMS)
      - metavariable-regex:
          metavariable: $QUERY
          regex: (?is).*\b(insert\s+into|update)\b.*\b(userpassword|password|passwd|pwd)\b.*
'''
SUPPORTED_EXTENSIONS = {
    ".py", ".pyi", ".ipynb", ".java", ".js", ".jsx", ".mjs", ".cjs",
    ".ts", ".tsx", ".html", ".htm", ".xhtml", ".css", ".scss",
    ".sass", ".less", ".php", ".rb", ".go", ".c", ".h", ".cpp",
    ".hpp", ".cc", ".hh", ".cs", ".sql", ".json", ".jsonc",
    ".xml", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf",
    ".properties", ".sh", ".bash", ".ps1", ".tf", ".hcl",
    ".dockerfile", ".vue", ".svelte", ".kt"}
SUPPORTED_FILENAMES = {
    "dockerfile", "makefile", ".gitignore", ".dockerignore",
    ".env", ".env.example", ".env.local", ".env.development",
    ".env.production", ".env.test", "requirements.txt", "package.json",
    "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
    "pom.xml", "build.gradle", "build.gradle.kts", "gradle.properties",
    "pipfile", "pipfile.lock", "pyproject.toml", "poetry.lock", "uv.lock",
    "go.mod", "go.sum", "cargo.toml", "cargo.lock", "composer.json",
    "composer.lock", "gemfile", "gemfile.lock", "mix.exs", "mix.lock",
    "requirements-dev.txt", "requirements-prod.txt", "webpack.config.js",
    "vite.config.js", "vite.config.ts", "next.config.js", "next.config.ts",
    "tsconfig.json", "eslint.config.js", ".eslintrc", ".eslintrc.json",
    "terraform.tfvars.example",
}
EXCLUDED_PARTS = {
    ".git", "node_modules", "venv", ".venv", "__pycache__",
    "dist", "build", "coverage", ".next", ".nuxt", "vendor",
    "target", "out", ".idea", ".vscode",
}
# ---------------- HTTP HELPERS ----------------
def http_get_json(url):
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "GitHub-Security-Scanner",
        },
    )
    with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT) as response:
        return json.loads(response.read().decode("utf-8"))
def http_get_bytes(url):
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "GitHub-Security-Scanner"},
    )
    with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT) as response:
        return response.read(MAX_FILE_SIZE + 1)
# ---------------- GITHUB REPOSITORY ----------------
def parse_github_url(url):
    parsed = urllib.parse.urlparse(url.strip())
    if parsed.scheme != "https" or parsed.netloc.lower() not in {
        "github.com", "www.github.com"
    }:
        raise ValueError(
            "Enter a public GitHub URL beginning with "
            "https://github.com/owner/repository"
        )
    parts = [
        urllib.parse.unquote(part)
        for part in parsed.path.strip("/").split("/")
        if part
    ]
    if len(parts) != 2:
        raise ValueError(
            "Enter the repository's main URL, not a file, pull request, "
            "or subdirectory URL."
        )
    owner, repo = parts
    repo = repo.removesuffix(".git")
    if not owner or not repo:
        raise ValueError("The GitHub owner or repository name is missing.")
    return owner, repo
def get_repository_files(owner, repo):
    """Return the default branch, immutable commit SHA, and full tree."""
    base_url = (
        "https://api.github.com/repos/"
        f"{urllib.parse.quote(owner, safe='')}/"
        f"{urllib.parse.quote(repo, safe='')}"
    )
    metadata = http_get_json(base_url)
    branch = metadata.get("default_branch")
    if not branch:
        raise RuntimeError("Could not determine the repository's default branch.")
    print(f"\nRepository: {owner}/{repo}")
    print(f"Branch: {branch}")
    encoded_branch = urllib.parse.quote(branch, safe="")
    branch_info = http_get_json(f"{base_url}/branches/{encoded_branch}")
    commit_sha = branch_info.get("commit", {}).get("sha")
    if not commit_sha:
        raise RuntimeError("Could not determine the repository commit SHA.")
    tree_url = (
        f"{base_url}/git/trees/"
        f"{urllib.parse.quote(commit_sha, safe='')}?recursive=1"
    )
    tree_data = http_get_json(tree_url)
    if tree_data.get("truncated"):
        raise RuntimeError(
            "GitHub returned a truncated repository tree. The scan was stopped "
            "to avoid silently missing repository files."
        )
    return branch, commit_sha, tree_data.get("tree", [])
def is_supported_file(path):
    name = path.name.lower()
    if name in SUPPORTED_FILENAMES:
        return True
    if path.suffix.lower() in SUPPORTED_EXTENSIONS:
        return True
    if name.startswith("dockerfile.") or name.startswith(".env."):
        return True
    return False
def download_source_files(owner, repo, commit_sha, tree, workspace):
    """Download supported files from one immutable commit into a fresh workspace."""
    workspace.mkdir(parents=True, exist_ok=False)
    candidates = []
    skipped_files = []
    for item in tree:
        if item.get("type") != "blob":
            continue
        relative_path = item.get("path", "")
        if not relative_path:
            continue
        # GitHub paths always use POSIX separators. Validate before mapping to disk.
        posix_path = PurePosixPath(relative_path)
        if posix_path.is_absolute() or ".." in posix_path.parts:
            skipped_files.append(f"{relative_path}: unsafe repository path")
            continue
        if any(part.lower() in EXCLUDED_PARTS for part in posix_path.parts):
            continue
        file_path = Path(*posix_path.parts)
        if not is_supported_file(file_path):
            continue
        size = item.get("size", 0)
        if size > MAX_FILE_SIZE:
            skipped_files.append(
                f"{relative_path}: file is larger than {MAX_FILE_SIZE} bytes"
            )
            print(f"Skipping oversized file: {relative_path}")
            continue
        candidates.append((relative_path, file_path))
    if len(candidates) > MAX_FILES:
        raise RuntimeError(
            f"Repository contains {len(candidates)} supported files, exceeding "
            f"the configured limit of {MAX_FILES}. The scan was stopped instead "
            "of silently scanning only part of the repository."
        )
    downloaded = []
    failed_downloads = []
    print("\nDownloading supported source/configuration files...")
    # Use commit SHA, not branch name, so tree and file contents are consistent.
    encoded_commit = urllib.parse.quote(commit_sha, safe="")
    for relative_path, file_path in candidates:
        encoded_path = urllib.parse.quote(relative_path, safe="/")
        raw_url = (
            "https://raw.githubusercontent.com/"
            f"{urllib.parse.quote(owner, safe='')}/"
            f"{urllib.parse.quote(repo, safe='')}/"
            f"{encoded_commit}/{encoded_path}"
        )
        try:
            content = http_get_bytes(raw_url)
            if len(content) > MAX_FILE_SIZE:
                skipped_files.append(
                    f"{relative_path}: downloaded content exceeded {MAX_FILE_SIZE} bytes"
                )
                print(f"Skipping oversized file: {relative_path}")
                continue
            destination = workspace.joinpath(*PurePosixPath(relative_path).parts)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(content)
            downloaded.append(relative_path)
        except Exception as error:
            failed_downloads.append(
                f"{relative_path}: {type(error).__name__}: {error}"
            )
            print(f"Download failed: {relative_path}")
    print(f"\nFiles downloaded: {len(downloaded)}")
    print(f"Files skipped (size/path restrictions): {len(skipped_files)}")
    print(f"Files that failed to download: {len(failed_downloads)}")
    for name in downloaded:
        print(name)
    return downloaded, failed_downloads, skipped_files
# ---------------- FRAMEWORK DETECTION ----------------
def detect_frameworks(workspace, downloaded):
    """Detect Flask/Django from source and dependency files to choose rule packs."""
    flask_detected = False
    django_detected = False
    indicators = (
        "from flask import", "import flask", "flask(", "flask==", "flask>=",
        "flask~=", "flask>", "flask<",
    )
    django_indicators = (
        "from django", "import django", "django==", "django>=", "django~=",
        "django>", "django<", "django.setup(",
    )
    for relative_path in downloaded:
        path = workspace.joinpath(*PurePosixPath(relative_path).parts)
        try:
            content = path.read_text(encoding="utf-8", errors="replace")[:500_000].lower()
        except OSError:
            continue
        if any(token in content for token in indicators):
            flask_detected = True
        if any(token in content for token in django_indicators):
            django_detected = True
    frameworks = []
    if flask_detected:
        frameworks.append("flask")
    if django_detected:
        frameworks.append("django")
    return frameworks
def ensure_custom_semgrep_rules():
    """Create default custom rules only when the file does not already exist."""
    if not CUSTOM_RULES_FILE.exists():
        CUSTOM_RULES_FILE.write_text(CUSTOM_SEMGREP_RULES, encoding="utf-8")
    return CUSTOM_RULES_FILE
# ---------------- SEMGREP SCANNING ----------------
def _normalise_semgrep_error(error_item):
    if isinstance(error_item, dict):
        message = error_item.get("message") or error_item.get("type") or str(error_item)
        path = error_item.get("path")
        if path:
            return f"{path}: {message}"
        return str(message)
    return str(error_item)
def run_semgrep(workspace, downloaded, frameworks):
    """Run Semgrep and return findings plus detailed coverage diagnostics."""
    print("\nRunning Semgrep...")
    configs = list(SEMGREP_BASE_CONFIGS)
    detected_extensions = {Path(name).suffix.lower() for name in downloaded}
    for extension in sorted(detected_extensions):
        config = SEMGREP_LANGUAGE_CONFIGS.get(extension)
        if config and config not in configs:
            configs.append(config)
    for framework in frameworks:
        config = SEMGREP_FRAMEWORK_CONFIGS.get(framework)
        if config and config not in configs:
            configs.append(config)
    custom_rules_path = ensure_custom_semgrep_rules()
    semgrep_executable = shutil.which("semgrep")
    if semgrep_executable:
        command = [semgrep_executable, "scan", "--json", "--no-git-ignore", "--metrics=off"]
    elif importlib.util.find_spec("semgrep") is not None:
        command = [sys.executable, "-m", "semgrep", "scan", "--json", "--no-git-ignore", "--metrics=off"]
    else:
        raise RuntimeError("Semgrep is not installed in PATH or the active Python environment. Install it with: python -m pip install semgrep")
    for config in configs:
        command.extend(["--config", config])
    command.extend(["--config", str(custom_rules_path), "."])
    report_configs = configs + ["local:scanner_custom_rules.yml"]
    print("Semgrep configurations:", ", ".join(report_configs))
    try:
        result = subprocess.run(
            command, cwd=str(workspace), capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=SEMGREP_TIMEOUT,
            check=False,
        )
    except FileNotFoundError:
        raise RuntimeError(
            "Semgrep was not found. Install it with: python -m pip install semgrep"
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("Semgrep exceeded the 10-minute scan timeout.")
    if not result.stdout.strip():
        detail = (result.stderr or "No stdout/stderr returned.")[-3000:]
        raise RuntimeError(
            f"Semgrep returned no JSON report (exit {result.returncode}): {detail}"
        )
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError(
            f"Could not parse Semgrep JSON: {error}; output: {result.stdout[-1000:]}"
        )
    findings = data.get("results", []) or []
    for finding in findings:
        finding["tool"] = "Semgrep"
        finding["detected_by"] = ["Semgrep"]
    warnings, parser_errors, skipped_paths = [], [], []
    for error_item in data.get("errors", []) or []:
        message = _normalise_semgrep_error(error_item)
        warnings.append(f"Semgrep: {message}")
        raw_text = " ".join(str(error_item.get(key, "")) for key in ("message", "type", "path")) if isinstance(error_item, dict) else str(error_item)
        if re.search(r"parse|syntax|parser|invalid syntax|unexpected token", raw_text, re.I):
            parser_errors.append(message)
    paths_data = data.get("paths", {}) or {}
    raw_skipped = paths_data.get("skipped", []) or []
    for skipped in raw_skipped:
        if isinstance(skipped, dict):
            path_value = skipped.get("path", "unknown path")
            reason = skipped.get("reason") or skipped.get("details") or "Semgrep skipped this path"
            skipped_paths.append(f"{path_value}: {reason}")
        else:
            skipped_paths.append(str(skipped))
    if skipped_paths:
        warnings.append(f"Semgrep skipped {len(skipped_paths)} path(s)/target(s).")
    if result.returncode not in (0, 1):
        warnings.append(f"Semgrep exited with code {result.returncode}.")
    for line in (result.stderr or "").splitlines():
        if re.search(r"\b(warning|error|failed|parse error|syntax error)\b", line, re.I):
            clean = line.strip()
            if clean and not any(clean in warning for warning in warnings):
                warnings.append(f"Semgrep diagnostic: {clean}")
            if re.search(r"parse error|syntax error|could not parse|parsing failed", clean, re.I) and clean not in parser_errors:
                parser_errors.append(clean)
    print(f"Semgrep findings: {len(findings)}")
    print(f"Semgrep execution warnings/errors: {len(warnings)}")
    return findings, warnings, result.returncode, parser_errors, report_configs, skipped_paths
def _relative_tool_path(raw_path, workspace):
    """Convert a tool path to a safe repository-relative path where possible."""
    if not raw_path:
        return "Unknown file"
    try:
        candidate = Path(str(raw_path))
        if not candidate.is_absolute():
            candidate = workspace / candidate
        resolved = candidate.resolve()
        resolved.relative_to(workspace.resolve())
        return resolved.relative_to(workspace.resolve()).as_posix()
    except (OSError, ValueError, RuntimeError):
        return Path(str(raw_path).replace("\\\\", "/")).name or "Unknown file"
def _severity_rank(value):
    text = str(value or "UNKNOWN").upper()
    if text in {"CRITICAL", "ERROR"}:
        return "CRITICAL" if text == "CRITICAL" else "HIGH"
    if text in {"HIGH", "MEDIUM", "LOW", "INFO"}:
        return text
    if text in {"WARNING", "MODERATE"}:
        return "MEDIUM"
    return "UNKNOWN"
def run_bandit(workspace, downloaded):
    """Run Bandit when Python files exist. Missing tool is reported as a coverage gap."""
    if not any(Path(name).suffix.lower() in {".py", ".pyi"} for name in downloaded):
        return [], [], {"status": "NOT_APPLICABLE", "reason": "No Python files found."}
    if importlib.util.find_spec("bandit") is not None:
        command = [sys.executable, "-m", "bandit"]
    else:
        executable = shutil.which("bandit")
        if not executable:
            return [], ["Bandit is not installed in the active Python environment or PATH; Python-specific secondary analysis was not run."], {"status": "NOT_INSTALLED", "reason": "Install with python -m pip install bandit."}
        command = [executable]
    command.extend(["-r", ".", "-f", "json", "-q", "-x", ".git,venv,.venv,node_modules,scan_runs"])
    try:
        result = subprocess.run(command, cwd=str(workspace), capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=OTHER_TOOL_TIMEOUT, check=False)
    except subprocess.TimeoutExpired:
        return [], ["Bandit timed out after 5 minutes."], {"status": "FAILED", "reason": "Timeout"}
    if not result.stdout.strip():
        return [], [f"Bandit returned no JSON output (exit {result.returncode}): {(result.stderr or '')[-1000:]}"], {"status": "FAILED", "reason": "No JSON output"}
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        return [], [f"Bandit JSON could not be parsed: {error}"], {"status": "FAILED", "reason": "Invalid JSON"}
    findings = []
    for item in data.get("results", []) or []:
        path = _relative_tool_path(item.get("filename"), workspace)
        line = item.get("line_number") or 1
        test_id = item.get("test_id") or "Bandit"
        severity = _severity_rank(item.get("issue_severity"))
        confidence = item.get("issue_confidence", "UNKNOWN")
        findings.append({
            "tool": "Bandit", "detected_by": ["Bandit"], "check_id": f"bandit.{test_id}",
            "path": path, "start": {"line": line}, "end": {"line": item.get("line_number", line)},
            "line_display": str(line), "extra": {
                "severity": severity, "message": item.get("issue_text", "Bandit finding"),
                "metadata": {"confidence": confidence, "test_id": test_id, "code": item.get("code", "")},
            },
        })
    if result.returncode not in (0, 1):
        return findings, [f"Bandit exited with code {result.returncode}: {(result.stderr or '')[-1000:]}"], {"status": "FAILED", "reason": f"Exit {result.returncode}"}
    return findings, [], {"status": "COMPLETED", "reason": f"{len(findings)} finding(s)"}
def run_gitleaks(workspace):
    """Scan downloaded working-tree files for secrets; secret values are never added to reports."""
    executable = shutil.which("gitleaks")
    if not executable:
        return [], ["Gitleaks is not installed; secret scanning was not run."], {"status": "NOT_INSTALLED", "reason": "Install Gitleaks and ensure it is on PATH."}
    report_path = BASE_DIR / f".gitleaks_report_{uuid4().hex}.json"
    commands = [
        [executable, "dir", "--report-format", "json", "--report-path", str(report_path), "--redact=100", "--no-banner", str(workspace)],
        [executable, "detect", "--source", str(workspace), "--report-format", "json", "--report-path", str(report_path), "--redact=100", "--no-git"],
    ]
    result = None
    try:
        for command in commands:
            try:
                result = subprocess.run(command, cwd=str(workspace), capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=OTHER_TOOL_TIMEOUT, check=False)
            except subprocess.TimeoutExpired:
                return [], ["Gitleaks timed out after 5 minutes."], {"status": "FAILED", "reason": "Timeout"}
            # Try legacy syntax only if the modern subcommand is unsupported.
            diagnostic = ((result.stderr or "") + "\n" + (result.stdout or "")).lower()
            if command[1] == "dir" and result.returncode not in (0, 1) and any(x in diagnostic for x in ("unknown command", "unknown flag", "flag provided but not defined", "usage:")):
                continue
            break
        if not report_path.exists():
            diagnostic = ((result.stderr or "") + "\n" + (result.stdout or ""))[-1500:] if result else "No process result"
            return [], [f"Gitleaks did not produce a JSON report: {diagnostic}"], {"status": "FAILED", "reason": "Missing report"}
        try:
            raw = json.loads(report_path.read_text(encoding="utf-8", errors="replace"))
        except json.JSONDecodeError as error:
            return [], [f"Gitleaks JSON could not be parsed: {error}"], {"status": "FAILED", "reason": "Invalid JSON"}
        raw_items = raw if isinstance(raw, list) else raw.get("findings", raw.get("Findings", [])) if isinstance(raw, dict) else []
        findings = []
        for item in raw_items or []:
            # Intentionally do not copy Secret, Match, or raw source lines from Gitleaks.
            rule_id = item.get("RuleID") or item.get("rule_id") or "secret-detected"
            description = item.get("Description") or item.get("description") or "Potential secret detected. Value redacted."
            path = _relative_tool_path(item.get("File") or item.get("file"), workspace)
            line = item.get("StartLine") or item.get("start_line") or 1
            end_line = item.get("EndLine") or item.get("end_line") or line
            findings.append({
                "tool": "Gitleaks", "detected_by": ["Gitleaks"], "check_id": f"gitleaks.{rule_id}",
                "path": path, "start": {"line": line}, "end": {"line": end_line},
                "line_display": str(line), "redact_evidence": True,
                "extra": {"severity": "HIGH", "message": f"{description} (potential secret value redacted)",
                          "metadata": {"rule_id": rule_id, "commit": item.get("Commit") or item.get("commit")}},
            })
        if result and result.returncode not in (0, 1):
            return findings, [f"Gitleaks exited with code {result.returncode}: {(result.stderr or '')[-1000:]}"], {"status": "FAILED", "reason": f"Exit {result.returncode}"}
        return findings, [], {"status": "COMPLETED", "reason": f"{len(findings)} finding(s); scans downloaded snapshot only, not Git history"}
    finally:
        try:
            report_path.unlink(missing_ok=True)
        except OSError:
            pass
def _osv_severity(vulnerability):
    database_specific = vulnerability.get("database_specific") or vulnerability.get("databaseSpecific") or {}
    value = database_specific.get("severity") or vulnerability.get("severity")
    if isinstance(value, list):
        scores = []
        for item in value:
            if isinstance(item, dict):
                score = item.get("score")
                try:
                    scores.append(float(score))
                except (TypeError, ValueError):
                    pass
        if scores:
            score = max(scores)
            return "CRITICAL" if score >= 9 else "HIGH" if score >= 7 else "MEDIUM" if score >= 4 else "LOW"
        return "UNKNOWN"
    return _severity_rank(value)
def run_osv_scanner(workspace, downloaded):
    """Scan supported dependency manifests/lockfiles using OSV-Scanner."""
    dependency_names = {
        "requirements.txt", "requirements-dev.txt", "requirements-prod.txt", "pyproject.toml", "poetry.lock", "uv.lock", "pipfile", "pipfile.lock",
        "package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "pom.xml", "build.gradle", "build.gradle.kts",
        "go.mod", "go.sum", "cargo.toml", "cargo.lock", "composer.json", "composer.lock", "gemfile", "gemfile.lock", "mix.lock",
    }
    manifests = [name for name in downloaded if Path(name).name.lower() in dependency_names]
    if not manifests:
        return [], [], {"status": "NOT_APPLICABLE", "reason": "No supported dependency manifest/lockfile found."}
    executable = shutil.which("osv-scanner")
    if not executable:
        return [], ["OSV-Scanner is not installed; dependency vulnerability scanning was not run."], {"status": "NOT_INSTALLED", "reason": "Install OSV-Scanner and ensure it is on PATH."}
    command = [executable, "scan", "--format", "json", str(workspace)]
    try:
        result = subprocess.run(command, cwd=str(workspace), capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=OTHER_TOOL_TIMEOUT, check=False)
    except subprocess.TimeoutExpired:
        return [], ["OSV-Scanner timed out after 5 minutes."], {"status": "FAILED", "reason": "Timeout"}
    if not result.stdout.strip():
        diagnostic = (result.stderr or "No JSON output")[-1500:]
        return [], [f"OSV-Scanner returned no JSON output (exit {result.returncode}): {diagnostic}"], {"status": "FAILED", "reason": "No JSON output"}
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        return [], [f"OSV-Scanner JSON could not be parsed: {error}"], {"status": "FAILED", "reason": "Invalid JSON"}
    findings = []
    for result_item in data.get("results", []) or []:
        source = result_item.get("source") or result_item.get("packageSource") or {}
        source_path = source.get("path") if isinstance(source, dict) else None
        relative_source = _relative_tool_path(source_path, workspace) if source_path else "Unknown dependency manifest"
        for package_item in result_item.get("packages", []) or []:
            package = package_item.get("package") or package_item.get("Package") or {}
            package_name = package.get("name") or package.get("Name") or "unknown-package"
            version = package.get("version") or package.get("Version") or "unknown-version"
            ecosystem = package.get("ecosystem") or package.get("Ecosystem") or "unknown ecosystem"
            vulnerabilities = package_item.get("vulnerabilities") or package_item.get("Vulnerabilities") or []
            for vulnerability in vulnerabilities:
                vuln_id = vulnerability.get("id") or vulnerability.get("ID") or "OSV-unknown"
                aliases = vulnerability.get("aliases") or vulnerability.get("Aliases") or []
                summary = vulnerability.get("summary") or vulnerability.get("Summary") or vulnerability.get("details") or vulnerability.get("Details") or "Known vulnerability in dependency."
                fixed_versions = []
                for affected in vulnerability.get("affected", []) or vulnerability.get("Affected", []) or []:
                    for event in (affected.get("ranges") or affected.get("Ranges") or []):
                        for event_item in event.get("events", []) or event.get("Events", []) or []:
                            fixed = event_item.get("fixed") or event_item.get("Fixed")
                            if fixed:
                                fixed_versions.append(str(fixed))
                fix_text = f" Potential fixed version(s): {', '.join(sorted(set(fixed_versions)))}." if fixed_versions else " Check the advisory for affected and fixed versions."
                findings.append({
                    "tool": "OSV-Scanner", "detected_by": ["OSV-Scanner"], "check_id": f"osv.{vuln_id}",
                    "path": relative_source, "start": {"line": 1}, "end": {"line": 1}, "line_display": "N/A",
                    "extra": {"severity": _osv_severity(vulnerability), "message": f"{summary} Package: {package_name}@{version} ({ecosystem}); advisory: {vuln_id}; aliases: {', '.join(map(str, aliases)) or 'none'}.{fix_text}",
                              "dependency": {"name": package_name, "version": version, "ecosystem": ecosystem, "advisory": vuln_id, "aliases": aliases, "manifest": relative_source}},
                })
    if result.returncode not in (0, 1) and not findings:
        return findings, [f"OSV-Scanner exited with code {result.returncode}: {(result.stderr or '')[-1200:]}"], {"status": "FAILED", "reason": f"Exit {result.returncode}"}
    if result.returncode not in (0, 1) and findings:
        return findings, [f"OSV-Scanner returned findings but exited with code {result.returncode}: {(result.stderr or '')[-1000:]}"], {"status": "FAILED", "reason": f"Exit {result.returncode}"}
    return findings, [], {"status": "COMPLETED", "reason": f"{len(findings)} vulnerability finding(s)"}
def finding_category(finding):
    """Conservative categories for safe cross-tool deduplication."""
    tool = str(finding.get("tool", "Semgrep")).lower()
    rule = str(finding.get("check_id", "")).lower()
    message = str(finding.get("extra", {}).get("message", "")).lower()
    if tool == "osv-scanner" or rule.startswith("osv."):
        return "dependency-vulnerability"
    if tool == "gitleaks" or any(token in rule + " " + message for token in ("secret", "api key", "credential", "hardcoded-database-password", "hardcoded-flask-secret-key")):
        return "secret-or-credential"
    if any(token in rule + " " + message for token in ("password", "passwd", "pwd", "userpassword")):
        return "password-handling"
    if "debug" in rule or "debug=True" in message:
        return "debug-configuration"
    if "csrf" in rule or "csrf" in message:
        return "csrf"
    if "sql-injection" in rule or "sql injection" in message:
        return "sql-injection"
    if "xss" in rule or "cross-site scripting" in message:
        return "xss"
    return f"{tool}:{rule}"
def deduplicate_findings(findings):
    """Merge clear same-file/same-line/same-category duplicates and retain provenance."""
    merged = {}
    for finding in findings:
        path = str(finding.get("path", "Unknown file")).replace("\\\\", "/")
        line = str(finding.get("line_display", finding.get("start", {}).get("line", "N/A")))
        category = finding_category(finding)
        # Only merge high-confidence overlaps at the same path and line. Do not
        # merge unrelated findings just because their messages contain similar words.
        key = (path, line, category)
        if key not in merged:
            clone = dict(finding)
            clone["detected_by"] = list(finding.get("detected_by") or [finding.get("tool", "Semgrep")])
            clone["corroborating_findings"] = []
            merged[key] = clone
            continue
        existing = merged[key]
        tool_name = finding.get("tool", "Unknown tool")
        if tool_name not in existing["detected_by"]:
            existing["detected_by"].append(tool_name)
        existing["corroborating_findings"].append({
            "tool": tool_name, "rule_id": finding.get("check_id"),
            "message": finding.get("extra", {}).get("message", ""),
        })
        # Keep the more severe normalized severity while retaining all detector names.
        rank = {"UNKNOWN": 0, "INFO": 1, "LOW": 2, "MEDIUM": 3, "WARNING": 3, "HIGH": 4, "ERROR": 4, "CRITICAL": 5}
        old_sev = str(existing.get("extra", {}).get("severity", "UNKNOWN")).upper()
        new_sev = str(finding.get("extra", {}).get("severity", "UNKNOWN")).upper()
        if rank.get(new_sev, 0) > rank.get(old_sev, 0):
            existing.setdefault("extra", {})["severity"] = new_sev
        if finding.get("redact_evidence"):
            existing["redact_evidence"] = True
        if finding.get("extra", {}).get("dependency"):
            existing.setdefault("extra", {})["dependency"] = finding["extra"]["dependency"]
    return list(merged.values())
# ---------------- SOURCE EVIDENCE ----------------
def get_source_evidence(workspace, finding):
    """Get source evidence safely; redact secret lines and handle dependency findings."""
    extra = finding.get("extra", {}) or {}
    if extra.get("dependency"):
        dep = extra["dependency"]
        return (
            f"Dependency advisory evidence (OSV-Scanner):\n"
            f"Package: {dep.get('name', 'unknown')}\n"
            f"Version: {dep.get('version', 'unknown')}\n"
            f"Ecosystem: {dep.get('ecosystem', 'unknown')}\n"
            f"Manifest/lockfile: {dep.get('manifest', finding.get('path', 'unknown'))}\n"
            f"Advisory: {dep.get('advisory', 'unknown')}\n"
            "This is dependency metadata, not a source-code line finding."
        )
    relative_path = finding.get("path", "")
    candidate = (workspace / relative_path).resolve()
    root = workspace.resolve()
    try:
        candidate.relative_to(root)
    except (ValueError, RuntimeError):
        return "Source evidence unavailable: invalid file path."
    if not candidate.is_file():
        return "Source evidence unavailable: file not found."
    start_line = finding.get("start", {}).get("line", 1)
    end_line = finding.get("end", {}).get("line", start_line)
    try:
        start_line = int(start_line)
        end_line = int(end_line)
    except (TypeError, ValueError):
        return "Source evidence unavailable: this finding has no source line (for example, a dependency advisory)."
    try:
        lines = candidate.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as error:
        return f"Could not read source file: {error}"
    first = max(1, start_line - 5)
    last = min(len(lines), max(end_line + 5, start_line + 5))
    output = []
    for line_number in range(first, last + 1):
        line_text = lines[line_number - 1]
        if finding.get("redact_evidence") and start_line <= line_number <= end_line:
            line_text = "[REDACTED: line contains a potential secret; inspect locally]"
        output.append(f"{line_number}: {line_text}")
    return "\n".join(output)
# ---------------- OLLAMA AI ANALYSIS ----------------
# Kept unchanged from the code you supplied.
def analyze_with_ollama(finding, evidence):
    """Ask the local Ollama model to explain one scanner finding."""
    rule_id = finding.get("check_id", "Unknown rule")
    severity = finding.get("extra", {}).get("severity", "UNKNOWN")
    message = finding.get("extra", {}).get("message", "No message supplied.")
    path = finding.get("path", "Unknown file")
    start_line = finding.get("start", {}).get("line", "Unknown")
    prompt = f"""
You are assisting with a defensive source-code security review.
Explain the scanner finding below using only the supplied evidence.
SCANNER RULE: {rule_id}
SCANNER SEVERITY: {severity}
FILE: {path}
LINE: {start_line}
SCANNER MESSAGE:
{message}
SOURCE EVIDENCE:
{evidence}
Write the analysis with these headings:
1. What the scanner detected
2. Why it may matter
3. Potential impact
4. Recommended remediation
5. Evidence and uncertainty
Rules:
- Treat the scanner result as a finding to evaluate, not proof of exploitation.
- Clearly distinguish confirmed facts from possible risks.
- Do not invent source code, credentials, attack results, or evidence.
- Do not claim SQL injection, XSS, or another vulnerability unless the
  supplied evidence supports that specific claim.
- Do not invent cryptographic hashes or provide placeholder hashes as fixes.
- If a safe fix depends on missing context, explain what must be verified.
- Do not say a fix is guaranteed to work unless the evidence supports it.
- Be concise, specific, and technically accurate.
"""
    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": 0.1},
    }
    request = urllib.request.Request(
        OLLAMA_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=OLLAMA_TIMEOUT) as response:
            data = json.loads(response.read().decode("utf-8"))
        return data.get("response", "").strip() or (
            "AI returned an empty response. Review the scanner evidence manually."
        )
    except Exception as error:
        return (
            "AI analysis could not be completed.\n\n"
            f"Reason: {type(error).__name__}: {error}\n\n"
            "Review the Semgrep finding and source evidence manually."
        )
# ---------------- REPORT GENERATION ----------------
def format_finding(index, finding, workspace):
    extra = finding.get("extra", {}) or {}
    start = finding.get("start", {}) or {}
    end = finding.get("end", {}) or {}
    rule_id = finding.get("check_id", "Unknown rule")
    path = finding.get("path", "Unknown file")
    severity = extra.get("severity", "UNKNOWN")
    message = extra.get("message", "No scanner message supplied.")
    line = finding.get("line_display", start.get("line", "N/A"))
    end_line = end.get("line", line)
    evidence = get_source_evidence(workspace, finding)
    tool_names = finding.get("detected_by") or [finding.get("tool", "Semgrep")]
    metadata = extra.get("metadata") or {}
    corroborating = finding.get("corroborating_findings") or []
    print(f"Analyzing finding {index}: {path}:{line} [{', '.join(tool_names)}]")
    analysis = analyze_with_ollama(finding, evidence)
    block = f"""
## Finding {index}: {rule_id}
- Detected by: {', '.join(tool_names)}
- File / dependency manifest: `{path}`
- Line: {line}
- End line: {end_line}
- Scanner severity: {severity}
- Scanner message: {message}
"""
    if metadata.get("confidence"):
        block += f"- Bandit confidence: {metadata['confidence']}\n"
    if corroborating:
        block += "- Corroborating tool findings: " + "; ".join(
            f"{item.get('tool', 'tool')} ({item.get('rule_id', 'rule')})" for item in corroborating
        ) + "\n"
    if finding.get("framework_mismatch_review"):
        block += "- Framework applicability: Review required; the rule appears framework-specific, but the framework detector did not confirm that framework.\n"
    block += f"""
### Source evidence
```text
{evidence}
```
### AI analysis
{analysis}
---
"""
    return block
def create_report(
    repository, branch, commit_sha, scan_time, downloaded, findings, warnings,
    failed_downloads, skipped_files, skipped_by_semgrep, frameworks,
    semgrep_configs, parser_errors, status, finding_sections, fatal_error=None,
    tool_statuses=None, semgrep_skipped_paths=None,
):
    tool_statuses = tool_statuses or {}
    semgrep_skipped_paths = semgrep_skipped_paths or []
    severity_counts = {}
    tool_counts = {}
    for finding in findings:
        sev = str(finding.get("extra", {}).get("severity", "UNKNOWN")).upper()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        for tool_name in (finding.get("detected_by") or [finding.get("tool", "Unknown")]):
            tool_counts[tool_name] = tool_counts.get(tool_name, 0) + 1
    lines = [
        "# GitHub Security Scan Report", "",
        f"- Repository: {repository}", f"- Branch: {branch or 'Unknown'}",
        f"- Commit scanned: `{commit_sha or 'Unknown'}`", f"- Scan time: {scan_time}",
        f"- Scan status: **{status}**", f"- Source files downloaded: {len(downloaded)}",
        f"- Total normalized findings: {len(findings)}",
        f"- Detected frameworks: {', '.join(frameworks) if frameworks else 'Not detected'}",
        f"- Semgrep configurations: {', '.join(semgrep_configs) if semgrep_configs else 'Not run'}",
        f"- Scanner execution warnings/errors: {len(warnings)}",
        f"- Template/parser errors: {len(parser_errors)}", "",
        "## Tool coverage", "",
    ]
    if tool_statuses:
        for name, item in tool_statuses.items():
            lines.append(f"- **{name}:** {item.get('status', 'UNKNOWN')} — {item.get('reason', '')}")
    else:
        lines.append("- Tool status information unavailable.")
    lines.extend(["", "## Findings summary by tool", ""])
    if tool_counts:
        lines.extend(f"- {name}: {count}" for name, count in sorted(tool_counts.items()))
    else:
        lines.append("- No findings reported.")
    lines.extend(["", "## Findings summary by severity", ""])
    if severity_counts:
        lines.extend(f"- {severity}: {count}" for severity, count in sorted(severity_counts.items()))
    else:
        lines.append("- No findings reported.")
    lines.extend(["", "## Files included in this scan", ""])
    if downloaded:
        lines.extend(f"- `{name}`" for name in downloaded)
    else:
        lines.append("- No files were downloaded.")
    lines.extend([
        "", "> Scope: this scanner downloads supported source/configuration files and runs multiple static-analysis, secret-detection, and dependency tools. Gitleaks scans the downloaded snapshot, not the repository commit history. Excluded directories, unsupported file types, size limits, network errors, missing tools, and parser errors can reduce coverage. A clean report does not prove the repository is vulnerability-free.",
        "", "> Security findings are indicators requiring validation. Severity is not proof of exploitability; AI explanations are advisory and must not replace manual review.", "",
    ])
    if skipped_files:
        lines.extend(["## Files skipped by scanner limits", ""])
        lines.extend(f"- {item}" for item in skipped_files)
        lines.append("")
    if failed_downloads:
        lines.extend(["## Files that could not be downloaded", ""])
        lines.extend(f"- {item}" for item in failed_downloads)
        lines.append("")
    if semgrep_skipped_paths:
        lines.extend(["## Semgrep skipped targets", "", "These targets were reported as skipped by Semgrep. Review them when they include relevant source files.", ""])
        lines.extend(f"- {item}" for item in semgrep_skipped_paths)
        lines.append("")
    if skipped_by_semgrep:
        lines.extend([
            "## Framework-specific findings requiring applicability review", "",
            "These findings appear to use framework-specific rules that do not match the detected framework. They are preserved for manual review and have not been discarded from the scan.", "",
        ])
        for item in skipped_by_semgrep:
            extra = item.get("extra", {}) or {}
            lines.append(f"- `{item.get('check_id', 'Unknown rule')}` — `{item.get('path', 'Unknown file')}`:{item.get('start', {}).get('line', '?')} — {extra.get('message', 'No message supplied.')}")
        lines.append("")
    if warnings:
        lines.extend(["## Scanner execution warnings/errors", "", "Review these messages before treating the scan as complete.", ""])
        lines.extend(f"- {warning}" for warning in warnings)
        lines.append("")
    if parser_errors:
        lines.extend(["## Parser/template errors requiring review", "", "Some content could not be parsed. Findings may be missing from those files.", ""])
        lines.extend(f"- {item}" for item in parser_errors)
        lines.append("")
    if fatal_error:
        lines.extend(["## Scan error", "", fatal_error, ""])
    lines.extend(["## Findings", ""])
    if findings:
        lines.extend(finding_sections)
    else:
        lines.extend(["No findings were reported by the tools that completed successfully. This does not prove the repository is vulnerability-free.", ""])
    return "\n".join(lines).rstrip() + "\n"
def save_reports(report_text, history_path):
    """Write latest report and exactly one history file for this scan."""
    LATEST_REPORT.write_text(report_text, encoding="utf-8")
    history_path.write_text(report_text, encoding="utf-8")
    print(f"\nLatest report: {LATEST_REPORT}")
    print(f"History report: {history_path}")
# ---------------- MAIN WORKFLOW ----------------
def main():
    url = input("Enter a public GitHub repository URL: ").strip()
    scan_time = datetime.now().astimezone().isoformat(timespec="seconds")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    HISTORY_DIR.mkdir(parents=True, exist_ok=True)
    BASE_WORKSPACE.mkdir(parents=True, exist_ok=True)
    history_path = HISTORY_DIR / f"scan_{timestamp}.md"
    workspace = BASE_WORKSPACE / uuid4().hex
    repository, branch, commit_sha = "Unknown", None, None
    downloaded, findings, warnings = [], [], []
    failed_downloads, skipped_files, skipped_by_semgrep = [], [], []
    semgrep_skipped_paths, frameworks, semgrep_configs, parser_errors = [], [], [], []
    finding_sections, tool_statuses = [], {}
    status, fatal_error, semgrep_exit_code = "FAILED", None, None
    try:
        owner, repo = parse_github_url(url)
        repository = f"{owner}/{repo}"
        branch, commit_sha, tree = get_repository_files(owner, repo)
        downloaded, failed_downloads, skipped_files = download_source_files(owner, repo, commit_sha, tree, workspace)
        if not downloaded:
            raise RuntimeError("No supported files were downloaded. Nothing was scanned.")
        frameworks = detect_frameworks(workspace, downloaded)
        semgrep_findings, semgrep_warnings, semgrep_exit_code, parser_errors, semgrep_configs, semgrep_skipped_paths = run_semgrep(workspace, downloaded, frameworks)
        tool_statuses["Semgrep"] = {"status": "COMPLETED" if semgrep_exit_code in (0, 1) else "FAILED", "reason": f"{len(semgrep_findings)} finding(s); {len(semgrep_skipped_paths)} skipped target(s)"}
        findings.extend(semgrep_findings)
        warnings.extend(semgrep_warnings)
        # Keep framework-mismatch results in the report; annotate instead of dropping them.
        for finding in findings:
            rule_id = str(finding.get("check_id", "")).lower()
            if "django" in rule_id and "django" not in frameworks:
                finding["framework_mismatch_review"] = True
                skipped_by_semgrep.append(finding)
        bandit_findings, bandit_warnings, tool_statuses["Bandit"] = run_bandit(workspace, downloaded)
        findings.extend(bandit_findings)
        warnings.extend(bandit_warnings)
        gitleaks_findings, gitleaks_warnings, tool_statuses["Gitleaks"] = run_gitleaks(workspace)
        findings.extend(gitleaks_findings)
        warnings.extend(gitleaks_warnings)
        osv_findings, osv_warnings, tool_statuses["OSV-Scanner"] = run_osv_scanner(workspace, downloaded)
        findings.extend(osv_findings)
        warnings.extend(osv_warnings)
        if failed_downloads:
            warnings.append(f"{len(failed_downloads)} file(s) could not be downloaded.")
        if skipped_files:
            warnings.append(f"{len(skipped_files)} file(s) were skipped by scanner limits/path checks.")
        if parser_errors:
            warnings.append(f"{len(parser_errors)} Semgrep parser/syntax error(s) were detected.")
        if semgrep_skipped_paths:
            warnings.append(f"Semgrep skipped {len(semgrep_skipped_paths)} target(s); see coverage details.")
        findings = deduplicate_findings(findings)
        for index, finding in enumerate(findings, start=1):
            try:
                finding_sections.append(format_finding(index, finding, workspace))
            except Exception as error:
                finding_sections.append(f"\n## Finding {index}: {finding.get('check_id', 'Unknown rule')}\n\nEvidence extraction or analysis failed: {type(error).__name__}: {error}\n\n")
                warnings.append(f"Analysis failed for finding {index}: {type(error).__name__}: {error}")
        failed_tools = any(value.get("status") in {"FAILED", "NOT_INSTALLED"} for value in tool_statuses.values())
        partial_coverage = bool(failed_downloads or skipped_files or parser_errors or semgrep_skipped_paths or failed_tools)
        if semgrep_exit_code not in (0, 1):
            status = "PARTIAL" if downloaded else "FAILED"
        elif partial_coverage:
            status = "PARTIAL"
        elif warnings:
            status = "COMPLETED_WITH_WARNINGS"
        else:
            status = "COMPLETED"
    except Exception as error:
        fatal_error = f"{type(error).__name__}: {error}"
        warnings.append(fatal_error)
        status = "FAILED"
        # Make tool coverage explicit even when setup/download failed early.
        tool_statuses.setdefault("Semgrep", {"status": "NOT_RUN", "reason": "Scan failed before Semgrep completed."})
        tool_statuses.setdefault("Bandit", {"status": "NOT_RUN", "reason": "Scan failed before Bandit completed."})
        tool_statuses.setdefault("Gitleaks", {"status": "NOT_RUN", "reason": "Scan failed before Gitleaks completed."})
        tool_statuses.setdefault("OSV-Scanner", {"status": "NOT_RUN", "reason": "Scan failed before OSV-Scanner completed."})
    try:
        report_text = create_report(
            repository=repository, branch=branch, commit_sha=commit_sha,
            scan_time=scan_time, downloaded=downloaded, findings=findings,
            warnings=warnings, failed_downloads=failed_downloads,
            skipped_files=skipped_files, skipped_by_semgrep=skipped_by_semgrep,
            frameworks=frameworks, semgrep_configs=semgrep_configs,
            parser_errors=parser_errors, status=status,
            finding_sections=finding_sections, fatal_error=fatal_error,
            tool_statuses=tool_statuses, semgrep_skipped_paths=semgrep_skipped_paths,
        )
        save_reports(report_text, history_path)
        print(f"\nScan status: {status}")
        print(f"Total normalized findings: {len(findings)}")
        print("Scan finished." if status != "FAILED" else "Scan failed.")
        if status in {"FAILED", "PARTIAL"}:
            print("Review security_report.md, especially tool coverage, warnings, and skipped-target sections.")
    finally:
        # Remove downloaded repository files after the report is safely generated.
        # The report/history files are stored outside this workspace and are preserved.
        shutil.rmtree(workspace, ignore_errors=True)
        try:
            BASE_WORKSPACE.rmdir()  # succeeds only when no other scans are using it
        except OSError:
            pass
if __name__ == "__main__":
    main()
