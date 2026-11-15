import json
import re
import subprocess
from pathlib import Path


CODE_EXTENSIONS = {".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go"}
SECRET_PATTERN = re.compile(
    r"(?i)\b(api[_-]?key|secret|password|token|private[_-]?key)\b\s*[:=]\s*['\"]([^'\"]{8,})['\"]"
)
HTTP_PATTERN = re.compile(r"""https?://[^\s'"]+""")
AUTH_MARKERS = ("auth", "authorize", "authorization", "permission", "security", "depends(")
ROUTE_PATTERN = re.compile(
    r"(?i)(?:@(?:app|router)\.(?:get|post|put|patch|delete|options|head)|"
    r"(?:app|router)\.(?:get|post|put|patch|delete))\s*\(\s*['\"]([^'\"]+)"
)


def finding(
    *,
    analyzer: str,
    rule: str,
    severity: str,
    path: str,
    line: int | None,
    message: str,
    evidence: str,
) -> dict:
    return {
        "analyzer": analyzer,
        "rule": rule,
        "severity": severity,
        "path": path,
        "line": line,
        "message": message,
        "evidence": evidence.strip()[:500],
    }


def scan_builtin(repository_root: Path, files: list[str]) -> list[dict]:
    findings = []
    for relative_path in files:
        path = repository_root / relative_path
        if path.suffix.lower() not in CODE_EXTENSIONS or not path.is_file():
            continue
        try:
            lines = path.read_text(errors="ignore").splitlines()
        except OSError:
            continue
        for line_number, line in enumerate(lines, start=1):
            if relative_path.endswith(".env.example") or "example" in relative_path.lower():
                continue
            secret = SECRET_PATTERN.search(line)
            if secret and secret.group(2).lower() not in {"changeme", "replace-me", "your-secret"}:
                findings.append(finding(
                    analyzer="securechange",
                    rule="hardcoded-credential",
                    severity="critical",
                    path=relative_path,
                    line=line_number,
                    message=f"Possible hardcoded {secret.group(1)} detected.",
                    evidence=line,
                ))
            for match in HTTP_PATTERN.finditer(line):
                url = match.group(0)
                if not url.startswith("http://localhost") and not url.startswith("http://127.0.0.1"):
                    findings.append(finding(
                        analyzer="securechange",
                        rule="insecure-http-url",
                        severity="medium",
                        path=relative_path,
                        line=line_number,
                        message="Plain HTTP URL may expose data in transit.",
                        evidence=url,
                    ))

        for line_number, line in enumerate(lines, start=1):
            route = ROUTE_PATTERN.search(line)
            if not route:
                continue
            window = "\n".join(lines[line_number - 1 : line_number + 8]).lower()
            if not any(marker in window for marker in AUTH_MARKERS):
                findings.append(finding(
                    analyzer="securechange",
                    rule="missing-authorization",
                    severity="high",
                    path=relative_path,
                    line=line_number,
                    message=f"Endpoint {route.group(1)} may not enforce authentication or authorization.",
                    evidence=line,
                ))
    return findings


def run_external_analyzer(command: list[str], repository_root: Path, analyzer: str) -> tuple[list[dict], str]:
    try:
        result = subprocess.run(
            command + [str(repository_root)],
            check=False,
            capture_output=True,
            text=True,
            timeout=45,
        )
    except FileNotFoundError:
        return [], "not-installed"
    except subprocess.TimeoutExpired:
        return [], "timed-out"
    if analyzer == "bandit":
        try:
            payload = json.loads(result.stdout or "{}")
            findings = [
                finding(
                    analyzer="bandit",
                    rule=item.get("test_id", "bandit"),
                    severity=str(item.get("issue_severity", "medium")).lower(),
                    path=item.get("filename", ""),
                    line=item.get("line_number"),
                    message=item.get("issue_text", "Bandit finding"),
                    evidence=item.get("code", ""),
                )
                for item in payload.get("results", [])
            ]
            return findings, "completed"
        except (json.JSONDecodeError, TypeError):
            return [], "invalid-output"
    try:
        payload = json.loads(result.stdout or "{}")
        findings = [
            finding(
                analyzer="semgrep",
                rule=item.get("check_id", "semgrep"),
                severity=str((item.get("extra") or {}).get("severity", "warning")).lower(),
                path=(item.get("path") or ""),
                line=((item.get("start") or {}).get("line")),
                message=(item.get("extra") or {}).get("message", "Semgrep finding"),
                evidence=((item.get("extra") or {}).get("lines", "")),
            )
            for item in payload.get("results", [])
        ]
        return findings, "completed"
    except (json.JSONDecodeError, TypeError):
        return [], "invalid-output"


def scan_repository(repository_root: Path, files: list[str]) -> tuple[list[dict], dict[str, str]]:
    findings = scan_builtin(repository_root, files)
    bandit_findings, bandit_status = run_external_analyzer(
        [
            "bandit",
            "-r",
            "-f",
            "json",
            "-q",
            "--exclude",
            ".venv,.security-venv,node_modules,dist,.git",
        ],
        repository_root,
        "bandit",
    )
    semgrep_findings, semgrep_status = run_external_analyzer(["semgrep", "--config", "auto", "--json", "--quiet"], repository_root, "semgrep")
    findings.extend(bandit_findings)
    findings.extend(semgrep_findings)
    return findings, {"securechange": "completed", "bandit": bandit_status, "semgrep": semgrep_status}
