#!/usr/bin/env python3
"""
SPECTRA Captures Strict Security & Schema Validator
===================================================
Enforces zero-trust validation on community telemetry capture submissions and
repository files:
  - Hard payload size ceiling (<= 250 KB)
  - Strict hex-only EEPROM keys and 16-bit integer/hex values
  - Strict top-level, gateway, and issue-label allowlists
  - Recursive XSS / HTML / template / shell / secret / private-key / path-leak checks
  - Safe allowlist verification of mock_python_snippet lines
  - Mathematical verification & duplicate/low-count collision audit for offset patches
"""

import argparse
import glob
import json
import os
import re
import sys
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

MAX_PAYLOAD_BYTES = 250 * 1024  # 250 KB hard ceiling
MAX_JSON_DEPTH = 12
MAX_TOTAL_NODES = 6000
MAX_EEPROM_WORDS = 2048

# Option A auto-ingestion allowlist
ALLOWED_AUTO_INGEST_USERS: Set[str] = {"pr0xya-91", "neon-rat"}
ALLOWED_AUTO_INGEST_ASSOCIATIONS: Set[str] = {"OWNER", "COLLABORATOR"}
APPROVED_CAPTURE_LABEL = "approved-capture"
NEEDS_REVIEW_LABEL = "needs-review"

# Strict issue label allowlist
ALLOWED_ISSUE_LABELS: Set[str] = {
    "capture",
    "approved-capture",
    "needs-review",
    "offset-fix",
    "bug",
    "enhancement",
    "documentation",
    "duplicate",
    "good first issue",
    "help wanted",
    "invalid",
    "question",
    "wontfix",
    "accessibility",
}

ALLOWED_TOP_LEVEL_KEYS: Set[str] = {
    "metadata",
    "identity",
    "gateways",
    "joe_ground_truth",
    "correlations",
    "mock_python_snippet",
    "eeprom_words",
    "ai_offset_fix",
}

ALLOWED_GATEWAY_KEYS: Set[str] = {
    "TY:",
    "TL:",
    "TY$:",
    "TL$:",
    "CS:",
    "CS$:",
    "IC:",
    "HZ:",
    "AS:",
    "DI$:",
    "ST$:",
}

_HEX_ADDR_RE = re.compile(r"^0x[0-9A-Fa-f]{2,4}$")
_HEX_VAL_STR_RE = re.compile(r"^(?:0x)?[0-9A-Fa-f]{1,4}$")
_SAFE_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

_SECRET_PATTERNS: Tuple[Tuple[str, re.Pattern], ...] = (
    ("github_pat", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9_]{16,}|github_pat_[A-Za-z0-9_]{20,})\b")),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("private_key_pem", re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")),
    ("bearer_token", re.compile(r"(?i)\bAuthorization\s*:\s*(?:Bearer|token)\s+[A-Za-z0-9._\-]{12,}")),
    ("generic_api_key", re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}\b")),
    ("jwt_token", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b")),
    ("workstation_path", re.compile(r"(?:/home/[A-Za-z0-9._-]+/|/Users/[A-Za-z0-9._-]+/|[A-Za-z]:\\Users\\[A-Za-z0-9._-]+\\)")),
)

_POISON_PATTERNS: Tuple[Tuple[str, re.Pattern], ...] = (
    ("xss_script_tag", re.compile(r"(?i)<\s*/?\s*(?:script|iframe|object|embed|svg|math|style|link|meta)\b")),
    ("xss_event_handler", re.compile(r"(?i)\bon(?:error|load|click|mouseover|focus|submit|animationstart)\s*=")),
    ("xss_uri_scheme", re.compile(r"(?i)\b(?:javascript|vbscript|data\s*:\s*text/html)\s*:")),
    ("gha_expr_injection", re.compile(r"\$\{\{.*?\}\}")),
    ("shell_cmd_subst", re.compile(r"\$\([^)]+\)|`[^`]+`")),
    ("python_exec_poison", re.compile(r"\b(?:__import__|eval|exec|subprocess|os\.system|os\.popen|shutil\.rmtree)\s*\(")),
)

# Strict allowlist for lines inside legacy mock_python_snippet
_MOCK_SNIPPET_ALLOWED_LINE_RES: Tuple[re.Pattern, ...] = (
    re.compile(r"^\s*$"),
    re.compile(r"^\s*#\s*Simulation Mock Seed for [A-Za-z0-9 _().,:/\-+]{1,120}$"),
    re.compile(r"^\s*if\s+'[A-Za-z0-9_\-]{1,40}'\s+in\s+self\.port_name\.upper\(\):$"),
    re.compile(r"^\s*self\._mock_eeprom\s*=\s*\{i:\s*0x0000\s+for\s+i\s+in\s+range\(\d{1,4}\)\}$"),
    re.compile(r"^\s*self\._mock_eeprom\[0x[0-9A-Fa-f]{4}\]\s*=\s*0x[0-9A-Fa-f]{4}\s*(?:#\s*\d{1,6})?$"),
    re.compile(r"^\s*return\s*$"),
)


def parse_eeprom_word_value(val: Any) -> Optional[int]:
    """Parse a strict 16-bit EEPROM word (int 0..0xFFFF or strict hex string). Rejects bool/arbitrary text."""
    if isinstance(val, bool):
        return None
    if isinstance(val, int):
        return val if 0 <= val <= 0xFFFF else None
    if isinstance(val, str):
        s = val.strip()
        if _HEX_VAL_STR_RE.fullmatch(s):
            parsed = int(s, 16)
            return parsed if 0 <= parsed <= 0xFFFF else None
    return None


def validate_issue_labels(labels: Sequence[str]) -> Tuple[bool, List[str]]:
    """Enforce the repository issue label allowlist."""
    disallowed: List[str] = []
    for raw in labels:
        name = str(raw or "").strip()
        if not name:
            continue
        if name.lower() not in ALLOWED_ISSUE_LABELS:
            disallowed.append(name)
    return len(disallowed) == 0, disallowed


def is_auto_ingest_authorized(
    author_login: str,
    author_association: str,
    issue_labels: Sequence[str],
    event_action: str = "opened",
    label_added: str = "",
    actor_login: str = "",
    actor_is_collaborator: bool = False,
) -> Tuple[bool, str]:
    """
    Evaluate Option A auto-ingestion policy:
      - Allowlisted users: Pr0xyA-91, neon-rat
      - Or author_association in {OWNER, COLLABORATOR}
      - Or manual `approved-capture` label applied by an authorized maintainer
    """
    author_low = str(author_login or "").strip().lower()
    assoc_up = str(author_association or "").strip().upper()
    actor_low = str(actor_login or "").strip().lower()
    labels_low = {str(l or "").strip().lower() for l in issue_labels}

    if author_low in ALLOWED_AUTO_INGEST_USERS:
        return True, f"allowlisted contributor @{author_login}"
    if assoc_up in ALLOWED_AUTO_INGEST_ASSOCIATIONS:
        return True, f"repository {assoc_up} (@{author_login})"

    if APPROVED_CAPTURE_LABEL in labels_low:
        if event_action == "labeled" and str(label_added or "").strip().lower() == APPROVED_CAPTURE_LABEL:
            if actor_low in ALLOWED_AUTO_INGEST_USERS or actor_is_collaborator:
                return True, f"manually approved via `{APPROVED_CAPTURE_LABEL}` by @{actor_login}"
            return False, f"label `{APPROVED_CAPTURE_LABEL}` actor @{actor_login} is not an authorized maintainer"
        if actor_low in ALLOWED_AUTO_INGEST_USERS or actor_is_collaborator:
            return True, f"carries verified `{APPROVED_CAPTURE_LABEL}` label"
        return False, "external issue cannot self-approve with `approved-capture`"

    return False, f"external contributor @{author_login or 'unknown'} (requires maintainer `{APPROVED_CAPTURE_LABEL}` label)"


def _check_string_safety(text: str, path: str, errors: List[str], allow_newlines: bool = False) -> None:
    if not isinstance(text, str):
        return
    if _SAFE_CONTROL_RE.search(text):
        errors.append(f"Illegal control character detected at {path}")
    if not allow_newlines and ("\n" in text or "\r" in text):
        if not path.startswith("mock_python_snippet") and not path.startswith("joe_ground_truth.raw_lines"):
            pass  # multiline notes are allowed if clean of injection patterns
    for pname, pat in _SECRET_PATTERNS:
        if pat.search(text):
            errors.append(f"Potential secret/PII leak ({pname}) detected at {path}")
    for pname, pat in _POISON_PATTERNS:
        if pat.search(text):
            errors.append(f"Potential payload poisoning ({pname}) detected at {path}")


def _walk_and_audit(obj: Any, path: str, errors: List[str], depth: int, counter: List[int]) -> None:
    counter[0] += 1
    if counter[0] > MAX_TOTAL_NODES:
        if len(errors) < 25:
            errors.append(f"JSON node count exceeds maximum limit ({MAX_TOTAL_NODES})")
        return
    if depth > MAX_JSON_DEPTH:
        errors.append(f"JSON nesting depth exceeds maximum ({MAX_JSON_DEPTH}) at {path}")
        return

    if isinstance(obj, dict):
        for k, v in obj.items():
            if not isinstance(k, str):
                errors.append(f"Non-string key at {path}")
                continue
            if len(k) > 128:
                errors.append(f"Oversized key (>128 chars) at {path}")
            _check_string_safety(k, f"{path}.{k}" if path else k, errors)
            _walk_and_audit(v, f"{path}.{k}" if path else k, errors, depth + 1, counter)
    elif isinstance(obj, list):
        if len(obj) > 2048:
            errors.append(f"Oversized array (>2048 items) at {path}")
            return
        for idx, item in enumerate(obj):
            _walk_and_audit(item, f"{path}[{idx}]", errors, depth + 1, counter)
    elif isinstance(obj, str):
        max_len = 16384 if path == "mock_python_snippet" else 2048
        if len(obj) > max_len:
            errors.append(f"Oversized string ({len(obj)} > {max_len}) at {path}")
        _check_string_safety(obj, path, errors, allow_newlines=(path == "mock_python_snippet"))


def validate_eeprom_words(eeprom: Any) -> Tuple[List[str], Dict[int, int]]:
    """Strict hex-only EEPROM address & 16-bit word validator."""
    errors: List[str] = []
    parsed: Dict[int, int] = {}
    if not isinstance(eeprom, dict):
        return ["`eeprom_words` must be a JSON object."], parsed
    if len(eeprom) == 0:
        return ["`eeprom_words` is empty; at least 1 hex register word is required."], parsed
    if len(eeprom) > MAX_EEPROM_WORDS:
        return [f"`eeprom_words` exceeds maximum allowed size ({len(eeprom)} > {MAX_EEPROM_WORDS})."], parsed

    for raw_k, raw_v in eeprom.items():
        if not isinstance(raw_k, str) or not _HEX_ADDR_RE.fullmatch(raw_k.strip()):
            errors.append(f"Non-hex EEPROM key rejected: {raw_k!r} (expected 0xXXXX)")
            if len(errors) >= 15:
                break
            continue
        val = parse_eeprom_word_value(raw_v)
        if val is None:
            errors.append(f"Invalid EEPROM value at {raw_k}: {raw_v!r} (must be 0..65535 int or 16-bit hex)")
            if len(errors) >= 15:
                break
            continue
        addr_int = int(raw_k.strip(), 16)
        parsed[addr_int] = val

    return errors, parsed


def audit_offset_fix_math(ai_fix: Dict[str, Any], eeprom_int: Dict[int, int]) -> Tuple[List[str], List[str]]:
    """Verify offset patch schema, mathematical match against EEPROM, and flag low-count/duplicate collisions."""
    errors: List[str] = []
    warnings: List[str] = []
    if not isinstance(ai_fix, dict):
        return ["`ai_offset_fix` must be an object."], warnings

    seen_addrs: Dict[int, str] = {}
    for section in ("products", "maintenance"):
        rows = ai_fix.get(section)
        if rows is None:
            continue
        if not isinstance(rows, list) or len(rows) > 128:
            errors.append(f"`ai_offset_fix.{section}` must be a list of <= 128 items.")
            continue
        for idx, item in enumerate(rows):
            if not isinstance(item, dict):
                errors.append(f"`ai_offset_fix.{section}[{idx}]` must be an object.")
                continue
            name = str(item.get("name") or "").strip()
            if not name or len(name) > 100:
                errors.append(f"Invalid name in `ai_offset_fix.{section}[{idx}]`.")
                continue
            raw_addr = item.get("addr") if item.get("addr") is not None else item.get("addr_hex")
            addr_i = parse_eeprom_word_value(raw_addr)
            if addr_i is None:
                errors.append(f"Invalid EEPROM address for `{name}`: {raw_addr!r}")
                continue
            if addr_i in seen_addrs:
                warnings.append(
                    f"Duplicate address collision at `0x{addr_i:04X}` between `{seen_addrs[addr_i]}` and `{name}`"
                )
            else:
                seen_addrs[addr_i] = name
            if eeprom_int:
                if addr_i not in eeprom_int:
                    warnings.append(f"`{name}` address `0x{addr_i:04X}` not present in captured EEPROM words")
                else:
                    actual = eeprom_int[addr_i]
                    joe_cnt = item.get("joe_count")
                    if isinstance(joe_cnt, int) and not isinstance(joe_cnt, bool):
                        if actual != joe_cnt:
                            warnings.append(
                                f"Math mismatch for `{name}` at `0x{addr_i:04X}`: EEPROM={actual} vs J.O.E.={joe_cnt}"
                            )
                        elif joe_cnt <= 2:
                            same_val_addrs = [a for a, v in eeprom_int.items() if v == joe_cnt]
                            if len(same_val_addrs) > 1:
                                warnings.append(
                                    f"Low-count overlap (`count={joe_cnt}`) for `{name}` at `0x{addr_i:04X}` "
                                    f"({len(same_val_addrs)} EEPROM words hold value {joe_cnt})"
                                )
    return errors, warnings


def validate_capture_dict(
    data: Any,
    raw_size_bytes: Optional[int] = None,
    strict_keys: bool = True,
) -> Dict[str, Any]:
    """Validate a capture dictionary against strict SPECTRA security & schema rules."""
    errors: List[str] = []
    warnings: List[str] = []

    if raw_size_bytes is not None and raw_size_bytes > MAX_PAYLOAD_BYTES:
        errors.append(f"Payload exceeds 250 KB limit ({raw_size_bytes:,} > {MAX_PAYLOAD_BYTES:,} bytes).")

    if not isinstance(data, dict):
        return {
            "ok": False,
            "errors": errors + ["Root JSON payload must be an object."],
            "warnings": warnings,
            "words_count": 0,
            "payload_bytes": raw_size_bytes or 0,
        }

    # Check serialized size as well
    serialized = json.dumps(data, ensure_ascii=False).encode("utf-8")
    payload_bytes = max(raw_size_bytes or 0, len(serialized))
    if payload_bytes > MAX_PAYLOAD_BYTES:
        errors.append(f"Serialized payload exceeds 250 KB limit ({payload_bytes:,} > {MAX_PAYLOAD_BYTES:,} bytes).")

    # Required top-level keys
    for req in ("metadata", "identity", "gateways", "eeprom_words"):
        if req not in data or not isinstance(data.get(req), dict):
            errors.append(f"Missing or non-object required root key: `{req}`.")

    # Top-level key allowlist
    if strict_keys:
        unknown_top = sorted(set(data.keys()) - ALLOWED_TOP_LEVEL_KEYS)
        if unknown_top:
            errors.append(f"Unexpected top-level keys rejected: {', '.join(unknown_top)}")

    # Gateway key allowlist
    gateways = data.get("gateways")
    if isinstance(gateways, dict):
        bad_gw = sorted(k for k in gateways.keys() if k not in ALLOWED_GATEWAY_KEYS)
        if bad_gw:
            errors.append(f"Disallowed gateway keys rejected: {', '.join(bad_gw)}")

    # Strict hex-only EEPROM validation
    eep_errors, eeprom_int = validate_eeprom_words(data.get("eeprom_words"))
    errors.extend(eep_errors)

    # Validate optional mock_python_snippet against strict line allowlist
    snippet = data.get("mock_python_snippet")
    if snippet is not None:
        if not isinstance(snippet, str):
            errors.append("`mock_python_snippet` must be a string.")
        else:
            for lineno, line in enumerate(snippet.splitlines(), start=1):
                if not any(pat.match(line) for pat in _MOCK_SNIPPET_ALLOWED_LINE_RES):
                    errors.append(f"Disallowed code/content in `mock_python_snippet` line {lineno}: {line[:80]!r}")
                    break

    # Recursive walk for XSS / secret / path-leak / nesting checks
    _walk_and_audit(data, "", errors, depth=0, counter=[0])

    # Mathematical verification of optional ai_offset_fix
    if isinstance(data.get("ai_offset_fix"), dict):
        fix_errs, fix_warns = audit_offset_fix_math(data["ai_offset_fix"], eeprom_int)
        errors.extend(fix_errs)
        warnings.extend(fix_warns)

    ident = data.get("identity") if isinstance(data.get("identity"), dict) else {}
    return {
        "ok": len(errors) == 0,
        "errors": errors,
        "warnings": warnings,
        "words_count": len(eeprom_int),
        "payload_bytes": payload_bytes,
        "model_name": str(ident.get("model_name") or "Unknown"),
        "article_number": str(ident.get("article_number") or ""),
        "firmware": str((gateways or {}).get("TY:") or "").replace("ty:", "").strip() if isinstance(gateways, dict) else "",
    }


def validate_file(file_path: str) -> Dict[str, Any]:
    """Validate a single JSON capture file on disk."""
    try:
        size = os.path.getsize(file_path)
    except OSError as exc:
        return {"ok": False, "errors": [f"Unable to stat {file_path}: {exc}"], "warnings": [], "words_count": 0, "payload_bytes": 0}
    if size > MAX_PAYLOAD_BYTES:
        return {
            "ok": False,
            "errors": [f"File exceeds 250 KB limit ({size:,} > {MAX_PAYLOAD_BYTES:,} bytes)."],
            "warnings": [],
            "words_count": 0,
            "payload_bytes": size,
        }
    try:
        with open(file_path, "rb") as fh:
            raw_bytes = fh.read(MAX_PAYLOAD_BYTES + 1)
        if b"\x00" in raw_bytes:
            return {"ok": False, "errors": ["Binary/NUL byte detected in capture file."], "warnings": [], "words_count": 0, "payload_bytes": len(raw_bytes)}
        data = json.loads(raw_bytes.decode("utf-8"))
    except Exception as exc:
        return {"ok": False, "errors": [f"Invalid UTF-8 JSON: {exc}"], "warnings": [], "words_count": 0, "payload_bytes": size}
    return validate_capture_dict(data, raw_size_bytes=size, strict_keys=True)


def scan_repository(repo_root: str) -> Tuple[bool, Dict[str, Any]]:
    """Audit every file under captures/ and INDEX.json for strict compliance."""
    captures_dir = os.path.join(repo_root, "captures")
    report: Dict[str, Any] = {"files_scanned": 0, "failed": [], "warnings": [], "unexpected_files": []}

    if os.path.isdir(captures_dir):
        for root, _, files in os.walk(captures_dir):
            for fname in sorted(files):
                fpath = os.path.join(root, fname)
                rel = os.path.relpath(fpath, repo_root)
                if os.path.islink(fpath):
                    report["failed"].append({"file": rel, "errors": ["Symlink rejected inside captures/"]})
                    continue
                if not fname.lower().endswith(".json"):
                    report["unexpected_files"].append(rel)
                    report["failed"].append({"file": rel, "errors": ["Non-JSON file rejected inside captures/"]})
                    continue
                report["files_scanned"] += 1
                res = validate_file(fpath)
                if not res["ok"]:
                    report["failed"].append({"file": rel, "errors": res["errors"]})
                if res["warnings"]:
                    report["warnings"].append({"file": rel, "warnings": res["warnings"]})

    index_path = os.path.join(repo_root, "INDEX.json")
    if os.path.isfile(index_path):
        idx_size = os.path.getsize(index_path)
        try:
            with open(index_path, "rb") as idx_fh:
                raw_idx = idx_fh.read()
            idx_text = raw_idx.decode("utf-8")
            idx_errs: List[str] = []
            _check_string_safety(idx_text, "INDEX.json", idx_errs, allow_newlines=True)
            json.loads(idx_text)
            if idx_errs:
                report["failed"].append({"file": "INDEX.json", "errors": idx_errs})
        except Exception as exc:
            report["failed"].append({"file": "INDEX.json", "errors": [f"Invalid INDEX.json ({idx_size} bytes): {exc}"]})

    ok = len(report["failed"]) == 0
    return ok, report


def format_scan_summary_markdown(
    result: Dict[str, Any],
    authorized: bool,
    auth_reason: str,
    disallowed_labels: Optional[Sequence[str]] = None,
) -> str:
    """Format a clear GitHub Issue comment summarizing read-only security validation."""
    ok = bool(result.get("ok")) and not disallowed_labels
    status_badge = "✅ PASS" if ok else "❌ FAILED"
    size_kb = (result.get("payload_bytes") or 0) / 1024.0
    lines = [
        "### 🛡️ SPECTRA Automated Capture Safety Scan (Read-Only)",
        "",
        f"- **Validation Status**: **{status_badge}**",
        f"- **Ingestion Policy**: {'Auto-ingest authorized' if authorized else 'Manual review required — ZERO bytes written to git'} ({auth_reason})",
        f"- **Detected Model**: `{result.get('model_name', 'Unknown')}` (Article `{result.get('article_number') or 'N/A'}`, FW `{result.get('firmware') or 'N/A'}`)",
        f"- **Payload Size**: `{size_kb:.1f} KB` / `250.0 KB` limit",
        f"- **EEPROM Hex Words**: `{result.get('words_count', 0)}` validated 16-bit hex registers",
    ]
    if disallowed_labels:
        lines.append(f"- **Disallowed Labels**: {', '.join(f'`{l}`' for l in disallowed_labels)}")

    if result.get("errors"):
        lines.extend(["", "#### Blocking Errors"])
        for err in result["errors"][:15]:
            lines.append(f"- ❌ {err}")

    if result.get("warnings"):
        lines.extend(["", "#### Offset / Mathematical Audit Warnings"])
        for warn in result["warnings"][:15]:
            lines.append(f"- ⚠️ {warn}")

    if not authorized:
        lines.extend([
            "",
            "---",
            f"📌 **Maintainer Action**: This submission has been tagged `{NEEDS_REVIEW_LABEL}` and **no files were committed to `main`**. "
            f"Add the `{APPROVED_CAPTURE_LABEL}` label once reviewed to ingest this capture automatically.",
        ])
    return "\n".join(lines)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="SPECTRA Captures strict security & schema validator")
    parser.add_argument("--file", help="Validate a single capture JSON file")
    parser.add_argument("--scan-repo", action="store_true", help="Audit all files under captures/ and INDEX.json")
    parser.add_argument("--strict", action="store_true", help="Strict mode (enabled by default)")
    parser.add_argument("--check-labels", help="Comma-separated issue labels to check against allowlist")
    parser.add_argument("--json", action="store_true", help="Emit JSON output")
    args = parser.parse_args(argv)

    if args.check_labels is not None:
        labels = [x.strip() for x in args.check_labels.split(",") if x.strip()]
        ok, bad = validate_issue_labels(labels)
        if args.json:
            print(json.dumps({"ok": ok, "disallowed_labels": bad}, indent=2))
        elif not ok:
            print(f"[-] Disallowed issue labels: {', '.join(bad)}", file=sys.stderr)
        else:
            print("[+] All issue labels are on the allowlist.")
        return 0 if ok else 1

    if args.file:
        res = validate_file(args.file)
        if args.json:
            print(json.dumps(res, indent=2))
        else:
            if res["ok"]:
                print(f"[+] PASS: {args.file} ({res['words_count']} hex words, {res['payload_bytes']} bytes)")
            else:
                print(f"[-] FAIL: {args.file}", file=sys.stderr)
                for e in res["errors"]:
                    print(f"    - {e}", file=sys.stderr)
        return 0 if res["ok"] else 1

    if args.scan_repo:
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        ok, rep = scan_repository(repo_root)
        if args.json:
            print(json.dumps({"ok": ok, **rep}, indent=2))
        else:
            print(f"[*] Scanned {rep['files_scanned']} capture files in {repo_root}")
            for w in rep["warnings"]:
                print(f"[!] Warnings in {w['file']}: {len(w['warnings'])}")
            for f in rep["failed"]:
                print(f"[-] FAILED {f['file']}:", file=sys.stderr)
                for e in f["errors"]:
                    print(f"    - {e}", file=sys.stderr)
        return 0 if ok else 1

    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
