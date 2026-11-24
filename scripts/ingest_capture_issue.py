#!/usr/bin/env python3
"""
SPECTRA Community Capture Issue Extractor, Validator & Ingestor
===============================================================
Parses GitHub Issue bodies submitted by SPECTRA (`[Capture]` and
`[Offset Fix + Capture]`, including size-bounded Gist fallbacks), enforces strict
hex-only EEPROM, <= 250 KB size, label allowlist, and XSS/secret checks via
`validate_payload.py`.

Supports `--validate-only` for non-allowlisted contributors so read-only safety
validation runs and writes ZERO bytes to disk/git.
"""

import argparse
import json
import os
import re
import sys
import urllib.parse
import urllib.request
from typing import Any, Dict, Optional, Tuple

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

import validate_payload as vp

MAX_PAYLOAD_BYTES = vp.MAX_PAYLOAD_BYTES


def _read_bounded_response(resp, limit: int = MAX_PAYLOAD_BYTES) -> bytes:
    raw = resp.read(limit + 1)
    if len(raw) > limit:
        raise ValueError(f"Remote payload exceeds 250 KB hard limit (> {limit:,} bytes).")
    return raw


def _fetch_gist_capture(issue_body: str) -> Tuple[Optional[Dict[str, Any]], int]:
    """If the capture exceeded 65KB and was uploaded to a GitHub Gist, fetch its JSON safely (<= 250 KB)."""
    m = re.search(r"https://gist\.github\.com/(?:[A-Za-z0-9_.-]+/)?([0-9a-fA-F]{16,40})", issue_body)
    if not m:
        return None, 0
    gist_id = m.group(1)
    api_url = f"https://api.github.com/gists/{gist_id}"
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "SPECTRA-Captures-Bot",
    }
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(api_url, headers=headers)
    with urllib.request.urlopen(req, timeout=20) as resp:
        gist_raw = _read_bounded_response(resp, limit=MAX_PAYLOAD_BYTES * 2)
    gist_data = json.loads(gist_raw.decode("utf-8"))
    files = gist_data.get("files") or {}
    for _fname, meta in files.items():
        if not isinstance(meta, dict):
            continue
        fsize = meta.get("size")
        if isinstance(fsize, int) and fsize > MAX_PAYLOAD_BYTES:
            raise ValueError(f"Gist capture file exceeds 250 KB limit ({fsize:,} bytes).")
        content = meta.get("content")
        if meta.get("truncated") and meta.get("raw_url"):
            parsed_url = urllib.parse.urlparse(str(meta["raw_url"]))
            if parsed_url.scheme != "https" or parsed_url.hostname != "gist.githubusercontent.com":
                raise ValueError(f"Rejected non-GitHub Gist raw URL host: {parsed_url.hostname!r}")
            raw_req = urllib.request.Request(meta["raw_url"], headers={"User-Agent": "SPECTRA-Captures-Bot"})
            with urllib.request.urlopen(raw_req, timeout=20) as raw_resp:
                raw_bytes = _read_bounded_response(raw_resp, limit=MAX_PAYLOAD_BYTES)
            content = raw_bytes.decode("utf-8")
        if isinstance(content, str) and content:
            raw_len = len(content.encode("utf-8"))
            if raw_len > MAX_PAYLOAD_BYTES:
                raise ValueError(f"Gist capture content exceeds 250 KB limit ({raw_len:,} bytes).")
            try:
                obj = json.loads(content)
                if isinstance(obj, dict) and ("eeprom_words" in obj or "identity" in obj):
                    return obj, raw_len
            except Exception:
                continue
    return None, 0


def extract_capture_payload(issue_body: str) -> Tuple[Optional[Dict[str, Any]], int]:
    """Extract capture JSON bundle from an issue body or linked Gist, enforcing <= 250 KB size."""
    body_bytes = len((issue_body or "").encode("utf-8"))
    if body_bytes > MAX_PAYLOAD_BYTES:
        raise ValueError(f"Issue body exceeds 250 KB limit ({body_bytes:,} > {MAX_PAYLOAD_BYTES:,} bytes).")

    candidates = []
    patch_meta: Dict[str, Any] = {}

    for m in re.finditer(r"```(?:json)?\s*(\{.*?\})\s*```", issue_body, re.DOTALL):
        raw_json = m.group(1).strip()
        raw_len = len(raw_json.encode("utf-8"))
        if raw_len > MAX_PAYLOAD_BYTES:
            raise ValueError(f"Embedded JSON block exceeds 250 KB limit ({raw_len:,} bytes).")
        try:
            obj = json.loads(raw_json)
        except Exception:
            continue
        if not isinstance(obj, dict):
            continue
        if obj.get("schema") == "spectra.offset_patch.v1":
            patch_meta = obj
            continue
        if "eeprom_words" in obj or ("identity" in obj and "gateways" in obj):
            candidates.append((obj, raw_len))

    if candidates:
        data, raw_size = candidates[-1]
    else:
        data, raw_size = _fetch_gist_capture(issue_body)

    if not isinstance(data, dict):
        return None, body_bytes

    # Normalize required top-level schema keys expected by scripts/index_captures.py
    if not isinstance(data.get("metadata"), dict):
        ts_match = re.search(r"\*\*Timestamp\*\*:\s*([^\n]+)", issue_body)
        build_match = re.search(r"\*\*Build\*\*:\s*([^\n]+)", issue_body)
        ts_val = str(patch_meta.get("timestamp") or (ts_match.group(1).strip() if ts_match else "")).strip()
        build_val = str(patch_meta.get("build") or (build_match.group(1).strip() if build_match else "")).strip()
        data["metadata"] = {
            "timestamp": ts_val,
            "spectra_build": build_val,
            "probe_version": f"Build {build_val}" if build_val else "SPECTRA",
        }
    else:
        meta = data["metadata"]
        if not meta.get("timestamp") and patch_meta.get("timestamp"):
            meta["timestamp"] = str(patch_meta["timestamp"]).strip()

    if not isinstance(data.get("identity"), dict):
        data["identity"] = dict(patch_meta.get("identity") or {})
    if not isinstance(data.get("gateways"), dict):
        data["gateways"] = {}
    if not isinstance(data.get("eeprom_words"), dict):
        data["eeprom_words"] = {}

    # Preserve offset patch metadata inside the capture if present and not already attached
    if patch_meta and "ai_offset_fix" not in data and isinstance(patch_meta.get("override"), dict):
        data["ai_offset_fix"] = patch_meta["override"]

    return data, max(raw_size, body_bytes)


def _write_gh_output(key: str, value: str) -> None:
    gh_out_path = os.environ.get("GITHUB_OUTPUT")
    if not gh_out_path:
        return
    txt = str(value)
    if "\n" in txt or "\r" in txt:
        delimiter = f"SPECTRA_EOF_{os.getpid()}"
        while delimiter in txt:
            delimiter += "_X"
        with open(gh_out_path, "a", encoding="utf-8") as gh_out:
            gh_out.write(f"{key}<<{delimiter}\n{txt}\n{delimiter}\n")
    else:
        with open(gh_out_path, "a", encoding="utf-8") as gh_out:
            gh_out.write(f"{key}={txt.strip()}\n")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Validate and optionally ingest a SPECTRA capture issue.")
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="Run strict read-only safety validation and emit scan summary without writing any repository files.",
    )
    args = parser.parse_args(argv)

    issue_body = os.environ.get("ISSUE_BODY", "")
    issue_labels_raw = os.environ.get("ISSUE_LABELS", "")
    issue_labels = [l.strip() for l in issue_labels_raw.split(",") if l.strip()]
    author_login = os.environ.get("ISSUE_AUTHOR", "")
    author_assoc = os.environ.get("ISSUE_AUTHOR_ASSOCIATION", "")
    event_action = os.environ.get("EVENT_ACTION", "opened")
    label_added = os.environ.get("EVENT_LABEL_NAME", "")
    actor_login = os.environ.get("EVENT_ACTOR", "")
    actor_is_collab = os.environ.get("ACTOR_IS_COLLABORATOR", "false").lower() == "true"

    labels_ok, disallowed_labels = vp.validate_issue_labels(issue_labels)
    authorized, auth_reason = vp.is_auto_ingest_authorized(
        author_login=author_login,
        author_association=author_assoc,
        issue_labels=issue_labels,
        event_action=event_action,
        label_added=label_added,
        actor_login=actor_login,
        actor_is_collaborator=actor_is_collab,
    )

    try:
        data, raw_size = extract_capture_payload(issue_body)
    except Exception as exc:
        val_res = {
            "ok": False,
            "errors": [str(exc)],
            "warnings": [],
            "words_count": 0,
            "payload_bytes": len(issue_body.encode("utf-8")),
            "model_name": "Unknown",
            "article_number": "",
            "firmware": "",
        }
        data = None
    else:
        if data is None:
            val_res = {
                "ok": False,
                "errors": ["No valid capture JSON payload found in issue body or linked GitHub Gist."],
                "warnings": [],
                "words_count": 0,
                "payload_bytes": raw_size,
                "model_name": "Unknown",
                "article_number": "",
                "firmware": "",
            }
        else:
            val_res = vp.validate_capture_dict(data, raw_size_bytes=raw_size, strict_keys=True)

    overall_ok = bool(val_res["ok"]) and labels_ok
    summary_md = vp.format_scan_summary_markdown(
        val_res,
        authorized=authorized,
        auth_reason=auth_reason,
        disallowed_labels=disallowed_labels if not labels_ok else None,
    )

    _write_gh_output("validation_ok", "true" if overall_ok else "false")
    _write_gh_output("authorized", "true" if authorized else "false")
    _write_gh_output("should_ingest", "true" if (overall_ok and authorized) else "false")
    _write_gh_output("auth_reason", auth_reason)
    _write_gh_output("model_name", val_res.get("model_name") or "Unknown")
    _write_gh_output("article", val_res.get("article_number") or "unknown")
    _write_gh_output("words_count", str(val_res.get("words_count", 0)))
    _write_gh_output("payload_bytes", str(val_res.get("payload_bytes", 0)))
    _write_gh_output("summary_md", summary_md)

    print(summary_md)

    if args.validate_only:
        # Read-only mode: NEVER touch the filesystem or git; return 0 so workflow posts summary cleanly
        return 0

    if not overall_ok or data is None:
        print("[-] Refusing to ingest capture: strict validation failed.", file=sys.stderr)
        return 1

    if not authorized:
        print(f"[-] Refusing to ingest capture: {auth_reason}", file=sys.stderr)
        return 1

    repo_root = os.path.realpath(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    captures_root = os.path.realpath(os.path.join(repo_root, "captures"))

    ident = data.get("identity") or {}
    raw_mfg = str(ident.get("manufacturer") or "Jura").strip() or "Jura"
    mfg = re.sub(r"[^A-Za-z0-9_-]", "_", raw_mfg).strip("_") or "Jura"

    model = str(ident.get("model_name") or "Unknown").strip() or "Unknown"
    raw_article = str(ident.get("article_number") or "").strip()
    article = re.sub(r"[^A-Za-z0-9_-]", "_", raw_article).strip("_") or "unknown"
    clean_model = re.sub(r"[^A-Za-z0-9_]", "_", model).strip("_") or "Unknown"

    ts = str((data.get("metadata") or {}).get("timestamp") or "")
    clean_ts = re.sub(r"[^0-9]", "", ts)[:14] or "unknown"

    rel_dir = os.path.join("captures", mfg, clean_model)
    out_dir = os.path.realpath(os.path.join(repo_root, rel_dir))
    if os.path.commonpath([captures_root, out_dir]) != captures_root:
        print("[-] Refusing to write capture outside captures/ directory.", file=sys.stderr)
        return 1
    os.makedirs(out_dir, exist_ok=True)

    filename = f"spectra_capture_{article}_{clean_ts}.json"
    rel_dest = os.path.join(rel_dir, filename)
    abs_dest = os.path.realpath(os.path.join(out_dir, filename))
    if os.path.commonpath([captures_root, abs_dest]) != captures_root:
        print("[-] Refusing path traversal target.", file=sys.stderr)
        return 1

    serialized = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    if len(serialized.encode("utf-8")) > MAX_PAYLOAD_BYTES:
        print("[-] Serialized capture exceeds 250 KB limit.", file=sys.stderr)
        return 1

    with open(abs_dest, "w", encoding="utf-8") as f:
        f.write(serialized)

    print(f"[+] Successfully ingested capture to: {rel_dest}")
    _write_gh_output("dest_path", rel_dest)
    return 0


if __name__ == "__main__":
    sys.exit(main())
