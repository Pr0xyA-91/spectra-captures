#!/usr/bin/env python3
"""
SPECTRA Community Capture Issue Extractor & Ingestor
Parses GitHub Issue bodies submitted by SPECTRA (both `[Capture]` and
`[Offset Fix + Capture]`, including Gist fallbacks), normalizes required
schema fields, writes the capture JSON under `captures/<mfg>/<model>/`,
and exports step outputs for GitHub Actions.
"""

import json
import os
import re
import sys
import urllib.request


def _fetch_gist_capture(issue_body: str):
    """If the capture exceeded 65KB and was uploaded to a GitHub Gist, fetch its JSON content."""
    m = re.search(r"https://gist\.github\.com/(?:[^/\s)]+/)?([0-9a-fA-F]{16,40})", issue_body)
    if not m:
        return None
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
        gist_data = json.loads(resp.read().decode("utf-8"))
    files = gist_data.get("files") or {}
    for fname, meta in files.items():
        if not isinstance(meta, dict):
            continue
        content = meta.get("content")
        if meta.get("truncated") and meta.get("raw_url"):
            raw_req = urllib.request.Request(meta["raw_url"], headers={"User-Agent": "SPECTRA-Captures-Bot"})
            with urllib.request.urlopen(raw_req, timeout=20) as raw_resp:
                content = raw_resp.read().decode("utf-8")
        if content:
            try:
                obj = json.loads(content)
                if isinstance(obj, dict) and ("eeprom_words" in obj or "identity" in obj):
                    return obj
            except Exception:
                continue
    return None


def extract_capture_payload(issue_body: str):
    """Extract the capture JSON bundle from an issue body (skipping spectra.offset_patch.v1 blocks)."""
    candidates = []
    patch_meta = {}

    for m in re.finditer(r"```(?:json)?\s*(\{.*?\})\s*```", issue_body, re.DOTALL):
        raw_json = m.group(1).strip()
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
            candidates.append(obj)

    data = candidates[-1] if candidates else _fetch_gist_capture(issue_body)
    if not isinstance(data, dict):
        return None

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

    return data


def _write_gh_output(key: str, value: str):
    gh_out_path = os.environ.get("GITHUB_OUTPUT")
    if not gh_out_path:
        return
    clean_val = str(value).replace("\r", " ").replace("\n", " ").strip()
    with open(gh_out_path, "a", encoding="utf-8") as gh_out:
        gh_out.write(f"{key}={clean_val}\n")


def main() -> int:
    issue_body = os.environ.get("ISSUE_BODY", "")
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    data = extract_capture_payload(issue_body)
    if data is None:
        print("[-] Error: No valid capture JSON payload found in issue body or linked Gist.", file=sys.stderr)
        return 1

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
    out_dir = os.path.join(repo_root, rel_dir)
    os.makedirs(out_dir, exist_ok=True)

    filename = f"spectra_capture_{article}_{clean_ts}.json"
    rel_dest = os.path.join(rel_dir, filename)
    abs_dest = os.path.join(repo_root, rel_dest)

    with open(abs_dest, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")

    print(f"[+] Successfully ingested capture to: {rel_dest}")
    _write_gh_output("dest_path", rel_dest)
    _write_gh_output("model_name", model)
    _write_gh_output("article", article)
    return 0


if __name__ == "__main__":
    sys.exit(main())
