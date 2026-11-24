#!/usr/bin/env python3
"""
SPECTRA Community Capture Catalog & Strict Validation Indexer
Scans captures/ directory, enforces strict hex-only EEPROM, <= 250 KB size,
XSS/secret/poisoning validation via validate_payload.py, and compiles INDEX.json.
"""

import argparse
import glob
import json
import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

import validate_payload as vp

REPO_ROOT = os.path.dirname(SCRIPT_DIR)
CAPTURES_DIR = os.path.join(REPO_ROOT, "captures")
INDEX_PATH = os.path.join(REPO_ROOT, "INDEX.json")


def validate_and_index(check_only: bool = False) -> int:
    captures = []
    errors = []

    # Reject any unexpected non-JSON files or symlinks inside captures/
    if os.path.isdir(CAPTURES_DIR):
        for root, _, files in os.walk(CAPTURES_DIR):
            for fname in sorted(files):
                fpath = os.path.join(root, fname)
                rel = os.path.relpath(fpath, REPO_ROOT)
                if os.path.islink(fpath):
                    errors.append((rel, "Symlink rejected inside captures/"))
                elif not fname.lower().endswith(".json"):
                    errors.append((rel, "Non-JSON file rejected inside captures/"))

    pattern = os.path.join(CAPTURES_DIR, "**", "*.json")
    for file_path in sorted(glob.glob(pattern, recursive=True)):
        rel_path = os.path.relpath(file_path, REPO_ROOT)
        try:
            res = vp.validate_file(file_path)
            if not res["ok"]:
                raise ValueError("; ".join(res["errors"]))

            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            ident = data.get("identity", {})
            gateways = data.get("gateways", {})
            meta = data.get("metadata", {})
            eep = data.get("eeprom_words", {})

            entry = {
                "file": rel_path,
                "model_name": ident.get("model_name") or "Unknown",
                "article_number": str(ident.get("article_number") or ""),
                "serial_number": str(ident.get("serial_number") or ""),
                "production_date": str(ident.get("production_date") or ""),
                "firmware": gateways.get("TY:", "").replace("ty:", "").strip(),
                "bootloader": gateways.get("TL:", "").replace("tl:", "").strip(),
                "ic_code": gateways.get("IC:", "").replace("ic:", "").strip(),
                "words_count": len(eep),
                "timestamp": meta.get("timestamp", ""),
                "probe_version": meta.get("probe_version", ""),
                "has_ground_truth": bool(data.get("joe_ground_truth", {}).get("raw_lines")),
            }
            captures.append(entry)
            print(f"[+] Validated: {rel_path} ({entry['model_name']} - Article {entry['article_number']}, {len(eep)} hex words)")
        except Exception as e:
            errors.append((rel_path, str(e)))
            print(f"[-] ERROR validating {rel_path}: {e}", file=sys.stderr)

    index_data = {
        "catalog_version": "1.0",
        "total_captures": len(captures),
        "captures": captures,
    }

    if not check_only:
        with open(INDEX_PATH, "w", encoding="utf-8") as f:
            json.dump(index_data, f, indent=2, ensure_ascii=False)
            f.write("\n")
        print(f"\n[+] Wrote {len(captures)} captures to {INDEX_PATH}")
    else:
        existing = json.load(open(INDEX_PATH, "r", encoding="utf-8")) if os.path.isfile(INDEX_PATH) else None
        if existing != index_data:
            errors.append(("INDEX.json", "INDEX.json is out of date; run scripts/index_captures.py"))

    if errors:
        print(f"\n[-] Encountered {len(errors)} errors during indexing!", file=sys.stderr)
        return 1
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate captures and rebuild INDEX.json")
    parser.add_argument("--check", action="store_true", help="Verify captures and INDEX.json without writing")
    args = parser.parse_args()
    return validate_and_index(check_only=args.check)


if __name__ == "__main__":
    sys.exit(main())
