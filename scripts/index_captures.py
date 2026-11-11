#!/usr/bin/env python3
"""
SPECTRA Community Capture Catalog & Validation Indexer
Scans captures/ directory, validates schema, and compiles INDEX.json & README tables.
"""

import os
import glob
import json
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CAPTURES_DIR = os.path.join(REPO_ROOT, "captures")
INDEX_PATH = os.path.join(REPO_ROOT, "INDEX.json")


def validate_and_index():
    captures = []
    errors = []

    pattern = os.path.join(CAPTURES_DIR, "**", "*.json")
    for file_path in sorted(glob.glob(pattern, recursive=True)):
        rel_path = os.path.relpath(file_path, REPO_ROOT)
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            # Basic schema check
            for required in ("metadata", "identity", "gateways", "eeprom_words"):
                if required not in data:
                    raise ValueError(f"Missing required root key: '{required}'")

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
                "has_ground_truth": bool(data.get("joe_ground_truth", {}).get("raw_lines"))
            }
            captures.append(entry)
            print(f"[+] Validated: {rel_path} ({entry['model_name']} - Article {entry['article_number']})")
        except Exception as e:
            errors.append((rel_path, str(e)))
            print(f"[-] ERROR validating {rel_path}: {e}", file=sys.stderr)

    index_data = {
        "catalog_version": "1.0",
        "total_captures": len(captures),
        "captures": captures
    }

    with open(INDEX_PATH, "w", encoding="utf-8") as f:
        json.dump(index_data, f, indent=2, ensure_ascii=False)
    print(f"\n[+] Wrote {len(captures)} captures to {INDEX_PATH}")

    if errors:
        print(f"\n[-] Encountered {len(errors)} errors during indexing!", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    validate_and_index()
