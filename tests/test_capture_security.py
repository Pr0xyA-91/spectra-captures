#!/usr/bin/env python3
"""Unit tests for spectra-captures Option A policy, strict hex EEPROM validation, and payload poisoning checks."""

import json
import os
import sys
import tempfile
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS_DIR = os.path.join(REPO_ROOT, "scripts")
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)

import validate_payload as vp
import ingest_capture_issue as ingest


def _minimal_valid_capture() -> dict:
    return {
        "metadata": {"timestamp": "2026-11-24T10:00:00", "spectra_build": "20261124.1000", "probe_version": "1.1.0"},
        "identity": {"model_name": "ENA 8 (EA)", "article_number": "15339", "address_width": 4, "max_words": 512},
        "gateways": {"TY:": "ty:EF1012M V01.02", "TL:": "tl:BL_RL78 V01.30"},
        "eeprom_words": {"0x0000": 1090, "0x0001": 103, "0x0008": "0x0027"},
    }


class TestSpectraCapturesSecurity(unittest.TestCase):
    def test_existing_repository_captures_pass_strict_audit(self):
        ok, report = vp.scan_repository(REPO_ROOT)
        self.assertTrue(ok, report)
        self.assertGreaterEqual(report["files_scanned"], 2)

    def test_option_a_allowlist_policy(self):
        # Allowlisted users
        ok, _ = vp.is_auto_ingest_authorized("Pr0xyA-91", "NONE", ["capture"])
        self.assertTrue(ok)
        ok, _ = vp.is_auto_ingest_authorized("neon-rat", "NONE", ["capture"])
        self.assertTrue(ok)
        # OWNER / COLLABORATOR
        ok, _ = vp.is_auto_ingest_authorized("someone", "OWNER", ["capture"])
        self.assertTrue(ok)
        ok, _ = vp.is_auto_ingest_authorized("someone", "COLLABORATOR", ["capture"])
        self.assertTrue(ok)
        # External user blocked without approved-capture
        ok, _ = vp.is_auto_ingest_authorized("random-user", "NONE", ["capture"])
        self.assertFalse(ok)
        # External user cannot self-approve
        ok, _ = vp.is_auto_ingest_authorized("random-user", "NONE", ["capture", "approved-capture"], event_action="opened", actor_login="random-user", actor_is_collaborator=False)
        self.assertFalse(ok)
        # Maintainer adding approved-capture unlocks ingestion
        ok, _ = vp.is_auto_ingest_authorized(
            "random-user", "NONE", ["capture", "approved-capture"],
            event_action="labeled", label_added="approved-capture",
            actor_login="Pr0xyA-91", actor_is_collaborator=True,
        )
        self.assertTrue(ok)

    def test_strict_hex_only_eeprom_validation(self):
        valid = _minimal_valid_capture()
        res = vp.validate_capture_dict(valid)
        self.assertTrue(res["ok"], res)

        # Reject non-hex key
        bad_key = _minimal_valid_capture()
        bad_key["eeprom_words"]["not_hex"] = 42
        res = vp.validate_capture_dict(bad_key)
        self.assertFalse(res["ok"])

        # Reject bool value
        bad_bool = _minimal_valid_capture()
        bad_bool["eeprom_words"]["0x0002"] = True
        self.assertFalse(vp.validate_capture_dict(bad_bool)["ok"])

        # Reject out-of-range value
        bad_range = _minimal_valid_capture()
        bad_range["eeprom_words"]["0x0002"] = 0x10000
        self.assertFalse(vp.validate_capture_dict(bad_range)["ok"])

        # Reject string payload in EEPROM value
        bad_str = _minimal_valid_capture()
        bad_str["eeprom_words"]["0x0002"] = "alert(1)"
        self.assertFalse(vp.validate_capture_dict(bad_str)["ok"])

    def test_size_limit_250kb_enforced(self):
        big = _minimal_valid_capture()
        res = vp.validate_capture_dict(big, raw_size_bytes=vp.MAX_PAYLOAD_BYTES + 1)
        self.assertFalse(res["ok"])
        self.assertTrue(any("250 KB" in e for e in res["errors"]))

    def test_label_allowlist(self):
        ok, bad = vp.validate_issue_labels(["capture", "approved-capture", "needs-review"])
        self.assertTrue(ok)
        self.assertEqual(bad, [])
        ok, bad = vp.validate_issue_labels(["capture", "evil-custom-label"])
        self.assertFalse(ok)
        self.assertEqual(bad, ["evil-custom-label"])

    def test_xss_secret_and_mock_snippet_poisoning_rejected(self):
        xss = _minimal_valid_capture()
        xss["identity"]["model_name"] = "<script>alert(1)</script>"
        self.assertFalse(vp.validate_capture_dict(xss)["ok"])

        gha = _minimal_valid_capture()
        gha["identity"]["model_name"] = "${{ secrets.GITHUB_TOKEN }}"
        self.assertFalse(vp.validate_capture_dict(gha)["ok"])

        pat = _minimal_valid_capture()
        pat["metadata"]["notes"] = "token ghp_1234567890abcdef1234567890abcdef1234"
        self.assertFalse(vp.validate_capture_dict(pat)["ok"])

        poison_snip = _minimal_valid_capture()
        poison_snip["mock_python_snippet"] = "import os\nos.system('id')\n"
        self.assertFalse(vp.validate_capture_dict(poison_snip)["ok"])

    def test_validate_only_writes_zero_files_for_external_user(self):
        cap = _minimal_valid_capture()
        issue_body = f"```json\n{json.dumps(cap)}\n```\n"
        with tempfile.NamedTemporaryFile("w+", delete=False) as gh_out:
            gh_out_path = gh_out.name
        try:
            env_backup = dict(os.environ)
            os.environ.update({
                "ISSUE_BODY": issue_body,
                "ISSUE_AUTHOR": "external-contributor",
                "ISSUE_AUTHOR_ASSOCIATION": "NONE",
                "ISSUE_LABELS": "capture",
                "EVENT_ACTION": "opened",
                "EVENT_ACTOR": "external-contributor",
                "ACTOR_IS_COLLABORATOR": "false",
                "GITHUB_OUTPUT": gh_out_path,
            })
            before_files = set(os.listdir(os.path.join(REPO_ROOT, "captures", "Jura")))
            rc = ingest.main(["--validate-only"])
            after_files = set(os.listdir(os.path.join(REPO_ROOT, "captures", "Jura")))
            self.assertEqual(rc, 0)
            self.assertEqual(before_files, after_files)
            with open(gh_out_path, "r", encoding="utf-8") as fh:
                out_txt = fh.read()
            self.assertIn("validation_ok=true", out_txt)
            self.assertIn("authorized=false", out_txt)
            self.assertIn("should_ingest=false", out_txt)
            self.assertIn("needs-review", out_txt)
        finally:
            os.environ.clear()
            os.environ.update(env_backup)
            if os.path.exists(gh_out_path):
                os.remove(gh_out_path)


if __name__ == "__main__":
    unittest.main()
