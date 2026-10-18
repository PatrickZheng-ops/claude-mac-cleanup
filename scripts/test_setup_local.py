"""Synthetic path declarations only; never use real Claude or Chrome stores."""
import contextlib
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest

import setup_local as s


class SetupTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="cleanup-setup-synthetic-")
        # macOS temporary-directory aliases are normalized by the fixture owner.
        self.base = Path(self.tmp.name).resolve()
        self.project = self.directory("work")
        self.audit = self.directory("audit")
        self.chrome = self.directory("synthetic-browser")
        self.shared = self.directory("shared-tools")
        self.config_dir = self.directory("private-config")
        self.output = self.config_dir / "local.json"

    def tearDown(self):
        self.tmp.cleanup()

    def directory(self, relative):
        p = self.base / relative
        p.mkdir(mode=0o700, parents=True)
        return p

    def config(self, **changes):
        data = {"schema_version": 1, "kind": "claude_mac_cleanup_local_config",
                "mode": "audit", "protected_roots": [str(self.project)],
                "no_protected_roots": False, "audit_base": str(self.audit),
                "chrome_user_data_dirs": [str(self.chrome)],
                "shared_paths": [str(self.shared)]}
        data.update(changes)
        return data

    def write_raw(self, data=None, raw=None):
        self.output.write_text(raw if raw is not None else json.dumps(data), encoding="utf-8")
        self.output.chmod(0o600)

    def run_cli(self, argv):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            result = s.main(argv)
        return result, stdout.getvalue(), stderr.getvalue()

    def test_private_creation_and_revalidation(self):
        s.write_new(self.output, self.config())
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o600)
        self.assertEqual(s.read_config(self.output), self.config())
        self.assertEqual(s.summary(self.config(), "checked")["deletion_authorized"], False)

    def test_cli_only_emits_status_counts(self):
        status, stdout, stderr = self.run_cli([
            "init", "--protected-root", str(self.project), "--audit-base", str(self.audit),
            "--chrome-user-data-dir", str(self.chrome), "--shared-path", str(self.shared),
            "--out", str(self.output)])
        self.assertEqual(status, 0, stderr)
        self.assertNotIn(str(self.base), stdout + stderr)
        self.assertEqual(json.loads(stdout)["protected_root_count"], 1)
        self.assertEqual(self.run_cli(["check", "--config", str(self.output)])[0], 0)

    def test_explicit_no_protection_is_not_authorization(self):
        status, stdout, _ = self.run_cli([
            "init", "--no-protected-roots", "--audit-base", str(self.audit),
            "--out", str(self.output)])
        self.assertEqual(status, 0)
        data = s.read_config(self.output)
        self.assertTrue(data["no_protected_roots"])
        self.assertEqual(data["protected_roots"], [])
        self.assertFalse(json.loads(stdout)["deletion_authorized"])

    def test_empty_protection_requires_explicit_flag(self):
        for data in (self.config(protected_roots=[]), self.config(no_protected_roots=True)):
            with self.assertRaises(s.SetupError):
                s.validate_config(data)

    def test_cli_protection_flags_mutually_exclusive(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
            s.main(["init", "--protected-root", str(self.project), "--no-protected-roots",
                    "--audit-base", str(self.audit), "--out", str(self.output)])
        self.assertEqual(error.exception.code, 2)
        self.assertFalse(self.output.exists())

    def test_config_has_no_unrecognized_or_authorization_fields(self):
        for data in (self.config(approved=True), self.config(token="synthetic-secret"),
                     self.config(mode="uninstall"), self.config(schema_version=True),
                     self.config(no_protected_roots=0)):
            with self.assertRaises(s.SetupError):
                s.validate_config(data)

    def test_missing_source_fails_without_creating_output(self):
        status, stdout, stderr = self.run_cli([
            "init", "--protected-root", str(self.base / "private-missing"),
            "--audit-base", str(self.audit), "--out", str(self.output)])
        self.assertEqual(status, 1)
        self.assertEqual(stdout, "")
        self.assertNotIn("private-missing", stderr)
        self.assertFalse(self.output.exists())

    def test_source_must_be_directory(self):
        file = self.base / "source-file"
        file.write_text("synthetic")
        for field in ("protected_roots", "chrome_user_data_dirs", "shared_paths"):
            with self.assertRaises((OSError, s.SetupError)):
                s.validate_config(self.config(**{field: [str(file)]}))

    def test_symlink_source_and_intermediate_component_rejected(self):
        link = self.base / "link"
        link.symlink_to(self.project, target_is_directory=True)
        child = self.project / "child"
        child.mkdir()
        for path in (link, link / "child"):
            with self.assertRaises((OSError, s.SetupError)):
                s.validate_config(self.config(protected_roots=[str(path)]))

    def test_relative_and_parent_traversal_rejected(self):
        for path in ("relative", str(self.project / ".." / "work"), "~/work"):
            with self.assertRaises(s.SetupError):
                s.validate_config(self.config(protected_roots=[path]))

    def test_audit_overlap_all_source_categories_both_directions(self):
        child = self.directory("work/child")
        for field in ("protected_roots", "chrome_user_data_dirs", "shared_paths"):
            for source, audit in ((self.project, child), (child, self.project),
                                  (self.project, self.project)):
                with self.assertRaises(s.SetupError):
                    s.validate_config(self.config(**{field: [str(source)], "audit_base": str(audit)}))

    def test_duplicate_roots_rejected(self):
        for field in ("protected_roots", "chrome_user_data_dirs", "shared_paths"):
            with self.assertRaises(s.SetupError):
                s.validate_config(self.config(**{field: [str(self.project), str(self.project)]}))

    def test_nested_protection_and_shared_roots_are_valid(self):
        child = self.directory("work/shared-subfolder")
        self.assertEqual(s.validate_config(self.config(shared_paths=[str(child)]))["mode"], "audit")

    def test_no_overwrite(self):
        s.write_new(self.output, self.config())
        original = self.output.read_bytes()
        with self.assertRaises(OSError):
            s.write_new(self.output, self.config())
        self.assertEqual(self.output.read_bytes(), original)

    def test_output_must_not_be_in_source(self):
        for source in (self.project, self.chrome, self.shared):
            with self.assertRaises(s.SetupError):
                s.write_new(source / "local.json", self.config())
            self.assertFalse((source / "local.json").exists())

    def test_output_parent_must_exist(self):
        with self.assertRaises(OSError):
            s.write_new(self.base / "missing-parent" / "local.json", self.config())

    def test_output_symlink_parent_and_target_rejected(self):
        linked_dir = self.base / "linked-config"
        linked_dir.symlink_to(self.config_dir, target_is_directory=True)
        with self.assertRaises(OSError):
            s.write_new(linked_dir / "local.json", self.config())
        target = self.config_dir / "existing.json"
        target.write_text("untouched")
        self.output.symlink_to(target)
        with self.assertRaises(OSError):
            s.write_new(self.output, self.config())
        self.assertEqual(target.read_text(), "untouched")

    def test_shared_writable_parent_rejected(self):
        self.config_dir.chmod(0o777)
        with self.assertRaises(s.SetupError):
            s.write_new(self.output, self.config())

    def test_check_rejects_public_mode(self):
        self.write_raw(self.config())
        self.output.chmod(0o644)
        with self.assertRaises(s.SetupError):
            s.read_config(self.output)

    def test_check_rejects_symlink_and_hardlink(self):
        self.write_raw(self.config())
        linked = self.config_dir / "linked.json"
        linked.symlink_to(self.output)
        with self.assertRaises(OSError):
            s.read_config(linked)
        os.link(self.output, self.config_dir / "hardlink.json")
        with self.assertRaises(s.SetupError):
            s.read_config(self.output)

    def test_check_rejects_fifo_without_blocking(self):
        os.mkfifo(self.output, 0o600)
        with self.assertRaises(s.SetupError):
            s.read_config(self.output)

    def test_duplicate_json_keys_rejected(self):
        raw = json.dumps(self.config())[:-1] + ', "mode": "audit"}'
        self.write_raw(raw=raw)
        with self.assertRaises(s.SetupError):
            s.read_config(self.output)

    def test_check_detects_source_removed_after_declaration(self):
        s.write_new(self.output, self.config())
        self.chrome.rmdir()
        with self.assertRaises(OSError):
            s.read_config(self.output)

    def test_oversized_config_rejected(self):
        self.write_raw(raw=" " * (s.MAX_CONFIG_BYTES + 1))
        with self.assertRaises(s.SetupError):
            s.read_config(self.output)

    def test_check_rejects_config_relocated_inside_source(self):
        self.write_raw(self.config())
        moved = self.project / "local.json"
        self.output.rename(moved)
        with self.assertRaises(s.SetupError):
            s.read_config(moved)

    def test_invalid_cli_argument_does_not_echo_private_value(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit):
            s.main(["check", "--config", str(self.output), "--secret-private-value"])
        self.assertNotIn("secret-private-value", stderr.getvalue())
        self.assertNotIn(str(self.output), stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
