"""Synthetic-only tests: every source is inside a new temporary directory."""
import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
import code_tools as tool


class CodeToolsTests(unittest.TestCase):
    def setUp(self):
        independent = self._testMethodName.startswith(('test_auth_', 'test_endpoint_')) or self._testMethodName == 'test_duplicate_vendor_provenance_refused'
        if not independent and tool.dependency.inspect_installation()['status'] == 'absent':
            self.skipTest('Optional upstream dependency absent; not covered by the base suite')
        self.tmp = tempfile.TemporaryDirectory(prefix='claude-cleanup-synthetic-')
        self.base = Path(self.tmp.name).resolve()
        self.source = self.base / 'source'
        self.source.mkdir()
        self.addCleanup(self.tmp.cleanup)

    def write(self, name, data):
        path = self.base / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(data if isinstance(data, str) else json.dumps(data))
        return path

    def policy(self, roots=None, **changes):
        roots = roots or {'work': str(self.source)}
        selected = tool.CORE.parse_roots([k + '=' + v for k, v in roots.items()], allow_missing=True)
        trees = tool.CORE.snapshot(selected, hashed=True)
        rows = [{'root': label, 'path': rel, 'classification': 'work_product'}
                for label, tree in trees.items() for rel, item in tree['entries'].items()
                if item['kind'] == 'file']
        value = {'schema': 1, 'mode': 'uninstall', 'backup_policy': 'work-products',
                 'roots': roots, 'reviewed_files': rows, 'writer_state': 'confirmed_stopped',
                 'authorization_ref': 'synthetic-approval-1', 'retention_note': 'Synthetic fixture only'}
        value.update(changes)
        return value

    def backup(self, name='backup', policy=None):
        path = self.write(name + '-policy.json', policy or self.policy())
        output = self.base / name
        tool.backup(path, output)
        return output

    def test_upstream_import_does_not_pollute_names(self):
        before = {name: sys.modules.get(name) for name in ('review_tools', 'local_state')}
        core, review = tool.load_upstream()
        self.assertEqual(before, {name: sys.modules.get(name) for name in before})
        self.write('source/session-env/12345678-abcd-1234-abcd-123456789abc/file.txt', 'not-read')
        out = self.base / 'audit.json'
        core.audit({'fixture': self.source}, out)
        self.assertEqual(json.loads(out.read_text())['relationships']['group_count'], 1)

    def test_changed_vendor_refused_before_execution(self):
        fixture = self.base / 'vendor/cc-clean/scripts'
        fixture.mkdir(parents=True)
        marker = self.base / 'must-not-execute'
        original_files = json.loads((tool.VENDOR.parent.parent / 'SOURCE.json').read_text())
        (fixture.parent.parent / 'SOURCE.json').write_text(json.dumps(original_files))
        for name in ('local_state.py', 'review_tools.py'):
            shutil.copy2(tool.VENDOR / name, fixture / name)
        (fixture / 'review_tools.py').write_text('from pathlib import Path\nPath(' + repr(str(marker)) + ').touch()\n')
        with patch.object(tool, 'VENDOR', fixture):
            with self.assertRaises(tool.VendorIntegrityError):
                tool.load_upstream()
        self.assertFalse(marker.exists())

    def test_duplicate_vendor_provenance_refused(self):
        fixture = self.base / 'vendor/cc-clean/scripts'
        fixture.mkdir(parents=True)
        (fixture.parent.parent / 'SOURCE.json').write_text('{"files":[],"files":[]}')
        with patch.object(tool, 'VENDOR', fixture):
            with self.assertRaises(tool.VendorIntegrityError):
                tool.load_upstream()

    def test_nested_state_values_and_keys_never_emitted(self):
        state = self.write('source/.claude.json', {'oauthAccount': {'secret': 'TOKEN_FIXTURE'},
               'TOP_PRIVATE_EMAIL': [{'deviceId': 'PRIVATE_DEVICE', 'device_id': None}], 'projects': {}})
        out = self.base / 'audit.json'
        tool.audit(['fixture=' + str(self.source)], out, state)
        text = out.read_text()
        for raw in ('TOKEN_FIXTURE', 'TOP_PRIVATE_EMAIL', 'PRIVATE_DEVICE'):
            self.assertNotIn(raw, text)
        data = json.loads(text)
        self.assertEqual(data['state']['device_id_field_count'], 2)
        self.assertFalse(data['history_content_read'])
        self.assertEqual(stat.S_IMODE(out.stat().st_mode), 0o600)

    def test_duplicate_state_keys_rejected(self):
        state = self.write('source/.claude.json', '{"deviceId":"one","deviceId":"two"}')
        with self.assertRaises(tool.GuardError):
            tool.audit(['fixture=' + str(self.source)], self.base / 'audit.json', state)
        self.assertFalse((self.base / 'audit.json').exists())

    def test_auth_presence_only_and_helper_not_executed(self):
        marker = self.base / 'must-not-exist'
        settings = self.write('settings.json', {'env': {'ANTHROPIC_API_KEY': 'secret-env-token',
            'CLAUDE_CODE_OAUTH_TOKEN': '', 'CLAUDE_CONFIG_DIR': 12},
            'apiKeyHelper': 'touch ' + str(marker)})
        out = self.base / 'auth.json'
        tool.auth(['fixture=' + str(settings)], out, include_process_env=True,
                  environment={'ANTHROPIC_AUTH_TOKEN': 'secret-inherited'})
        text = out.read_text()
        self.assertNotIn('secret-env-token', text)
        self.assertNotIn('secret-inherited', text)
        self.assertNotIn(str(marker), text)
        self.assertFalse(marker.exists())
        data = json.loads(text)
        variables = data['settings'][0]['variables']
        self.assertTrue(variables['CLAUDE_CODE_OAUTH_TOKEN']['empty'])
        self.assertEqual(variables['CLAUDE_CONFIG_DIR']['value_type'], 'number')
        self.assertFalse(data['effective_authentication_verified'])

    def test_endpoint_generic_tld_ipv6_and_redaction(self):
        for url, host in [('https://PRIVATE_USER:PRIVATE_PASS@gateway.example.dev:8443/private?token=SECRET#SECRET', 'gateway.example.dev'),
                          ('http://[::1]:8080/private?x=SECRET', '::1')]:
            row = tool.endpoint(url)
            self.assertEqual(row['host'], host)
            self.assertNotIn('PRIVATE', json.dumps(row))
            self.assertNotIn('SECRET', json.dumps(row))
            self.assertNotIn('private', json.dumps(row))
        self.assertEqual(tool.endpoint('file:///private?secret')['status'], 'invalid_or_unsupported')

    def test_auth_duplicate_fields_rejected_including_unrelated_objects(self):
        for i, raw in enumerate(('{"env":{},"env":{"ANTHROPIC_API_KEY":"SECRET"}}',
                                 '{"permissions":{"a":"SECRET","a":"OTHER"}}')):
            source = self.write('settings' + str(i) + '.json', raw)
            with self.assertRaises(tool.GuardError):
                tool.auth(['fixture=' + str(source)], self.base / ('out' + str(i) + '.json'))

    def test_auth_complete_settings_ignore_unrelated_fields(self):
        source = self.write('settings.json', {'model': 'PRIVATE_MODEL',
            'permissions': {'allow': ['PRIVATE_PERMISSION']}, 'hooks': {'PRIVATE_HOOK': 'touch nothing'},
            'env': {'PATH': 'PRIVATE_PATH', 'OTHER_SECRET': 'SECRET_VALUE', 'ANTHROPIC_API_KEY': 'secret-key'},
            'apiKeyHelper': 'PRIVATE_HELPER'})
        out = self.base / 'auth.json'
        tool.auth(['fixture=' + str(source)], out)
        text = out.read_text()
        for value in ('PRIVATE_', 'OTHER_SECRET', 'SECRET_VALUE', 'secret-key'):
            self.assertNotIn(value, text)
        self.assertTrue(json.loads(text)['settings'][0]['variables']['ANTHROPIC_API_KEY']['present'])

    def test_auth_default_does_not_inspect_process_environment(self):
        class ForbiddenEnvironment:
            def __contains__(self, key):
                raise AssertionError('Process environment must not be inspected')
            def get(self, key):
                raise AssertionError('Process environment must not be inspected')
        out = self.base / 'auth.json'
        with patch.object(tool.os, 'environ', ForbiddenEnvironment()):
            tool.auth([], out)
        data = json.loads(out.read_text())
        self.assertFalse(data['process_environment_included'])
        self.assertEqual(data['helper_environment'], {})
        self.assertEqual(data['helper_environment_source'], 'not-inspected')

    def test_auth_explicit_process_environment_uses_only_mock(self):
        out = self.base / 'auth.json'
        with patch.object(tool.os, 'environ', {'ANTHROPIC_AUTH_TOKEN': 'MOCK_SECRET', 'OTHER': 'NO_READ'}):
            tool.auth([], out, include_process_env=True)
        text = out.read_text()
        data = json.loads(text)
        self.assertTrue(data['process_environment_included'])
        self.assertTrue(data['helper_environment']['ANTHROPIC_AUTH_TOKEN']['present'])
        self.assertEqual(data['helper_environment_source'], 'current-helper-inherited')
        self.assertTrue(data['effective_configuration_unknown'])
        self.assertNotIn('MOCK_SECRET', text)
        self.assertNotIn('NO_READ', text)

    def test_output_inside_source_overwrite_and_symlink_rejected(self):
        settings = self.write('settings.json', {'env': {}})
        for path in (self.source / 'out.json', self.source):
            with self.assertRaises(tool.GuardError):
                tool.audit(['fixture=' + str(self.source)], path)
        existing = self.write('already.json', 'keep')
        with self.assertRaises(tool.GuardError):
                tool.auth(['fixture=' + str(settings)], existing)
        link = self.base / 'linked-output'
        link.symlink_to(self.source, target_is_directory=True)
        with self.assertRaises(tool.GuardError):
                tool.auth(['fixture=' + str(settings)], link / 'auth.json')
        self.assertEqual(existing.read_text(), 'keep')

    def test_missing_policy_and_unknown_fields_rejected(self):
        with self.assertRaises((tool.GuardError, OSError)):
            tool.backup(self.base / 'missing.json', self.base / 'backup')
        self.write('source/work.md', 'fixture')
        policy = self.policy(override='SECRET')
        with self.assertRaises(tool.GuardError):
            self.backup(policy=policy)

    def test_writers_and_sensitive_uninstall_rejected(self):
        self.write('source/work.md', 'fixture')
        for changes in ({'writer_state': 'running'},
                        {'backup_policy': 'sensitive-recovery', 'accept_sensitive_originals': True},
                        {'mode': 'maintenance', 'backup_policy': 'sensitive-recovery'},
                        {'authorization_ref': ''}, {'retention_note': ''}):
            with self.assertRaises(tool.GuardError):
                self.backup(policy=self.policy(**changes))
            self.assertFalse((self.base / 'backup').exists())

    def test_policy_full_coverage_and_added_file(self):
        self.write('source/a.md', 'a')
        policy = self.policy()
        self.write('source/new.md', 'new')
        with self.assertRaises(tool.GuardError):
            self.backup(policy=policy)
        policy = self.policy()
        policy['reviewed_files'] = []
        with self.assertRaises(tool.GuardError):
            self.backup(policy=policy)

    def test_review_paths_duplicates_hash_and_unknown_class(self):
        path = self.write('source/a.md', 'a')
        for mode in ('duplicate', 'traversal', 'unknown', 'hash'):
            policy = self.policy()
            row = policy['reviewed_files'][0]
            if mode == 'duplicate':
                policy['reviewed_files'].append(dict(row))
            elif mode == 'traversal':
                row['path'] = '../a.md'
            elif mode == 'unknown':
                row['classification'] = 'automatically_safe'
            else:
                row['sha256'] = '0' * 64
            with self.assertRaises(tool.GuardError):
                self.backup(policy=policy)

    def test_known_credentials_cannot_be_misclassified(self):
        for name in ('.claude.json', '.env', '.env.local', '.credentials.json', 'history.jsonl'):
            path = self.write('source/' + name, 'synthetic-secret')
            with self.assertRaises(tool.GuardError):
                self.backup(policy=self.policy())
            path.unlink()

    def test_symlink_and_special_file_backups_rejected(self):
        target = self.write('outside.md', 'not-selected')
        (self.source / 'link.md').symlink_to(target)
        with self.assertRaises(tool.GuardError):
            self.backup(policy=self.policy())
        (self.source / 'link.md').unlink()
        os.mkfifo(self.source / 'fifo')
        with self.assertRaises(tool.GuardError):
            self.policy()

    def test_work_backup_verified_and_sources_unchanged(self):
        file = self.write('source/work.md', 'user-work-fixture')
        before = tool.CORE.file_digest(file)
        output = self.backup()
        result = tool.verify(output, True)
        self.assertEqual(result['status'], 'backup_verified')
        self.assertTrue(result['policy_verified'])
        self.assertEqual(result['contains_sensitive_originals'], 'possible_unverified')
        self.assertEqual(tool.CORE.file_digest(file), before)
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((output / 'policy-receipt.json').stat().st_mode), 0o600)

    def test_explicit_sensitive_fixture_copied_and_flagged(self):
        self.write('source/.claude.json', '{"token":"synthetic-secret-only"}')
        policy = self.policy(mode='maintenance', backup_policy='sensitive-recovery', accept_sensitive_originals=True)
        policy['reviewed_files'][0]['classification'] = 'sensitive_state'
        output = self.backup(policy=policy)
        result = tool.verify(output)
        self.assertIs(result['contains_sensitive_originals'], True)
        self.assertFalse(result['authorization_verified_by_helper'])
        self.assertIn('synthetic-secret-only', (output / 'copies/work/.claude.json').read_text())

    def test_policy_receipt_missing_or_tampered_rejected(self):
        self.write('source/work.md', 'fixture')
        output = self.backup()
        path = output / 'policy-receipt.json'
        receipt = path.read_text()
        path.unlink()
        with self.assertRaises((tool.GuardError, OSError)):
            tool.verify(output)
        path.write_text(receipt.replace('synthetic-approval-1', 'synthetic-approval-2'))
        with self.assertRaises(tool.GuardError):
            tool.verify(output)

    def test_source_changed_requires_new_plan(self):
        path = self.write('source/work.md', 'fixture')
        output = self.backup()
        path.write_text('different')
        with self.assertRaises(tool.GuardError):
            tool.verify(output, True)
        self.assertEqual(tool.verify(output)['status'], 'backup_verified')

    def test_source_change_between_review_and_copy_invalidates_receipt(self):
        path = self.write('source/work.md', 'fixture')
        original_backup = tool.CORE.backup
        def changed(roots, output, allow_missing=False):
            path.write_text('new content after policy validation')
            return original_backup(roots, output, allow_missing)
        with patch.object(tool.CORE, 'backup', changed):
            with self.assertRaises(tool.GuardError):
                self.backup()
        self.assertFalse((self.base / 'backup/policy-receipt.json').exists())

    def restore_setup(self):
        selected = self.write('source/selected.md', 'older')
        unselected = self.write('source/keep.md', 'keep')
        old = self.backup('old')
        selected.write_text('newer')
        current = self.backup('current')
        plan = self.base / 'plan.json'
        result = tool.prepare_restore(old, current, ['work:selected.md'], plan)
        self.assertFalse(result['restore_authorized'])
        self.assertEqual(selected.read_text(), 'newer')
        return selected, unselected, old, current, plan

    def test_prepare_and_record_restore_only_observe(self):
        selected, unselected, old, current, plan = self.restore_setup()
        # Test harness simulates an independently approved restore, never the adapter.
        shutil.copy2(old / 'copies/work/selected.md', selected)
        result = tool.record_restore(plan, self.base / 'observation.json')
        self.assertEqual(result['status'], 'restore_verified')
        self.assertEqual(unselected.read_text(), 'keep')
        data = json.loads((self.base / 'observation.json').read_text())
        self.assertTrue(data['unselected_unchanged'])
        self.assertFalse(data['restore_performed_by_helper'])

    def test_restore_changed_unselected_is_partial(self):
        selected, unselected, old, current, plan = self.restore_setup()
        shutil.copy2(old / 'copies/work/selected.md', selected)
        unselected.write_text('unauthorized change fixture')
        result = tool.record_restore(plan, self.base / 'observation.json')
        self.assertEqual(result['status'], 'restore_partial')
        self.assertEqual(result['unselected_changes'], 1)

    def test_restore_scope_mismatch_and_tampered_plan_rejected(self):
        selected, unselected, old, current, plan = self.restore_setup()
        other = self.base / 'other'
        other.mkdir()
        (other / 'work.md').write_text('other fixture')
        backup = self.backup('other-backup', self.policy(roots={'work': str(other)}))
        with self.assertRaises(tool.GuardError):
            tool.prepare_restore(old, backup, ['work:selected.md'], self.base / 'bad-plan.json')
        data = json.loads(plan.read_text())
        data['items'][0]['path'] = 'keep.md'
        plan.write_text(json.dumps(data))
        with self.assertRaises(tool.GuardError):
            tool.record_restore(plan, self.base / 'bad-observation.json')

    def test_safe_error_messages_do_not_echo_input_values(self):
        settings = self.write('settings.json', '{"env":{"UNRECOGNIZED_SECRET":"do-not-print-me","UNRECOGNIZED_SECRET":"again"}}')
        stderr, stdout = io.StringIO(), io.StringIO()
        with contextlib.redirect_stderr(stderr), contextlib.redirect_stdout(stdout):
            status = tool.main(['auth', '--settings', 'fixture=' + str(settings), '--out', str(self.base / 'out.json')])
        self.assertEqual(status, 2)
        self.assertNotIn('do-not-print-me', stderr.getvalue() + stdout.getvalue())
        self.assertNotIn('UNRECOGNIZED_SECRET', stderr.getvalue() + stdout.getvalue())


if __name__ == '__main__':
    unittest.main()
