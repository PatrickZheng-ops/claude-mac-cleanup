#!/usr/bin/env python3
"""Synthetic saved-evidence tests. No live Claude, Chrome or user-project reads."""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
import report_tools as rt


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='cleanup-report-test-')
        self.base = Path(os.path.realpath(self.temp.name))
        self.source = self.base / 'source'
        self.source.mkdir()
        self.inputs = self.base / 'inputs'; self.inputs.mkdir()
        self.output = self.base / 'reports'; self.output.mkdir()

    def tearDown(self):
        self.temp.cleanup()

    def saved(self, name, data):
        path = self.inputs / (name + '.json')
        path.write_text(json.dumps(data), encoding='utf-8')
        return path

    def code(self):
        session = '12345678-1234-1234-1234-123456789012'
        return {'schema': 1, 'mode': 'metadata-only', 'created_at': '2026-01-01T00:00:00Z',
                'roots': {'claude': str(self.source / '.claude')},
                'trees': {'claude': {'missing': False, 'entries': {
                    '.': {'kind': 'directory', 'bytes': 0},
                    'settings.json': {'kind': 'file', 'bytes': 100},
                    'projects/project/' + session + '.jsonl': {'kind': 'file', 'bytes': 200},
                    'debug/' + session + '.txt': {'kind': 'file', 'bytes': 300}}}},
                'state': {'identity_keys_present': ['oauthAccount'], 'cache_keys_present': ['tipsHistory'],
                    'projects_count': 2, 'mcp_servers_count': 1,
                    'device_id_fields': [{'field': 'deviceId', 'location': [{'object_key_index': 2}],
                        'value_type': 'string', 'present': True, 'value_recorded': False,
                        'ownership': 'unverified', 'preserve': True}],
                    'device_id_field_count': 1, 'device_id_scan_scope': 'selected-state-json-objects-and-arrays',
                    'device_id_scan_complete': True},
                'relationships': {'cleanup_authorized': True, 'raw_secret': 'DO_NOT_SHOW_GRAPH_SECRET'},
                'summary': {'complete': True}, 'raw_secret': 'DO_NOT_SHOW_TOP_SECRET'}

    def chrome(self):
        return {'schema_version': 1, 'kind': 'chrome_audit', 'created_at': '2026-01-02T00:00:00Z',
                'user_data_root': str(self.source / 'Chrome'), 'domains': ['claude.ai'],
                'summary': {'complete': True}, 'profiles': [{
                    'profile': 'Default', 'cookies': [{'status': 'ok', 'target_cookie_count': 1,
                        'target_partitioned_cookie_count': 1, 'value': 'DO_NOT_SHOW_COOKIE'}],
                    'history': {'urls': {'status': 'locked', 'ui_row_count': 0},
                        'visits': {'status': 'locked'}, 'downloads': {'status': 'ok',
                            'target_unique_download_ids': 1, 'target_chain_row_count': 3,
                            'matching_download_records': 1, 'orphan_target_chain_ids': 0,
                            'downloads_table': {'status': 'ok'}}},
                    'passwords': {'Login Data': {'status': 'ok', 'target_login_record_count': 0},
                                  'Login Data For Account': {'status': 'missing'}},
                    'bookmarks': {'status': 'ok', 'target_bookmark_count': 0},
                    'preferences': {'status': 'ok', 'target_key_count': 0, 'unsupported_category_count': 0},
                    'indexeddb': {'status': 'partially_unsupported_layout', 'target_origin_store_count': 0,
                                  'unrecognized_entries': 4, 'symlink_entries_skipped': 0},
                    'official_extension': {'status': 'absent', 'official_extension_directory_exists': False}}],
                'warnings': []}

    def auth(self):
        absent = {'present': False, 'value_recorded': False, 'value_hash_recorded': False, 'value_type': None, 'empty': None}
        present = {'present': True, 'value_recorded': False, 'value_hash_recorded': False, 'value_type': 'string', 'empty': False}
        keys = ('ANTHROPIC_API_KEY', 'ANTHROPIC_AUTH_TOKEN', 'CLAUDE_CODE_OAUTH_TOKEN', 'ANTHROPIC_BASE_URL', 'CLAUDE_CONFIG_DIR', 'CLAUDE_SECURESTORAGE_CONFIG_DIR')
        variables = {key: copy.deepcopy(absent) for key in keys}
        variables['ANTHROPIC_API_KEY'] = dict(present, unknown_value='DO_NOT_SHOW_AUTH_SECRET')
        variables['ANTHROPIC_BASE_URL'] = dict(present, endpoint={'status': 'parsed', 'scheme': 'https', 'host': 'gateway.example.dev', 'port': 8443})
        return {'schema': 1, 'kind': 'auth-candidates', 'settings': [{'label': 'settings', 'variables': variables,
            'apiKeyHelper': dict(absent, executed=False)}], 'helper_environment': None,
            'effective_authentication_verified': False, 'precedence_resolved': False}

    def protection(self):
        return {'schema_version': 1, 'kind': 'comparison', 'root': str(self.source / 'project'),
                'summary': {'complete': True, 'source_errors': 0,
                    'hash_comparisons': {'equal': 2, 'both_absent': 8}},
                'changes': [{'path': '.DS_Store', 'change': 'changed'},
                            {'path': 'work.docx', 'change': 'changed'}]}

    def duplicates(self):
        return {'schema_version': 1, 'kind': 'duplicates', 'copies_root': str(self.source / 'copies'),
                'original_roots': [str(self.source / 'original')],
                'matches': [{'path': 'copy.docx', 'size': 123, 'sha256': 'a' * 64,
                    'originals': [{'root': str(self.source / 'original'), 'path': 'draft.docx'}]}],
                'unmatched': [{'path': 'old.xlsx', 'size': 40, 'status': 'no_equal_hash_in_readable_candidates'}],
                'errors': [], 'summary': {'complete': True}}

    def restore(self):
        metadata = {'kind': 'file', 'bytes': 4, 'sha256': 'a' * 64, 'mode': 384, 'uid': 1, 'gid': 1}
        return {'schema': 1, 'kind': 'restore-observation', 'status': 'partial',
                'roots': {'claude': str(self.source / '.claude')},
                'backup_dir': str(self.source / 'backup'), 'pre_restore_backup': str(self.source / 'before'),
                'observed_at': '2026-01-03T00:00:00Z', 'selected_results': [
                    {'root': 'claude', 'path': 'good.json', 'result': 'verified',
                        'expected': metadata, 'observed': copy.deepcopy(metadata)},
                    {'root': 'claude', 'path': 'pending.json', 'result': 'unverified',
                        'expected': metadata, 'observed': None}],
                'unselected_changes': [], 'unselected_unchanged': False,
                'observation_error': 'DO_NOT_SHOW_RAW_ERROR'}

    def backup(self):
        return {'schema': 1, 'kind': 'policy-backup-receipt', 'status': 'policy_backup_verified',
                'backup_dir': str(self.source / 'backup'), 'classification_counts': {'work_product': 1, 'nonsecret_config': 1},
                'contains_sensitive_originals': 'possible_unverified', 'known_sensitive_paths_blocked': True,
                'arbitrary_embedded_secrets_detected': False, 'authorization_verified_by_helper': False,
                'writer_state_verified_by_helper': False, 'copied_source_unchanged': True,
                'source_changed_by_tool': False, 'reviewed_hash_coverage': 1,
                'policy_sha256': 'a' * 64, 'manifest_sha256': 'b' * 64, 'receipt_sha256': 'c' * 64,
                'policy': {'schema': 1, 'mode': 'uninstall', 'backup_policy': 'work-products',
                    'roots': {'work': str(self.source / 'work')}, 'writer_state': 'confirmed_stopped',
                    'authorization_ref': 'DO_NOT_SHOW_POLICY_TEXT', 'retention_note': 'DO_NOT_SHOW_NOTE',
                    'reviewed_files': [{'path': 'DO_NOT_SHOW_FILE_LIST'}]}}

    def ledger(self):
        return {'schema_version': 1, 'kind': 'cleanup_ledger', 'run_id': 'fixture', 'mode': 'uninstall',
                'observed_at': '2026-01-03T01:00:00Z', 'scope': {'protected_roots': [str(self.source / 'protected')]},
                'objects': [{'id': 'app-1', 'kind': 'app', 'batch': 'B1', 'status': 'verified_removed',
                    'locator': '/Applications/Claude.app', 'action': 'permanent_delete', 'before_count': 1,
                    'after_count': 0, 'unit': 'item', 'evidence_refs': ['verification.md:item-1'],
                    'approval_ref': 'conversation:approval-1', 'limitations': []}]}

    def build(self, kind, data):
        return rt.load_sources([(kind, self.saved(kind, data))])[0]

    @unittest.skipUnless(rt.dependency.inspect_installation()['status'] == 'verified', 'Optional upstream dependency absent; not covered by the base suite')
    def test_combined_eight_modules_and_distinct_units(self):
        specs = [(kind, self.saved(kind, getattr(self, kind)())) for kind in rt.NORMALIZERS]
        payload = rt.render(specs, self.output / 'report.html', self.output / 'report.md')
        self.assertEqual(len(payload['sources']), 8)
        self.assertEqual({r['module'] for r in payload['rows']}, set(rt.MODULE_NAMES.values()))
        self.assertFalse(payload['cleanup_authorized']); self.assertFalse(payload['restore_authorized'])
        self.assertEqual(payload['operations'], [])
        self.assertEqual(payload['cleanup_completion'], 'not_determined_by_report')
        row = next(r for r in payload['rows'] if r['category'] == '下载记录')
        self.assertEqual([(c['value'], c['unit']) for c in row['counts']][:2], [(1, 'download_id'), (3, 'chain_rows')])
        html_text = (self.output / 'report.html').read_text()
        markdown = (self.output / 'report.md').read_text()
        for row in payload['rows']:
            self.assertIn(rt.md_text(row['target']), markdown)
        self.assertIn('本报告不判定整机清理完成', html_text)

    @unittest.skipUnless(rt.dependency.inspect_installation()['status'] == 'verified', 'Optional upstream dependency absent; not covered by the base suite')
    def test_whitelist_ignores_secrets_and_raw_graph(self):
        data = self.code()
        data['state']['raw_secret'] = 'DO_NOT_SHOW_STATE_SECRET'
        data['trees']['claude']['entries']['settings.json']['raw_secret'] = 'DO_NOT_SHOW_ENTRY_SECRET'
        payload = self.build('code', data)
        raw = json.dumps(payload)
        self.assertNotIn('DO_NOT_SHOW', raw)
        self.assertNotIn('12345678-1234', raw)
        self.assertEqual(len([r for r in payload['rows'] if r['category'] == '会话关联']), 1)
        self.assertFalse(payload['cleanup_authorized'])

    def test_auth_candidate_only_and_safe_endpoint(self):
        payload = self.build('auth', self.auth())
        raw = json.dumps(payload, ensure_ascii=False)
        self.assertNotIn('DO_NOT_SHOW', raw)
        self.assertIn('https://gateway.example.dev:8443', raw)
        self.assertTrue(any(r['target'] == '实际生效认证与账号' and r['status'] == 'not_checked' for r in payload['rows']))

    def test_auth_endpoint_cannot_smuggle_query_or_credentials(self):
        for host in ('user:pass@example.dev', 'example.dev?code=SECRET', 'example.dev/path', 'example.dev#secret'):
            data = self.auth(); data['settings'][0]['variables']['ANTHROPIC_BASE_URL']['endpoint']['host'] = host
            with self.subTest(host=host), self.assertRaises(rt.audit.AuditError): self.build('auth', data)

    @unittest.skipUnless(rt.dependency.inspect_installation()['status'] == 'verified', 'Optional upstream dependency absent; not covered by the base suite')
    def test_device_value_or_ancestor_in_summary_rejected(self):
        for field, value in [('value', 'private'), ('hash', 'a' * 64), ('ancestor', 'private')]:
            data = self.code(); data['state']['device_id_fields'][0][field] = value
            with self.subTest(field=field), self.assertRaises(rt.audit.AuditError):
                self.build('code', data)

    @unittest.skipUnless(rt.dependency.inspect_installation()['status'] == 'verified', 'Optional upstream dependency absent; not covered by the base suite')
    def test_device_count_mismatch_rejected(self):
        data = self.code(); data['state']['device_id_field_count'] = 2
        with self.assertRaises(rt.audit.AuditError): self.build('code', data)

    @unittest.skipUnless(rt.dependency.inspect_installation()['status'] == 'verified', 'Optional upstream dependency absent; not covered by the base suite')
    def test_old_device_summary_is_unverified(self):
        data = self.code(); data['state'] = {'identity_keys_present': []}
        payload = self.build('code', data)
        row = next(r for r in payload['rows'] if r['category'] == '设备标识摘要')
        self.assertEqual(row['status'], 'not_checked')

    @unittest.skipUnless(rt.dependency.inspect_installation()['status'] == 'verified', 'Optional upstream dependency absent; not covered by the base suite')
    def test_bad_schema_modes_rejected(self):
        for value in [0, 2, '1', True, None]:
            data = self.chrome(); data['schema_version'] = value
            with self.subTest(value=value), self.assertRaises(rt.audit.AuditError):
                self.build('chrome', data)
        data = self.code(); data['mode'] = 'full-copy'
        with self.assertRaises(rt.audit.AuditError): self.build('code', data)

    def test_url_query_fragment_userinfo_any_tld_removed(self):
        value = 'https://alice:pass@auth.example.dev:8443/callback?code=TOPSECRET&state=STATESECRET#FRAGMENTSECRET'
        self.assertEqual(rt.safe_text(value), 'https://auth.example.dev:8443/callback')
        self.assertEqual(rt.safe_text('http://localhost:3999/cb?token=TOPSECRET'), 'http://localhost:3999/cb')
        self.assertEqual(rt.safe_text('chrome-extension://fcoeoabgfenejglbffodgkkbkcdhcgfn/p?code=TOPSECRET#fragment'), 'chrome-extension://fcoeoabgfenejglbffodgkkbkcdhcgfn/p')

    def test_home_email_uuid_key_masking(self):
        value = '/Users/sensitiveperson/file alice@example.dev 12345678-1234-1234-1234-123456789012 sk-ant-123456789'
        result = rt.safe_text(value)
        for needle in ('sensitiveperson', 'alice@example', '12345678-1234', 'sk-ant-'):
            self.assertNotIn(needle, result)

    def test_xss_safe_html_markdown_and_csp_hashes(self):
        data = self.ledger()
        malicious = '</script><script>alert("XSS")</script><img src=x onerror=alert(1)> [p](javascript:alert(1)) | end'
        data['objects'][0]['locator'] = malicious
        payload = self.build('ledger', data)
        rendered = rt.render_html(payload); markdown = rt.render_markdown(payload)
        self.assertNotIn(malicious, rendered)
        self.assertNotIn('<img src=x', markdown)
        self.assertNotIn('[p](javascript:', markdown)
        self.assertIn('\\u003c/script\\u003e', rendered)
        self.assertNotIn('innerHTML', rendered)
        self.assertIn("connect-src &#x27;none&#x27;", rendered)
        scripts = re.findall(r'<script>([\s\S]*?)</script>', rendered)
        styles = re.findall(r'<style>([\s\S]*?)</style>', rendered)
        self.assertEqual(len(scripts), 1)
        for content in scripts + styles:
            digest = base64.b64encode(hashlib.sha256(content.encode()).digest()).decode()
            self.assertIn(digest, rendered)

    def test_locked_db_not_zero_despite_zero_ui_and_complete_summary(self):
        payload = self.build('chrome', self.chrome())
        row = next(r for r in payload['rows'] if r['category'] == '历史 URL')
        self.assertEqual(row['status'], 'not_checked'); self.assertIsNone(row['counts'][0]['value'])
        self.assertNotIn('DO_NOT_SHOW_COOKIE', json.dumps(payload))

    def test_wal_is_unverified_not_zero(self):
        for status in ('wal_mode_unverified', 'wal_or_journal_present_unverified'):
            data = self.chrome(); data['profiles'][0]['history']['urls'] = {'status': status}
            payload = self.build('chrome', data)
            row = next(r for r in payload['rows'] if r['category'] == '历史 URL')
            self.assertEqual(row['status'], 'not_checked'); self.assertIsNone(row['counts'][0]['value'])

    def test_unrecognized_indexeddb_not_false_residual_or_clean(self):
        payload = self.build('chrome', self.chrome())
        row = next(r for r in payload['rows'] if r['category'] == 'IndexedDB')
        self.assertEqual(row['status'], 'not_checked')
        self.assertEqual(row['counts'][0]['value'], 0)
        self.assertEqual(row['counts'][1]['value'], 4)

    def test_unknown_status_is_unverified_and_not_echoed(self):
        data = self.chrome(); data['profiles'][0]['history']['urls'] = {'status': 'DO_NOT_SHOW_STATUS_SECRET'}
        payload = self.build('chrome', data)
        self.assertNotIn('DO_NOT_SHOW', json.dumps(payload))

    def test_failed_check_cannot_smuggle_zero_count(self):
        data = self.chrome(); data['profiles'][0]['history']['urls'] = {'status': 'locked', 'target_url_count': 0}
        payload = self.build('chrome', data)
        row = next(r for r in payload['rows'] if r['category'] == '历史 URL')
        self.assertIsNone(row['counts'][0]['value']); self.assertEqual(row['status'], 'not_checked')

    @unittest.skipUnless(rt.dependency.inspect_installation()['status'] == 'verified', 'Optional upstream dependency absent; not covered by the base suite')
    def test_partial_restore_remains_partial(self):
        payload = self.build('restore', self.restore())
        overall = next(r for r in payload['rows'] if r['category'] == '恢复验收范围')
        self.assertEqual(overall['status'], 'partial')
        self.assertNotIn('DO_NOT_SHOW', json.dumps(payload)); self.assertNotIn('a' * 64, json.dumps(payload))

    def test_backup_policy_does_not_export_raw_policy_or_claim_secret_free(self):
        payload = self.build('backup', self.backup()); raw = json.dumps(payload, ensure_ascii=False)
        self.assertNotIn('DO_NOT_SHOW', raw); self.assertNotIn('a' * 64, raw)
        self.assertIn('possible_unverified', raw)
        self.assertEqual(payload['rows'][0]['status'], 'not_checked')

    def test_sensitive_backup_remains_visible(self):
        data = self.backup(); data['policy'].update(mode='maintenance', backup_policy='sensitive-recovery')
        data.update(contains_sensitive_originals=True, known_sensitive_paths_blocked=False)
        data['classification_counts'] = {'sensitive_state': 2}
        payload = self.build('backup', data)
        self.assertEqual(payload['rows'][0]['status'], 'residual')
        self.assertIn('明确保留了敏感原件', payload['rows'][0]['note'])

    def test_backup_cannot_claim_verified_human_authorization(self):
        data = self.backup(); data['authorization_verified_by_helper'] = True
        with self.assertRaises(rt.audit.AuditError): self.build('backup', data)

    def test_backup_hash_coverage_must_fit_classification(self):
        data = self.backup(); data['reviewed_hash_coverage'] = 99
        with self.assertRaises(rt.audit.AuditError): self.build('backup', data)

    @unittest.skipUnless(rt.dependency.inspect_installation()['status'] == 'verified', 'Optional upstream dependency absent; not covered by the base suite')
    def test_inconsistent_verified_restore_downgraded(self):
        data = self.restore(); data['status'] = 'verified'; data['unselected_unchanged'] = True
        data['selected_results'] = data['selected_results'][:1]
        data['selected_results'][0]['observed']['bytes'] = 20
        data['observation_error'] = None
        payload = self.build('restore', data)
        overall = next(r for r in payload['rows'] if r['category'] == '恢复验收范围')
        self.assertNotEqual(overall['status'], 'verified')

    def test_verified_ledger_requires_evidence(self):
        data = self.ledger(); data['objects'][0]['evidence_refs'] = [' ']
        payload = self.build('ledger', data)
        self.assertEqual(payload['rows'][0]['status'], 'attempted_unverified')
        self.assertFalse(payload['cleanup_authorized'])

    def test_verified_removed_positive_after_count_becomes_residual(self):
        data = self.ledger(); data['objects'][0]['after_count'] = 1
        payload = self.build('ledger', data)
        self.assertEqual(payload['rows'][0]['status'], 'residual')
        self.assertIn('数量与结论冲突', payload['rows'][0]['note'])
        self.assertEqual(payload['rows'][0]['counts'][1]['value'], 1)

    def test_verified_removed_null_after_count_is_not_automatically_downgraded(self):
        data = self.ledger(); data['objects'][0]['after_count'] = None
        payload = self.build('ledger', data)
        self.assertEqual(payload['rows'][0]['status'], 'verified_removed')
        self.assertIsNone(payload['rows'][0]['counts'][1]['value'])

    def test_multiple_ledgers_rejected_by_api(self):
        first = self.saved('ledger-before', self.ledger())
        data = self.ledger(); data['objects'][0]['status'] = 'residual'
        second = self.saved('ledger-after', data)
        with self.assertRaisesRegex(rt.audit.AuditError, 'Only one cleanup ledger'):
            rt.render([('ledger', first), ('ledger', second)], self.output / 'a.html', self.output / 'a.md')
        self.assertEqual(list(self.output.iterdir()), [])

    def test_repeated_ledger_cli_argument_is_rejected(self):
        source = self.saved('ledger', self.ledger())
        result = subprocess.run([sys.executable, str(rt.BASE / 'scripts' / 'report_tools.py'),
            '--ledger', str(source), '--ledger', str(source),
            '--out-html', str(self.output / 'a.html'), '--out-md', str(self.output / 'a.md')],
            capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('--ledger may be provided only once', result.stderr)
        self.assertEqual(list(self.output.iterdir()), [])

    def test_ledger_approval_is_only_reference(self):
        payload = self.build('ledger', self.ledger())
        self.assertEqual(payload['rows'][0]['approval_ref'], 'conversation:approval-1')
        self.assertFalse(payload['cleanup_authorized']); self.assertEqual(payload['operations'], [])

    def test_ledger_duplicate_identity_rejected(self):
        data = self.ledger(); data['objects'] *= 2
        with self.assertRaises(rt.audit.AuditError): self.build('ledger', data)

    def test_unmatched_not_called_useless(self):
        payload = self.build('duplicates', self.duplicates())
        row = next(r for r in payload['rows'] if r['category'] == '未匹配副本')
        self.assertEqual(row['status'], 'retained')
        self.assertIn('用途和保留价值仍需判断', row['note'])

    def test_missing_hash_coverage_and_ds_store_not_hidden(self):
        payload = self.build('protection', self.protection())
        self.assertTrue(any(r['target'] == '.DS_Store' for r in payload['rows']))
        row = next(r for r in payload['rows'] if r['category'] == '项目保护比对')
        self.assertIn('元数据相同不等于字节一致', row['note'])
        self.assertTrue(any(c['label'] == '双方无哈希' and c['value'] == 8 for c in row['counts']))

    def test_private_permissions(self):
        source = self.saved('ledger', self.ledger())
        rt.render([('ledger', source)], self.output / 'a.html', self.output / 'a.md')
        for path in self.output.iterdir():
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_no_input_does_not_create_output(self):
        with self.assertRaises(rt.audit.AuditError): rt.render([], self.output / 'a.html', self.output / 'a.md')
        self.assertEqual(list(self.output.iterdir()), [])

    def test_existing_output_never_overwritten(self):
        source = self.saved('ledger', self.ledger()); target = self.output / 'a.md'; target.write_text('KEEP')
        with self.assertRaises(rt.audit.AuditError): rt.render([('ledger', source)], self.output / 'a.html', target)
        self.assertEqual(target.read_text(), 'KEEP'); self.assertFalse((self.output / 'a.html').exists())

    def test_outputs_must_be_distinct(self):
        source = self.saved('ledger', self.ledger()); target = self.output / 'a.html'
        with self.assertRaises(rt.audit.AuditError): rt.render([('ledger', source)], target, target)
        self.assertFalse(target.exists())

    @unittest.skipUnless(rt.dependency.inspect_installation()['status'] == 'verified', 'Optional upstream dependency absent; not covered by the base suite')
    def test_output_inside_declared_source_rejected(self):
        data = self.code(); data['roots']['claude'] = str(self.source)
        source = self.saved('code', data)
        with self.assertRaises(rt.audit.AuditError): rt.render([('code', source)], self.source / 'a.html', self.output / 'a.md')

    def test_output_inside_protected_or_backup_root_rejected(self):
        for kind, rootkey in (('ledger', 'protected'), ('restore', 'backup')):
            data = getattr(self, kind)(); targetdir = self.source / rootkey; targetdir.mkdir()
            source = self.saved(kind, data)
            with self.subTest(kind=kind), self.assertRaises(rt.audit.AuditError):
                rt.render([(kind, source)], targetdir / 'a.html', self.output / 'a.md')

    def test_symlink_output_ancestor_rejected(self):
        link = self.base / 'link'; link.symlink_to(self.output, target_is_directory=True)
        source = self.saved('ledger', self.ledger())
        with self.assertRaises(rt.audit.AuditError): rt.render([('ledger', source)], link / 'a.html', self.output / 'a.md')

    def test_symlink_input_rejected(self):
        source = self.saved('ledger', self.ledger()); link = self.inputs / 'link.json'; link.symlink_to(source)
        with self.assertRaises(rt.audit.AuditError): rt.load_sources([('ledger', link)])

    def test_duplicate_json_keys_rejected_at_all_depths(self):
        for raw in ('{"schema_version":1,"schema_version":2}',
                    '{"scope":{"status":"failed","status":"verified_removed"}}',
                    '{"objects":[{"status":"failed","status":"verified_removed"}]}'):
            path = self.inputs / 'ambiguous.json'; path.write_text(raw)
            with self.subTest(raw=raw), self.assertRaises(rt.audit.AuditError): rt.load_saved_json(path)

    @unittest.skipUnless(rt.dependency.inspect_installation()['status'] == 'verified', 'Optional upstream dependency absent; not covered by the base suite')
    def test_source_paths_are_never_probed(self):
        data = self.code(); data['roots']['claude'] = '/nonexistent/evidence-only-source/.claude'
        source = self.saved('code', data)
        original_lstat = Path.lstat
        def guarded(path, *args, **kwargs):
            if str(path).startswith('/nonexistent'):
                raise AssertionError('Probed saved source root')
            return original_lstat(path, *args, **kwargs)
        with mock.patch.object(Path, 'lstat', guarded):
            payload = rt.render([('code', source)], self.output / 'a.html', self.output / 'a.md')
        self.assertEqual(payload['mode'], 'review-only')

    @unittest.skipUnless(rt.dependency.inspect_installation()['status'] == 'verified', 'Optional upstream dependency absent; not covered by the base suite')
    def test_relative_root_and_traversing_entry_rejected(self):
        data = self.code(); data['roots']['claude'] = '../../bad'
        with self.assertRaises(rt.audit.AuditError): self.build('code', data)
        data = self.code(); data['trees']['claude']['entries']['../bad'] = {'kind': 'file', 'bytes': 1}
        with self.assertRaises(rt.audit.AuditError): self.build('code', data)

    def test_js_syntax(self):
        node = shutil.which('node')
        if not node:
            self.skipTest('Node is unavailable; JS syntax validation not run')
        script = re.search(r'<script>([\s\S]*?)</script>', (rt.BASE / 'assets' / 'report.html').read_text())[1]
        path = self.base / 'report.js'; path.write_text(script)
        result = subprocess.run([node, '--check', str(path)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_full_table_default_and_print_all_filter_results(self):
        asset = (rt.BASE / 'assets' / 'report.html').read_text()
        self.assertIn('<option value="all" selected>', asset)
        self.assertIn('window.addEventListener("beforeprint"', asset)
        self.assertIn('window.addEventListener("afterprint"', asset)

    @unittest.skipUnless(rt.dependency.inspect_installation()['status'] == 'verified', 'Optional upstream dependency absent; not covered by the base suite')
    def test_tampered_vendor_rejected_before_execution(self):
        fakebase = self.base / 'fake-skill'
        shutil.copytree(rt.BASE / 'vendor', fakebase / 'vendor')
        helper = fakebase / 'vendor/cc-clean/runtime/cc-clean/scripts/review_tools.py'
        helper.write_text(helper.read_text() + '\nraise RuntimeError("MUST NOT EXECUTE")\n')
        with mock.patch.object(rt, 'BASE', fakebase), self.assertRaises(rt.audit.AuditError):
            rt.vendor_modules()

    def test_cli_errors_do_not_echo_input(self):
        source = self.saved('bad', {'schema_version': 1, 'kind': 'chrome_audit', 'user_data_root': 'DO_NOT_SHOW'})
        result = subprocess.run([sys.executable, str(rt.BASE / 'scripts' / 'report_tools.py'),
            '--chrome', str(source), '--out-html', str(self.output / 'a.html'), '--out-md', str(self.output / 'a.md')],
            capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0); self.assertNotIn('DO_NOT_SHOW', result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
