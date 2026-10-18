#!/usr/bin/env python3
"""One full synthetic flow through actual helpers and the unified report."""
import hashlib
import json
from pathlib import Path
import shutil
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

import audit_tools as audit
import code_tools as code
import report_tools as report


@unittest.skipUnless(code.dependency.inspect_installation()['status'] == 'verified', 'Optional upstream dependency absent; all-eight-module integration not covered')
class IntegrationTests(unittest.TestCase):
    def test_generated_evidence_from_all_eight_modules(self):
        with tempfile.TemporaryDirectory(prefix='cleanup-full-flow-') as temporary:
            base = Path(temporary).resolve()
            project = base / 'project'; project.mkdir()
            config = base / 'config'; config.mkdir()
            chrome = base / 'chrome'; profile = chrome / 'Default'; profile.mkdir(parents=True)
            outputs = base / 'outputs'; outputs.mkdir()
            selected = project / 'report.txt'; selected.write_text('older synthetic work')
            (project / 'keep.txt').write_text('untouched synthetic work')
            (config / 'settings.json').write_text(json.dumps({'model': 'synthetic-model',
                'permissions': {'allow': []}, 'env': {'ANTHROPIC_API_KEY': 'SYNTHETIC_SECRET_NOT_FOR_DISPLAY'}}))
            state = base / '.claude.json'
            state.write_text(json.dumps({'oauthAccount': {'emailAddress': 'fake@example.invalid'},
                                        'nested': {'deviceId': 'SYNTHETIC_DEVICE_NOT_FOR_DISPLAY'}}))
            for filename, sql in (
                ('Cookies', "CREATE TABLE cookies(host_key TEXT,top_frame_site_key TEXT,value TEXT);"
                    "INSERT INTO cookies VALUES('.claude.ai','https://example.invalid','SYNTHETIC_COOKIE_NOT_FOR_DISPLAY');"),
                ('History', "CREATE TABLE urls(id INTEGER,url TEXT); CREATE TABLE visits(url INTEGER);"
                    "CREATE TABLE downloads_url_chains(id INTEGER,url TEXT); CREATE TABLE downloads(id INTEGER);"
                    "INSERT INTO downloads VALUES(1);"
                    "INSERT INTO downloads_url_chains VALUES(1,'https://claude.ai/a'),(1,'https://claude.ai/b'),(1,'https://claude.ai/c');")):
                with sqlite3.connect(profile / filename) as database:
                    database.executescript(sql)
            (profile / 'Preferences').write_text('{}')
            before = audit.scan_tree(project, True)
            code.audit(['config=' + str(config), 'state=' + str(state)], outputs / 'code.json', state)
            # Default auth must not touch inherited authentication state.
            with patch.object(code.os, 'environ', new=None):
                code.auth(['main=' + str(config / 'settings.json')], outputs / 'auth.json')

            def backup(name):
                policy = {'schema': 1, 'mode': 'maintenance', 'backup_policy': 'work-products',
                    'roots': {'work': str(project)}, 'writer_state': 'confirmed_stopped',
                    'authorization_ref': 'synthetic-test-only', 'retention_note': 'temporary fixture',
                    'reviewed_files': [{'root': 'work', 'path': p.name, 'classification': 'work_product',
                        'sha256': hashlib.sha256(p.read_bytes()).hexdigest()} for p in sorted(project.iterdir())]}
                policy_path = outputs / (name + '-policy.json')
                policy_path.write_text(json.dumps(policy))
                destination = base / name
                code.backup(policy_path, destination)
                self.assertTrue(code.verify(destination, True)['policy_verified'])
                return destination

            old = backup('old')
            selected.write_text('newer synthetic work')
            current = backup('current')
            plan = outputs / 'plan.json'
            code.prepare_restore(old, current, ['work:report.txt'], plan)
            self.assertEqual(selected.read_text(), 'newer synthetic work')
            # Only the test harness simulates an approved restore in its fixture.
            shutil.copy2(old / 'copies/work/report.txt', selected)
            receipt = outputs / 'restore.json'
            self.assertEqual(code.record_restore(plan, receipt)['status'], 'restore_verified')
            after = audit.scan_tree(project, True)
            audit.write_new(outputs / 'protection.json', audit.compare_snapshots(before, after), [project])
            audit.write_new(outputs / 'chrome.json', audit.chrome_audit(chrome, ['claude.ai']), [chrome])
            audit.write_new(outputs / 'duplicates.json', audit.duplicates(old / 'copies/work', [project]), [project, old])
            ledger = {'schema_version': 1, 'kind': 'cleanup_ledger', 'run_id': 'synthetic-full-flow',
                'mode': 'maintenance', 'observed_at': audit.now(), 'scope': {'protected_roots': [str(project)]},
                'objects': [{'id': 'cookie', 'status': 'residual', 'kind': 'partitioned_cookie',
                    'locator': 'Default/claude.ai', 'before_count': 1, 'after_count': 1, 'unit': 'cookie',
                    'evidence_refs': ['chrome.json'], 'limitations': ['Synthetic audit only; no deletion attempted.']}]}
            audit.write_new(outputs / 'ledger.json', ledger, [project])
            specs = [(kind, outputs / (kind + '.json')) for kind in report.NORMALIZERS if kind != 'backup']
            specs.append(('backup', old / 'policy-receipt.json'))
            payload = report.render(specs, outputs / 'report.html', outputs / 'report.md')
            self.assertEqual(len(payload['sources']), 8)
            self.assertEqual({x['module'] for x in payload['rows']}, set(report.MODULE_NAMES.values()))
            self.assertFalse(payload['cleanup_authorized']); self.assertFalse(payload['restore_authorized'])
            self.assertEqual(payload['operations'], [])
            downloads = next(x for x in payload['rows'] if x['category'] == '下载记录')
            self.assertEqual([(v['value'], v['unit']) for v in downloads['counts']][:2],
                             [(1, 'download_id'), (3, 'chain_rows')])
            cookie = next(x for x in payload['rows'] if x['category'] == 'Cookie')
            self.assertEqual(cookie['status'], 'residual')
            self.assertEqual(cookie['counts'][1]['value'], 1)
            combined = (outputs / 'report.html').read_text() + (outputs / 'report.md').read_text()
            self.assertNotIn('NOT_FOR_DISPLAY', combined)
            self.assertNotIn('fake@example.invalid', combined)
            self.assertEqual((project / 'keep.txt').read_text(), 'untouched synthetic work')
            self.assertEqual(selected.read_text(), 'older synthetic work')


if __name__ == '__main__':
    unittest.main()
