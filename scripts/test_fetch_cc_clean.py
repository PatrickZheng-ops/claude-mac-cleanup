"""Downloader and dependency-free operation tests; all downloads are mocked."""
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
import fetch_cc_clean as dep
import code_tools as code
import report_tools as report


class FetchTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='optional-dependency-test-')
        self.base = Path(self.tmp.name).resolve()
        self.addCleanup(self.tmp.cleanup)
        self.out = self.base / 'runtime'
        self.source = self.base / 'SOURCE.json'
        self.metadata, _ = dep.manifest()
        self.marker = self.base / 'downloaded-code-must-not-run'
        self.contents = {name: ('from pathlib import Path\nPath(' + repr(str(self.marker)) + ').touch()\n# ' + name).encode()
                         for name in dep.FILES}
        for row in self.metadata['files']:
            row['sha256'] = hashlib.sha256(self.contents[row['path']]).hexdigest()
        self.source.write_text(json.dumps(self.metadata))
        self.urls = []

    def download(self, url):
        self.urls.append(url)
        prefix = 'https://raw.githubusercontent.com/luwill/cc-clean/' + dep.COMMIT + '/'
        self.assertTrue(url.startswith(prefix))
        return self.contents[url[len(prefix):]]

    def fetch(self, **kwargs):
        return dep.fetch(destination=self.out, manifest_path=self.source, downloader=self.download, **kwargs)

    def test_missing_acceptance_never_downloads(self):
        with self.assertRaises(dep.DependencyError):
            self.fetch()
        self.assertEqual(self.urls, [])
        self.assertFalse(self.out.exists())

    def test_pinned_six_files_verify_private_and_never_execute(self):
        result = self.fetch(accepted=True)
        self.assertEqual(result['files_verified'], 6)
        self.assertEqual(result['status'], 'installed_verified')
        self.assertFalse(result['executed'])
        self.assertFalse(self.marker.exists())
        self.assertEqual(len(self.urls), 6)
        for path in self.out.rglob('*'):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700 if path.is_dir() else 0o600)
        self.assertFalse(json.loads((self.out / 'INSTALLATION.json').read_text())['license_granted_by_this_tool'])

    def test_verified_install_is_idempotent_without_network(self):
        self.fetch(accepted=True)
        self.urls.clear()
        result = self.fetch(accepted=True)
        self.assertEqual(result['status'], 'already_verified')
        self.assertFalse(result['network_used'])
        self.assertEqual(self.urls, [])

    def test_hash_failure_creates_no_destination(self):
        self.contents[next(iter(self.contents))] = b'tampered'
        with self.assertRaises(dep.DependencyError):
            self.fetch(accepted=True)
        self.assertFalse(self.out.exists())
        self.assertFalse(self.marker.exists())

    def test_existing_empty_or_file_destination_never_overwritten(self):
        self.out.mkdir()
        with self.assertRaises(dep.DependencyError): self.fetch(accepted=True)
        self.assertEqual(self.urls, [])
        self.out.rmdir(); self.out.write_text('keep')
        with self.assertRaises(dep.DependencyError): self.fetch(accepted=True)
        self.assertEqual(self.out.read_text(), 'keep')

    def test_tampered_or_extra_installation_refused_without_network(self):
        self.fetch(accepted=True); self.urls.clear()
        path = self.out / next(iter(self.contents)); previous = path.read_bytes()
        path.write_bytes(b'changed')
        with self.assertRaises(dep.DependencyError): self.fetch(accepted=True)
        path.write_bytes(previous)
        (self.out / 'surprise.py').write_text('raise RuntimeError')
        with self.assertRaises(dep.DependencyError): self.fetch(accepted=True)
        self.assertEqual(self.urls, [])

    def test_manifest_paths_commit_url_and_duplicates_rejected(self):
        for field, value in [('path', '../escape.py'), ('path', '/absolute.py'),
                             ('upstream_url', 'https://example.com/evil.py'), ('sha256', 'bad')]:
            data = copy.deepcopy(self.metadata); data['files'][0][field] = value
            self.source.write_text(json.dumps(data))
            with self.subTest(field=field), self.assertRaises(dep.DependencyError): self.fetch(accepted=True)
        data = copy.deepcopy(self.metadata); data['commit'] = 'a' * 40
        self.source.write_text(json.dumps(data))
        with self.assertRaises(dep.DependencyError): self.fetch(accepted=True)
        data = copy.deepcopy(self.metadata); data['files'][1] = data['files'][0]
        self.source.write_text(json.dumps(data))
        with self.assertRaises(dep.DependencyError): self.fetch(accepted=True)
        self.source.write_text('{"files": [], "files": []}')
        with self.assertRaises(dep.DependencyError): self.fetch(accepted=True)
        self.assertEqual(self.urls, [])

    def test_linked_destination_or_parent_refused(self):
        other = self.base / 'other'; other.mkdir()
        self.out.symlink_to(other, target_is_directory=True)
        with self.assertRaises(dep.DependencyError): self.fetch(accepted=True)
        self.out.unlink()
        linked = self.base / 'linked'; linked.symlink_to(other, target_is_directory=True)
        with self.assertRaises(dep.DependencyError):
            dep.fetch(True, linked / 'runtime', self.source, self.download)
        self.assertEqual(self.urls, [])

    def test_destination_appearing_during_fetch_is_not_overwritten(self):
        def racing(url):
            self.out.mkdir(exist_ok=True)
            (self.out / 'keep').write_text('kept')
            return self.download(url)
        with self.assertRaises(dep.DependencyError): dep.fetch(True, self.out, self.source, racing)
        self.assertEqual((self.out / 'keep').read_text(), 'kept')
        self.assertFalse((self.out / 'INSTALLATION.json').exists())

    def test_incomplete_write_never_has_complete_status(self):
        with mock.patch.object(dep.audit, 'write_new', side_effect=OSError('mock disk full')):
            with self.assertRaises(dep.DependencyError): self.fetch(accepted=True)
        self.assertFalse((self.out / 'INSTALLATION.json').exists())
        with self.assertRaises(dep.DependencyError): dep.inspect_installation(self.out, self.source)

    def test_redirects_and_unapproved_host_are_refused(self):
        with self.assertRaises(dep.DependencyError):
            dep.NoRedirect().redirect_request(None, None, 302, '', {}, 'https://example.com/evil')
        with mock.patch.object(dep.request, 'build_opener', side_effect=AssertionError('network')):
            with self.assertRaises(dep.DependencyError): dep.download('https://example.com/evil')

    def test_oversized_or_nonbytes_download_rejected(self):
        for value in ('text', b'x' * (dep.MAX_FILE_BYTES + 1)):
            with self.assertRaises(dep.DependencyError):
                dep.fetch(True, self.out, self.source, lambda _: value)
        self.assertFalse(self.out.exists())


class DependencyFreeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='base-feature-test-')
        self.base = Path(self.tmp.name).resolve()
        self.addCleanup(self.tmp.cleanup)

    def test_import_help_and_auth_work_without_dependency(self):
        fake = self.base / 'skill'; fake.mkdir()
        shutil.copytree(dep.ROOT / 'scripts', fake / 'scripts', ignore=shutil.ignore_patterns('__pycache__'))
        (fake / 'vendor/cc-clean').mkdir(parents=True)
        shutil.copyfile(dep.MANIFEST, fake / 'vendor/cc-clean/SOURCE.json')
        settings = self.base / 'settings.json'; settings.write_text('{"env":{"ANTHROPIC_API_KEY":"PRIVATE_FIXTURE"}}')
        script = fake / 'scripts/code_tools.py'
        result = subprocess.run([sys.executable, '-B', str(script), '--help'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        out = self.base / 'auth.json'
        result = subprocess.run([sys.executable, '-B', str(script), 'auth', '--settings', 'settings=' + str(settings),
                                 '--out', str(out)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('PRIVATE_FIXTURE', out.read_text())
        result = subprocess.run([sys.executable, '-B', str(script), 'audit', '--root', 'test=' + str(settings),
                                 '--out', str(self.base / 'audit.json')], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn('Optional CC Clean dependency', result.stderr)
        self.assertNotIn('Traceback', result.stderr)
        self.assertFalse((self.base / 'audit.json').exists())

    def test_six_report_modules_work_without_optional_loader(self):
        from test_report_tools import ReportTests
        fixture = ReportTests(methodName='test_auth_candidate_only_and_safe_endpoint')
        fixture.setUp()
        try:
            kinds = ('chrome', 'protection', 'duplicates', 'auth', 'backup', 'ledger')
            specs = [(kind, fixture.saved(kind, getattr(fixture, kind)())) for kind in kinds]
            with mock.patch.object(report, 'vendor_modules', side_effect=AssertionError('optional load')):
                payload = report.render(specs, fixture.output / 'base.html', fixture.output / 'base.md')
            self.assertEqual(len(payload['sources']), 6)
            self.assertEqual(payload['operations'], [])
            self.assertFalse(payload['cleanup_authorized'])
        finally:
            fixture.tearDown()

    def test_code_report_missing_dependency_is_explicit(self):
        from test_report_tools import ReportTests
        fixture = ReportTests(methodName='test_auth_candidate_only_and_safe_endpoint'); fixture.setUp()
        try:
            with mock.patch.object(report, 'BASE', self.base):
                with self.assertRaisesRegex(report.audit.AuditError, 'Optional CC Clean dependency is absent'):
                    fixture.build('code', fixture.code())
        finally:
            fixture.tearDown()


if __name__ == '__main__':
    unittest.main()
