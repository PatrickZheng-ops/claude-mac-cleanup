import json
from pathlib import Path
import tempfile
import unittest
import zipfile
import release_guard as guard


class ReleaseGuardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='public-release-check-')
        self.base = Path(self.temp.name).resolve()
        self.root = self.base / 'source'; self.root.mkdir()
        (self.root / 'SKILL.md').write_text('Generic synthetic instructions')
        self.manifest(['SKILL.md', 'release-files.json'])

    def tearDown(self): self.temp.cleanup()

    def manifest(self, files):
        (self.root / 'release-files.json').write_text(json.dumps({'schema_version': 1, 'files': files}))

    def test_private_denylist_never_echoes_match(self):
        private = 'PRIVATE_' + 'SYNTHETIC_MARKER'
        (self.root / 'SKILL.md').write_text(private)
        result = guard.check(self.root, [private])
        self.assertEqual(result['status'], 'failed')
        self.assertNotIn(private, json.dumps(result))

    def test_archive_excludes_unlisted_private_and_upstream_files(self):
        (self.root / 'local-config.json').write_text('PRIVATE_SYNTHETIC')
        vendor = self.root / 'vendor/cc-clean'; vendor.mkdir(parents=True)
        (vendor / 'external.py').write_text('not redistributed')
        destination = self.base / 'release.zip'
        result = guard.build_zip(destination, self.root)
        self.assertEqual(result['files'], 2)
        with zipfile.ZipFile(destination) as archive:
            self.assertEqual(len(archive.namelist()), 2)
            self.assertFalse(any('vendor' in x or 'config' in x for x in archive.namelist()))

    def test_runtime_json_and_upstream_entries_rejected(self):
        for name in ('local-config.json', 'vendor/cc-clean/external.py', '../escape'):
            self.manifest([name])
            with self.assertRaises(ValueError): guard.public_files(self.root)

    def test_existing_archive_is_never_overwritten(self):
        destination = self.base / 'release.zip'; destination.write_bytes(b'keep')
        with self.assertRaises(ValueError): guard.build_zip(destination, self.root)
        self.assertEqual(destination.read_bytes(), b'keep')

    def test_symlink_release_source_rejected(self):
        (self.root / 'link.md').symlink_to(self.root / 'SKILL.md')
        self.manifest(['link.md'])
        with self.assertRaises(ValueError): guard.public_files(self.root)


if __name__ == '__main__': unittest.main()
