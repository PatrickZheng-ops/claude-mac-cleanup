import json
from pathlib import Path
import tempfile
import unittest
import install_skill


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='public-skill-install-')
        self.base = Path(self.temp.name).resolve()
        self.source = self.base / 'source'; self.source.mkdir()
        (self.source / 'SKILL.md').write_text('synthetic skill')
        (self.source / 'release-files.json').write_text(json.dumps({'files': ['SKILL.md', 'release-files.json']}))
        self.target = self.base / 'installed'

    def tearDown(self):
        self.temp.cleanup()

    def test_new_install_preserves_source_and_excludes_local_files(self):
        (self.source / 'local-config.json').write_text('PRIVATE_SYNTHETIC')
        result = install_skill.install(self.target, self.source)
        self.assertEqual(result['files'], 2)
        self.assertEqual((self.target / 'SKILL.md').read_text(), 'synthetic skill')
        self.assertFalse((self.target / 'local-config.json').exists())
        self.assertEqual((self.target / 'SKILL.md').stat().st_mode & 0o777, 0o600)

    def test_existing_install_is_not_touched(self):
        self.target.mkdir(); (self.target / 'old').write_text('keep')
        with self.assertRaises(ValueError): install_skill.install(self.target, self.source)
        self.assertEqual((self.target / 'old').read_text(), 'keep')

    def test_symlink_destination_is_rejected(self):
        self.target.symlink_to(self.source, target_is_directory=True)
        with self.assertRaises(ValueError): install_skill.install(self.target, self.source)

    def test_traversal_and_upstream_source_rejected(self):
        for path in ('../outside', 'vendor/cc-clean/cc-clean/scripts/local_state.py'):
            (self.source / 'release-files.json').write_text(json.dumps({'files': [path]}))
            with self.assertRaises(ValueError): install_skill.install(self.target, self.source)
            self.assertFalse(self.target.exists())

    def test_install_cannot_overlap_checkout(self):
        with self.assertRaises(ValueError): install_skill.install(self.source / 'nested', self.source)


if __name__ == '__main__':
    unittest.main()
