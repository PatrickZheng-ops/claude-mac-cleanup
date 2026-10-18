#!/usr/bin/env python3
"""Synthetic tests only. Temporary fixtures stay beneath this scripts directory."""
import contextlib
import io
import json
import os
from pathlib import Path
import sqlite3
import stat
import tempfile
import unittest
from unittest import mock

import audit_tools as a


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='.test-fixtures-', dir=Path(__file__).parent)
        self.base = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def directory(self, name):
        p = self.base / name
        p.mkdir(parents=True)
        return p

    def database(self, path, sql):
        path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(str(path)) as con:
            con.executescript(sql)
        return path

    def jsonfile(self, path, data):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data), encoding='utf-8')
        return path

    def test_domain_boundaries(self):
        for host in ('claude.ai', '.claude.ai', 'a.claude.ai', 'A.CLAUDE.AI.'):
            self.assertTrue(a.host_matches(host, a.DEFAULT_DOMAINS), host)
        for host in ('evilclaude.ai', 'claude.ai.evil.test', 'claude-ai.test', '', None,
                     'https://a.claude.ai', 'bad..claude.ai'):
            self.assertFalse(a.host_matches(host, a.DEFAULT_DOMAINS), host)
        self.assertTrue(a.url_matches('https://claude.ai/login?token=SECRET#sensitive', a.DEFAULT_DOMAINS))
        self.assertFalse(a.url_matches('https://claude.ai@evil.test/', a.DEFAULT_DOMAINS))
        self.assertFalse(a.url_matches('file:///claude.ai', a.DEFAULT_DOMAINS))
        for invalid in ('https://claude.ai', 'claude.ai/path', 'claude.ai:443', '../claude.ai',
                        '-bad.claude.ai', 'bad-.claude.ai', 'bad..claude.ai', 'bad_label.claude.ai',
                        'a' * 64 + '.claude.ai', 'x.' * 130 + 'ai', '.claude.ai', 'claude.ai..'):
            with self.assertRaises(a.AuditError):
                a.normalize_domains([invalid])

    def test_snapshot_symlinks_hardlinks_and_private_report(self):
        root = self.directory('root')
        other = self.directory('outside')
        (other / 'secret').write_text('not scanned')
        (root / 'file').write_bytes(b'abcd')
        os.link(root / 'file', root / 'hardlink')
        os.symlink(other, root / 'escape')
        report = a.scan_tree(root, True)
        self.assertEqual(report['summary']['regular_file_entries'], 2)
        self.assertEqual(report['summary']['unique_regular_file_inodes'], 1)
        self.assertEqual(report['summary']['regular_file_logical_bytes_unique'], 4)
        self.assertEqual(report['summary']['regular_file_allocated_bytes_unique'], (root / 'file').stat().st_blocks * 512)
        paths = {r['path'] for r in report['entries']}
        self.assertIn('escape', paths)
        self.assertNotIn('escape/secret', paths)
        self.assertEqual(report['summary']['sha256_files'], 2)
        out = self.base / 'snapshot.json'
        a.write_new(out, report, [root])
        self.assertEqual(stat.S_IMODE(out.stat().st_mode), 0o600)
        with self.assertRaises(a.AuditError):
            a.scan_tree(root / 'escape')

    def test_output_guards(self):
        root = self.directory('root')
        with self.assertRaises(a.AuditError):
            a.write_new(root / 'out.json', {}, [root])
        out = self.base / 'already.json'
        a.write_new(out, {'safe': True})
        with self.assertRaises(a.AuditError):
            a.write_new(out, {'overwritten': True})
        self.assertEqual(json.loads(out.read_text()), {'safe': True})
        link = self.base / 'link.json'
        os.symlink(out, link)
        with self.assertRaises(a.AuditError):
            a.write_new(link, {})
        os.symlink(root, self.base / 'linked-dir')
        with self.assertRaises(a.AuditError):
            a.write_new(self.base / 'linked-dir' / 'out.json', {})
        self.assertFalse((root / 'out.json').exists())

    def test_compare_changes_and_hash_limits(self):
        root = self.directory('root')
        (root / 'same').write_bytes(b'same')
        (root / 'gone').write_bytes(b'gone')
        (root / '.DS_Store').write_bytes(b'old')
        before = a.scan_tree(root, True)
        (root / 'gone').unlink()
        (root / 'added').write_bytes(b'new')
        (root / '.DS_Store').write_bytes(b'new')
        after = a.scan_tree(root)
        report = a.compare_snapshots(before, after)
        rows = {r['path']: r for r in report['changes']}
        self.assertEqual(rows['gone']['change'], 'missing')
        self.assertEqual(rows['added']['change'], 'added')
        self.assertEqual(rows['.DS_Store']['category'], 'finder_metadata')
        self.assertGreaterEqual(report['summary']['hash_comparisons']['after_absent'], 1)
        self.assertEqual(report['summary']['finder_metadata_changes'], 1)
        after['root'] = str(self.base / 'other')
        with self.assertRaises(a.AuditError):
            a.compare_snapshots(before, after)

    def test_duplicates_same_size_different_hash_and_links(self):
        copies = self.directory('copies')
        originals = self.directory('originals')
        (copies / 'matched').write_bytes(b'abcd')
        (copies / 'different').write_bytes(b'wxyz')
        (copies / 'no_size').write_bytes(b'longer')
        (originals / 'original').write_bytes(b'abcd')
        os.symlink(originals / 'original', copies / 'ignored-symlink')
        report = a.duplicates(copies, [originals])
        self.assertEqual(report['summary']['matched_copy_entries'], 1)
        self.assertEqual(report['summary']['matched_copy_logical_bytes'], 4)
        self.assertEqual(report['summary']['unmatched_copy_entries'], 2)
        self.assertEqual(report['matches'][0]['originals'][0]['path'], 'original')
        self.assertTrue(report['summary']['complete'])
        with self.assertRaises(a.AuditError):
            a.duplicates(copies, [self.base])

    def test_duplicates_permission_failure_is_incomplete(self):
        copies = self.directory('copies')
        originals = self.directory('originals')
        (copies / 'f').write_bytes(b'abcd')
        (originals / 'f').write_bytes(b'abcd')
        real_digest = a.digest_relative
        def denied(root, rel, expected):
            if str(root) == str(originals):
                raise PermissionError(13, 'Permission denied')
            return real_digest(root, rel, expected)
        with mock.patch.object(a, 'digest_relative', side_effect=denied):
            report = a.duplicates(copies, [originals])
        self.assertFalse(report['summary']['complete'])
        self.assertEqual(report['summary']['errors'], 1)
        self.assertEqual(report['unmatched'][0]['status'], 'hash_read_failed')
        self.assertIn('NOT mean useless', report['summary']['interpretation'])

    def test_cookie_partition_and_no_secret_output(self):
        db = self.database(self.base / 'Cookies', '''
        CREATE TABLE cookies(host_key TEXT, top_frame_site_key TEXT, value TEXT, encrypted_value BLOB);
        INSERT INTO cookies VALUES('.claude.ai','chrome-extension://fcoeoabgfenejglbffodgkkbkcdhcgfn','COOKIE_SECRET',X'11112222');
        INSERT INTO cookies VALUES('a.claude.ai','https://unrelated.test/?secret=HIDDEN','COOKIE_SECRET',X'11112222');
        INSERT INTO cookies VALUES('claude.ai','','COOKIE_SECRET',X'11112222');
        INSERT INTO cookies VALUES('evilclaude.ai','','COOKIE_SECRET',X'11112222');
        INSERT INTO cookies VALUES('claude.ai.evil.test','','COOKIE_SECRET',X'11112222');
        ''')
        report = a.cookie_check(db, a.DEFAULT_DOMAINS)
        self.assertEqual(report['target_cookie_count'], 3)
        self.assertEqual(report['target_partitioned_cookie_count'], 2)
        self.assertEqual(report['partition_categories']['official_claude_extension'], 1)
        raw = json.dumps(report)
        for value in ('COOKIE_SECRET', 'HIDDEN', 'unrelated.test', '11112222'):
            self.assertNotIn(value, raw)

    def test_history_download_unique_id_and_chain_count(self):
        db = self.database(self.base / 'History', '''
        CREATE TABLE urls(id INTEGER, url TEXT);
        CREATE TABLE visits(id INTEGER, url INTEGER);
        CREATE TABLE downloads(id INTEGER, target_path TEXT);
        CREATE TABLE downloads_url_chains(id INTEGER, chain_index INTEGER, url TEXT);
        INSERT INTO urls VALUES(1,'https://claude.ai/login?code=SECRET');
        INSERT INTO urls VALUES(2,'https://a.claude.ai/new');
        INSERT INTO urls VALUES(3,'https://claude.ai.evil.test/');
        INSERT INTO visits VALUES(1,1),(2,1),(3,2),(4,3);
        INSERT INTO downloads VALUES(17,'');
        INSERT INTO downloads_url_chains VALUES(17,0,'https://claude.ai/a?code=SECRET');
        INSERT INTO downloads_url_chains VALUES(17,1,'https://downloads.claude.ai/b');
        INSERT INTO downloads_url_chains VALUES(17,2,'https://claude.ai/c');
        ''')
        report = a.history_check(db, a.DEFAULT_DOMAINS)
        self.assertEqual(report['urls']['target_url_count'], 2)
        self.assertEqual(report['visits']['target_visit_count'], 3)
        self.assertEqual(report['downloads']['target_chain_row_count'], 3)
        self.assertEqual(report['downloads']['target_unique_download_ids'], 1)
        self.assertEqual(report['downloads']['matching_download_records'], 1)
        self.assertNotIn('SECRET', json.dumps(report))
        self.assertNotIn('https://', json.dumps(report))

    def test_missing_schema_locked_and_missing_database(self):
        empty = self.database(self.base / 'empty', 'CREATE TABLE unrelated(x);')
        self.assertEqual(a.cookie_check(empty, a.DEFAULT_DOMAINS)['status'], 'unsupported_schema')
        self.assertEqual(a.history_check(empty, a.DEFAULT_DOMAINS)['urls']['status'], 'unsupported_schema')
        self.assertEqual(a.login_check(empty, a.DEFAULT_DOMAINS)['status'], 'unsupported_schema')
        self.assertEqual(a.cookie_check(self.base / 'missing', a.DEFAULT_DOMAINS)['status'], 'missing')
        db = self.database(self.base / 'locked', 'CREATE TABLE cookies(host_key,top_frame_site_key);')
        holder = sqlite3.connect(str(db))
        try:
            holder.execute('BEGIN EXCLUSIVE')
            self.assertEqual(a.cookie_check(db, a.DEFAULT_DOMAINS)['status'], 'locked')
        finally:
            holder.rollback(); holder.close()
        with mock.patch.object(a, 'safe_path', side_effect=PermissionError(13, 'Permission denied')):
            self.assertEqual(a.cookie_check(db, a.DEFAULT_DOMAINS)['status'], 'permission_denied')

    def test_readonly_connection_rejects_sql_writes_and_wal_sidecar_creation(self):
        db = self.database(self.base / 'db', 'CREATE TABLE t(x);')
        with a.ro_db(db) as con:
            with self.assertRaises(sqlite3.OperationalError):
                con.execute('INSERT INTO t VALUES(1)')
        Path(str(db) + '-wal').write_bytes(b'fixture')
        result = a.cookie_check(db, a.DEFAULT_DOMAINS)
        self.assertEqual(result['status'], 'wal_or_journal_present_unverified')
        self.assertFalse(Path(str(db) + '-shm').exists())

    def test_json_chrome_filters_profiles_and_symlinks(self):
        root = self.directory('Chrome')
        default = root / 'Default'; default.mkdir()
        (root / 'Profile 2').mkdir()
        outside = self.directory('outside')
        os.symlink(outside, root / 'Profile 8')
        self.jsonfile(root / 'Local State', {'profile': {'info_cache': {
            'Default': {'user_name': 'PRIVATE_EMAIL'}, 'Profile 2': {},
            '../outside': {}, str(outside): {}, 'Profile 99': {}}}})
        self.jsonfile(default / 'Bookmarks', {'roots': {'bookmark_bar': {'children': [
            {'type': 'url', 'url': 'https://claude.ai/new?secret=PRIVATE_QUERY'},
            {'type': 'url', 'url': 'https://notclaude.ai/'},
            {'type': 'url', 'url': 'https://a.claude.ai/new'}]}}})
        self.jsonfile(default / 'Preferences', {'profile': {'content_settings': {'exceptions': {
            'cookies': {'https://[*.]claude.ai:443,*': {'some_secret': 'PRIVATE_SECRET'},
                        'https://claude.ai.evil.test,*': {}, '[*.]anthropic.com,*': {}},
            'site_engagement': {'https://claude.ai:443,*': {}}}}}})
        idir = default / 'IndexedDB'; idir.mkdir()
        for n in ('https_claude.ai_0.indexeddb.leveldb', 'https_a.claude.ai_0.indexeddb.blob',
                  'https_evilclaude.ai_0.indexeddb.leveldb', 'https_claude.ai.evil.test_0.indexeddb.leveldb',
                  'https_claude.ai_0.indexeddb.leveldb-secret=PRIVATE_QUERY'):
            (idir / n).mkdir()
        os.symlink(outside, idir / 'https_anthropic.com_0.indexeddb.leveldb')
        report = a.chrome_audit(root, a.DEFAULT_DOMAINS)
        self.assertEqual(report['summary']['profiles'], 4)
        result = next(p for p in report['profiles'] if p['profile'] == 'Default')
        self.assertEqual(result['bookmarks']['target_bookmark_count'], 2)
        self.assertEqual(result['preferences']['target_key_count'], 3)
        self.assertEqual(result['indexeddb']['target_origin_store_count'], 2)
        self.assertEqual(result['indexeddb']['symlink_entries_skipped'], 1)
        self.assertFalse(report['summary']['complete'])
        raw = json.dumps(report)
        for secret in ('PRIVATE_EMAIL', 'PRIVATE_SECRET', 'PRIVATE_QUERY', 'evilclaude.ai'):
            self.assertNotIn(secret, raw)
        self.assertEqual(next(p for p in report['profiles'] if p['profile'] == 'Profile 99')['status'], 'missing')

    def test_unsupported_partition_and_download_schema_not_zero(self):
        cookie = self.database(self.base / 'old-cookies', "CREATE TABLE cookies(host_key); INSERT INTO cookies VALUES('claude.ai');")
        result = a.cookie_check(cookie, a.DEFAULT_DOMAINS)
        self.assertEqual(result['status'], 'partially_unsupported_schema')
        self.assertEqual(result['target_cookie_count'], 1)
        self.assertIsNone(result['target_partitioned_cookie_count'])
        history = self.database(self.base / 'old-history', "CREATE TABLE downloads_url_chains(id,url); INSERT INTO downloads_url_chains VALUES(1,'https://claude.ai/a');")
        result = a.history_check(history, a.DEFAULT_DOMAINS)
        self.assertEqual(result['downloads']['downloads_table']['status'], 'unsupported_schema')
        self.assertNotIn('matching_download_records', result['downloads'])

    def test_changed_file_rejected_for_hash(self):
        root = self.directory('root')
        path = root / 'file'; path.write_bytes(b'original')
        entry = next(r for r in a.scan_tree(root)['entries'] if r['path'] == 'file')
        path.write_bytes(b'changed')
        with self.assertRaises(a.AuditError):
            a.digest_relative(root, 'file', entry)
        external = self.directory('external')
        os.symlink(external, root / 'subdir')
        with self.assertRaises(OSError):
            a.digest_relative(root, 'subdir/file', entry)

    def complete_profile_fixture(self, root, name='Default'):
        profile = root / name
        profile.mkdir(parents=True, exist_ok=True)
        self.database(profile / 'Cookies', "CREATE TABLE cookies(host_key,top_frame_site_key);")
        self.database(profile / 'History', "CREATE TABLE urls(id,url); CREATE TABLE visits(id,url); CREATE TABLE downloads(id); CREATE TABLE downloads_url_chains(id,url);")
        for db in ('Login Data', 'Login Data For Account'):
            self.database(profile / db, "CREATE TABLE logins(origin_url,action_url,signon_realm);")
        self.jsonfile(profile / 'Bookmarks', {'roots': {}})
        self.jsonfile(profile / 'Preferences', {'profile': {'content_settings': {'exceptions': {}}}})
        (profile / 'IndexedDB').mkdir()
        return profile

    def test_wal_existing_shm_is_not_modified_or_connected(self):
        db = self.base / 'wal-db'
        con = sqlite3.connect(str(db))
        con.execute('PRAGMA journal_mode=WAL')
        con.execute('PRAGMA wal_autocheckpoint=0')
        con.execute('CREATE TABLE cookies(host_key,top_frame_site_key)')
        con.execute("INSERT INTO cookies VALUES('claude.ai','')")
        con.commit()
        wal = Path(str(db) + '-wal'); shm = Path(str(db) + '-shm')
        wal_bytes, shm_bytes = wal.read_bytes(), shm.read_bytes()
        con.close()
        wal.write_bytes(wal_bytes)
        shm.write_bytes(bytes(len(shm_bytes)))
        before = {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in (db, wal, shm)}
        with mock.patch.object(a.sqlite3, 'connect', side_effect=AssertionError('must not connect WAL')):
            result = a.cookie_check(db, a.DEFAULT_DOMAINS)
        self.assertEqual(result['status'], 'wal_or_journal_present_unverified')
        self.assertNotIn('target_cookie_count', result)
        for path, (content, mtime) in before.items():
            self.assertEqual(path.read_bytes(), content)
            self.assertEqual(path.stat().st_mtime_ns, mtime)

    def test_wal_header_without_sidecars_is_unverified(self):
        db = self.base / 'wal-header-db'
        con = sqlite3.connect(str(db))
        con.execute('PRAGMA journal_mode=WAL')
        con.execute('CREATE TABLE cookies(host_key,top_frame_site_key)')
        con.commit()
        con.execute('PRAGMA wal_checkpoint(TRUNCATE)').fetchall()
        con.close()
        # Synthetic fixture: emulate a closed WAL database with no sidecars.
        for suffix in ('-wal', '-shm'):
            Path(str(db) + suffix).unlink(missing_ok=True)
        self.assertFalse(Path(str(db) + '-wal').exists())
        self.assertFalse(Path(str(db) + '-shm').exists())
        content = db.read_bytes()
        self.assertEqual(content[18:20], b'\x02\x02')
        with mock.patch.object(a.sqlite3, 'connect', side_effect=AssertionError('must not connect WAL header')):
            result = a.cookie_check(db, a.DEFAULT_DOMAINS)
        self.assertEqual(result['status'], 'wal_mode_unverified')
        self.assertFalse(Path(str(db) + '-wal').exists())
        self.assertFalse(Path(str(db) + '-shm').exists())
        self.assertEqual(content, db.read_bytes())

    def test_any_journal_or_shm_presence_prevents_connection(self):
        for sidecar in ('-shm', '-journal'):
            db = self.database(self.base / ('db' + sidecar), 'CREATE TABLE cookies(host_key,top_frame_site_key);')
            Path(str(db) + sidecar).write_bytes(b'')
            with mock.patch.object(a.sqlite3, 'connect', side_effect=AssertionError('must not connect sidecar')):
                self.assertEqual(a.cookie_check(db, a.DEFAULT_DOMAINS)['status'], 'wal_or_journal_present_unverified')

    def test_output_parent_swapped_after_validation_does_not_write_source(self):
        source = self.directory('source')
        output = self.directory('output')
        moved = self.base / 'moved'
        real_check = a.check_output
        def swap(path, roots):
            result = real_check(path, roots)
            output.rename(moved)
            os.symlink(source, output)
            return result
        with mock.patch.object(a, 'check_output', side_effect=swap):
            with self.assertRaises((a.AuditError, OSError)):
                a.write_new(output / 'report.json', {}, [source])
        self.assertFalse((source / 'report.json').exists())
        self.assertFalse((moved / 'report.json').exists())

    def test_output_ancestor_swap_after_parent_pinned_cannot_redirect_write(self):
        source = self.directory('source')
        ancestor = self.directory('ancestor')
        parent = ancestor / 'output'; parent.mkdir()
        (source / 'output').mkdir()
        moved = self.base / 'moved'
        real_open = a.os.open
        swapped = False
        def swap(path, flags, mode=0o777, *, dir_fd=None):
            nonlocal swapped
            if path == 'report.json' and flags & os.O_CREAT and not swapped:
                swapped = True
                ancestor.rename(moved)
                os.symlink(source, ancestor)
            return real_open(path, flags, mode, dir_fd=dir_fd)
        with mock.patch.object(a.os, 'open', side_effect=swap):
            with self.assertRaises((a.AuditError, OSError)):
                a.write_new(parent / 'report.json', {'safe': True}, [source])
        self.assertTrue(swapped)
        self.assertFalse((source / 'output' / 'report.json').exists())
        self.assertTrue((moved / 'output' / 'report.json').exists())

    def test_indexeddb_unknown_or_link_alone_makes_complete_false(self):
        for invalid in ('unknown-layout', 'symlink'):
            root = self.directory('Chrome-' + invalid)
            profile = self.complete_profile_fixture(root)
            self.jsonfile(root / 'Local State', {'profile': {'info_cache': {'Default': {}}}})
            self.assertTrue(a.chrome_audit(root, a.DEFAULT_DOMAINS)['summary']['complete'])
            if invalid == 'symlink':
                outside = self.directory('outside-' + invalid)
                os.symlink(outside, profile / 'IndexedDB' / 'https_claude.ai_0.indexeddb.leveldb')
            else:
                (profile / 'IndexedDB' / 'unknown-format').mkdir()
            result = a.chrome_audit(root, a.DEFAULT_DOMAINS)
            self.assertFalse(result['summary']['complete'])
            self.assertEqual(result['profiles'][0]['indexeddb']['status'], 'partially_unsupported_layout')
            self.assertEqual(set(result['summary']['status_counts']), {'ok', 'absent', 'partially_unsupported_layout'})

    def test_custom_indexed_unindexed_system_guest_and_private_labels(self):
        root = self.directory('Chrome-custom')
        names = ['Default', 'Profile Work', 'private@example.com', 'Unindexed secret-token-123', 'System Profile', 'Guest Profile']
        for name in names:
            self.complete_profile_fixture(root, name)
        self.jsonfile(root / 'Local State', {'profile': {'info_cache': {'Default': {}, 'Profile Work': {}, 'private@example.com': {}}}})
        result = a.chrome_audit(root, a.DEFAULT_DOMAINS)
        self.assertEqual(result['summary']['profiles'], 6)
        self.assertTrue(result['summary']['complete'])
        self.assertEqual(len([p for p in result['profiles'] if p['profile_kind'] == 'custom']), 3)
        self.assertEqual({p['profile_kind'] for p in result['profiles']}, {'standard', 'custom', 'system', 'guest'})
        raw = json.dumps(result)
        for name in ('Profile Work', 'private@example.com', 'Unindexed secret-token-123'):
            self.assertNotIn(name, raw)
        self.assertTrue(any('directory_scan_marker' in p['discovery_sources'] for p in result['profiles']))

    def test_unsafe_local_state_keys_make_scan_incomplete(self):
        root = self.directory('Chrome-unsafe')
        self.complete_profile_fixture(root)
        self.jsonfile(root / 'Local State', {'profile': {'info_cache': {'Default': {}, '../escape-secret': {}, '/absolute-secret': {}, 'x\\evil': {}, '..': {}}}})
        result = a.chrome_audit(root, a.DEFAULT_DOMAINS)
        self.assertEqual(result['summary']['profiles'], 1)
        self.assertFalse(result['summary']['complete'])
        self.assertEqual(result['warnings'][0]['status'], 'unsafe_profile_keys_ignored')
        self.assertEqual(result['warnings'][0]['count'], 4)
        self.assertNotIn('escape-secret', json.dumps(result))

    def test_login_without_password_selection(self):
        db = self.database(self.base / 'Login Data', '''
        CREATE TABLE logins(origin_url,action_url,signon_realm,password_value);
        INSERT INTO logins VALUES('https://claude.ai/login?x=SECRET','','https://claude.ai/','SECRET_PASSWORD');
        INSERT INTO logins VALUES('https://claude.ai.evil.test/','','','SECRET_PASSWORD');
        ''')
        result = a.login_check(db, a.DEFAULT_DOMAINS)
        self.assertEqual(result['target_login_record_count'], 1)
        self.assertNotIn('SECRET', json.dumps(result))

    def test_cli_summary_only_and_overwrite_exit(self):
        root = self.directory('root')
        (root / 'document-with-sensitive-name').write_bytes(b'contents')
        out = self.base / 'report.json'
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = a.main(['snapshot', '--root', str(root), '--out', str(out), '--hash'])
        self.assertEqual(code, 0)
        self.assertNotIn('document-with-sensitive-name', stdout.getvalue())
        self.assertNotIn('contents', stdout.getvalue())
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = a.main(['snapshot', '--root', str(root), '--out', str(out)])
        self.assertEqual(code, 1)


if __name__ == '__main__':
    unittest.main(verbosity=2)
