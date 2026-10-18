#!/usr/bin/env python3
"""Read-only local Claude cleanup evidence. No deletion, app, or network actions.

Reports are newly created with mode 0600. Source trees and browser databases are
never changed. SQLite read-only connections may fail while Chrome owns a lock;
that is evidence of an incomplete check, not a zero-result check.
"""
import argparse
import collections
import contextlib
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import sys
import urllib.parse

VERSION = 1
DEFAULT_DOMAINS = ('claude.ai', 'claude.com', 'anthropic.com')
EXTENSION = 'fcoeoabgfenejglbffodgkkbkcdhcgfn'
NOFOLLOW = getattr(os, 'O_NOFOLLOW', 0)
DIRECTORY = getattr(os, 'O_DIRECTORY', 0)


class AuditError(ValueError):
    pass


class UnverifiedDatabase(sqlite3.OperationalError):
    def __init__(self, status):
        super().__init__(status)
        self.audit_status = status


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def safe_path(path, must_exist=True):
    """Reject symbolic links in every existing path component, including roots."""
    p = Path(os.path.abspath(os.path.expanduser(str(path))))
    current = Path(p.anchor)
    for part in p.parts[1:]:
        current /= part
        try:
            s = current.lstat()
        except FileNotFoundError:
            if must_exist:
                raise
            continue
        if stat.S_ISLNK(s.st_mode):
            raise AuditError('Symbolic-link path component is not allowed: ' + str(current))
    if must_exist and not p.exists():
        raise FileNotFoundError(str(p))
    return p


def inside(path, root):
    try:
        Path(path).relative_to(root)
        return True
    except ValueError:
        return False


def check_output(path, roots=()):
    p = safe_path(path, must_exist=False)
    safe_path(p.parent)
    if p.exists() or p.is_symlink():
        raise AuditError('Output exists; refusing to overwrite: ' + str(p))
    for root in roots:
        if inside(p, root):
            raise AuditError('Output must be outside scanned source tree: ' + str(root))
    return p


@contextlib.contextmanager
def directory_fd(path):
    """Pin each ancestor through openat; never follow a substituted directory link."""
    p = Path(os.path.abspath(os.path.expanduser(str(path))))
    fd = os.open(p.anchor, os.O_RDONLY | DIRECTORY | NOFOLLOW)
    try:
        for part in p.parts[1:]:
            nxt = os.open(part, os.O_RDONLY | DIRECTORY | NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = nxt
        yield fd
    finally:
        os.close(fd)


def write_new(path, report, roots=()):
    p = check_output(path, roots)
    data = (json.dumps(report, ensure_ascii=False, indent=2) + '\n').encode('utf-8')
    with directory_fd(p.parent) as dfd:
        pinned_parent = os.fstat(dfd)
        fd = os.open(p.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | NOFOLLOW, 0o600, dir_fd=dfd)
        with os.fdopen(fd, 'wb') as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        # A renamed pinned parent is safe from link traversal, but its original
        # pathname is no longer a verified delivery location. Do not claim it is.
        with directory_fd(p.parent) as current_fd:
            current = os.fstat(current_fd)
            if (current.st_dev, current.st_ino) != (pinned_parent.st_dev, pinned_parent.st_ino):
                raise AuditError('Output parent changed; report location is unverified')
    return p


def error_record(path, operation, exc):
    return {'path': str(path), 'operation': operation,
            'error_type': type(exc).__name__, 'errno': getattr(exc, 'errno', None),
            'reason': os.strerror(exc.errno) if getattr(exc, 'errno', None) else type(exc).__name__}


def kind(mode):
    if stat.S_ISREG(mode):
        return 'file'
    if stat.S_ISDIR(mode):
        return 'directory'
    if stat.S_ISLNK(mode):
        return 'symlink'
    return 'other'


def record(rel, s):
    return {'path': rel, 'type': kind(s.st_mode), 'size': s.st_size,
            'mtime_ns': s.st_mtime_ns, 'mode': s.st_mode, 'inode': s.st_ino,
            'dev': s.st_dev, 'allocated_bytes': getattr(s, 'st_blocks', 0) * 512}


def identity(s):
    return (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_mode)


def digest_fd(fd, expected):
    before = os.fstat(fd)
    if not stat.S_ISREG(before.st_mode) or identity(before) != identity(expected):
        raise AuditError('Source changed before hashing')
    h = hashlib.sha256()
    while True:
        b = os.read(fd, 1024 * 1024)
        if not b:
            break
        h.update(b)
    if identity(os.fstat(fd)) != identity(before):
        raise AuditError('Source changed during hashing')
    return h.hexdigest()


def digest_relative(root, rel, expected_record):
    """Open each directory using no-follow descriptors; do not follow race swaps."""
    root = safe_path(root)
    fd = os.open(str(root), os.O_RDONLY | DIRECTORY | NOFOLLOW)
    try:
        parts = Path(rel).parts
        for part in parts[:-1]:
            nxt = os.open(part, os.O_RDONLY | DIRECTORY | NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = nxt
        ffd = os.open(parts[-1], os.O_RDONLY | NOFOLLOW | getattr(os, 'O_NONBLOCK', 0), dir_fd=fd)
        try:
            s = os.fstat(ffd)
            if any(getattr(s, attr) != expected_record[key] for attr, key in (
                    ('st_dev', 'dev'), ('st_ino', 'inode'), ('st_size', 'size'),
                    ('st_mtime_ns', 'mtime_ns'), ('st_mode', 'mode'))):
                raise AuditError('Source changed since inventory')
            return digest_fd(ffd, s)
        finally:
            os.close(ffd)
    finally:
        os.close(fd)


def scan_tree(root, with_hash=False):
    root = safe_path(root)
    if not root.is_dir():
        raise AuditError('Scan root must be a directory')
    rows, errors = [], []
    fd = os.open(str(root), os.O_RDONLY | DIRECTORY | NOFOLLOW)
    try:
        rows.append(record('.', os.fstat(fd)))

        def walk(dfd, prefix):
            try:
                with os.scandir(dfd) as it:
                    children = sorted(it, key=lambda e: e.name)
            except OSError as e:
                errors.append(error_record(prefix or '.', 'scandir', e))
                return
            for ent in children:
                rel = str(Path(prefix) / ent.name)
                try:
                    s = os.stat(ent.name, dir_fd=dfd, follow_symlinks=False)
                    row = record(rel, s)
                    rows.append(row)
                    if row['type'] == 'file' and with_hash:
                        try:
                            ffd = os.open(ent.name, os.O_RDONLY | NOFOLLOW | getattr(os, 'O_NONBLOCK', 0), dir_fd=dfd)
                            try:
                                row['sha256'] = digest_fd(ffd, s)
                            finally:
                                os.close(ffd)
                        except (OSError, AuditError) as e:
                            errors.append(error_record(rel, 'sha256', e))
                    elif row['type'] == 'directory':
                        cfd = os.open(ent.name, os.O_RDONLY | DIRECTORY | NOFOLLOW, dir_fd=dfd)
                        try:
                            opened = os.fstat(cfd)
                            if (opened.st_dev, opened.st_ino) != (s.st_dev, s.st_ino):
                                raise AuditError('Directory changed during scan')
                            walk(cfd, rel)
                        finally:
                            os.close(cfd)
                except (OSError, AuditError) as e:
                    errors.append(error_record(rel, 'stat_or_open', e))
        walk(fd, '')
    finally:
        os.close(fd)
    unique = {}
    for r in rows:
        if r['type'] == 'file':
            unique.setdefault((r['dev'], r['inode']), r)
    summary = {
        'entries_including_root': len(rows), 'type_counts': dict(collections.Counter(r['type'] for r in rows)),
        'regular_file_entries': sum(r['type'] == 'file' for r in rows),
        'unique_regular_file_inodes': len(unique),
        'regular_file_logical_bytes_unique': sum(r['size'] for r in unique.values()),
        'regular_file_allocated_bytes_unique': sum(r['allocated_bytes'] for r in unique.values()),
        'accounting': 'Regular files only; hard links deduplicated by device+inode. Allocated bytes use st_blocks*512; not physical free-space measurement.',
        'sha256_files': sum('sha256' in r for r in rows), 'errors': len(errors),
        'complete': not errors,
        'consistency': 'A live recursive scan is not an atomic filesystem snapshot; close writers for final verification.',
    }
    return {'schema_version': VERSION, 'kind': 'snapshot', 'created_at': now(), 'root': str(root),
            'hash_requested': with_hash, 'summary': summary, 'entries': rows, 'errors': errors}


def load_json(path):
    p = safe_path(path)
    fd = os.open(str(p), os.O_RDONLY | NOFOLLOW)
    with os.fdopen(fd, 'r', encoding='utf-8') as f:
        return json.load(f)


def compare_snapshots(before, after):
    if before.get('kind') != 'snapshot' or after.get('kind') != 'snapshot':
        raise AuditError('Inputs must be snapshot reports')
    if before.get('root') != after.get('root'):
        raise AuditError('Snapshot roots differ')
    b = {e['path']: e for e in before['entries']}
    a = {e['path']: e for e in after['entries']}
    changes = []
    hash_counts = collections.Counter()
    for name in sorted(set(b) | set(a)):
        category = 'finder_metadata' if Path(name).name == '.DS_Store' else 'other'
        if name not in b or name not in a:
            changes.append({'path': name, 'change': 'added' if name not in b else 'missing', 'category': category})
            continue
        fields = [k for k in ('type', 'size', 'mtime_ns', 'mode', 'inode', 'dev', 'allocated_bytes') if b[name].get(k) != a[name].get(k)]
        if b[name]['type'] == 'file' and a[name]['type'] == 'file':
            if 'sha256' in b[name] and 'sha256' in a[name]:
                hc = 'equal' if b[name]['sha256'] == a[name]['sha256'] else 'different'
                if hc == 'different':
                    fields.append('sha256')
            else:
                hc = ('both_absent' if 'sha256' not in b[name] and 'sha256' not in a[name]
                      else 'before_absent' if 'sha256' not in b[name] else 'after_absent')
            hash_counts[hc] += 1
        else:
            hc = 'not_regular_file_in_both'
        if fields:
            changes.append({'path': name, 'change': 'changed', 'category': category,
                            'fields': fields, 'hash_comparison': hc})
    summary = {'changes': len(changes), 'by_change': dict(collections.Counter(c['change'] for c in changes)),
               'finder_metadata_changes': sum(c['category'] == 'finder_metadata' for c in changes),
               'hash_comparisons': dict(hash_counts),
               'source_errors': len(before.get('errors', [])) + len(after.get('errors', [])),
               'complete': not before.get('errors') and not after.get('errors'),
               'interpretation': 'Missing hashes mean content equality is unverified. Metadata-only equality is not byte equality. Source scan errors make absence conclusions incomplete.'}
    return {'schema_version': VERSION, 'kind': 'comparison', 'created_at': now(), 'root': before['root'],
            'before_time': before.get('created_at'), 'after_time': after.get('created_at'),
            'summary': summary, 'changes': changes}


def duplicates(copies, originals):
    copies = safe_path(copies)
    originals = list(dict.fromkeys(str(safe_path(p)) for p in originals))
    if not originals:
        raise AuditError('At least one original root is required')
    for original in originals:
        if inside(copies, original) or inside(original, copies):
            raise AuditError('Copies and original trees must not overlap')
    for i, p in enumerate(originals):
        if any(inside(p, q) or inside(q, p) for q in originals[:i]):
            raise AuditError('Original trees must not overlap')
    cs = scan_tree(copies)
    osnaps = [scan_tree(p) for p in originals]
    errors = [{'root': str(copies), **e} for e in cs['errors']]
    by_size = collections.defaultdict(list)
    for snap in osnaps:
        errors.extend({'root': snap['root'], **e} for e in snap['errors'])
        for r in snap['entries']:
            if r['type'] == 'file':
                by_size[r['size']].append((snap['root'], r))
    cache = {}
    matches, unmatched = [], []

    def hashed(root, r):
        key = (r['dev'], r['inode'], r['size'], r['mtime_ns'])
        if key not in cache:
            try:
                cache[key] = digest_relative(root, r['path'], r)
            except (OSError, AuditError) as e:
                errors.append({'root': str(root), **error_record(r['path'], 'sha256', e)})
                cache[key] = None
        return cache[key]

    for r in cs['entries']:
        if r['type'] != 'file':
            continue
        candidates = by_size.get(r['size'], [])
        if not candidates:
            unmatched.append({'path': r['path'], 'size': r['size'], 'status': 'no_same_size_candidate_in_readable_inventory'})
            continue
        ch = hashed(copies, r)
        found = []
        candidate_failure = False
        if ch is not None:
            for root, original in candidates:
                oh = hashed(root, original)
                candidate_failure |= oh is None
                if oh is not None and oh == ch:
                    found.append({'root': root, 'path': original['path']})
        if found:
            matches.append({'path': r['path'], 'size': r['size'], 'sha256': ch, 'originals': found})
        else:
            unmatched.append({'path': r['path'], 'size': r['size'],
                              'status': 'hash_read_failed' if ch is None or candidate_failure else 'no_equal_hash_in_readable_candidates'})
    summary = {'copy_file_entries': cs['summary']['regular_file_entries'],
               'matched_copy_entries': len(matches), 'matched_copy_logical_bytes': sum(r['size'] for r in matches),
               'unmatched_copy_entries': len(unmatched), 'unmatched_copy_logical_bytes': sum(r['size'] for r in unmatched),
               'errors': len(errors), 'complete': not errors,
               'interpretation': 'Matching size+SHA-256 is evidence of identical bytes at scan time. Unmatched does NOT mean useless, globally unique, or safe to delete; unreadable paths make search incomplete. Counts/bytes are per copy path, not deduplicated disk usage.'}
    return {'schema_version': VERSION, 'kind': 'duplicates', 'created_at': now(), 'copies_root': str(copies),
            'original_roots': originals, 'summary': summary, 'matches': matches, 'unmatched': unmatched,
            'errors': errors}


def canonical_host(value, allow_cookie_dot=False):
    """Strict ASCII DNS labels; a single terminal root dot is accepted."""
    if not isinstance(value, str):
        return None
    host = value.strip().lower()
    if allow_cookie_dot and host.startswith('.'):
        host = host[1:]
    if host.endswith('.'):
        host = host[:-1]
    if not host or len(host) > 253:
        return None
    labels = host.split('.')
    if len(labels) < 2:
        return None
    label_re = r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?'
    if any(not re.fullmatch(label_re, label) for label in labels):
        return None
    return host


def normalize_domains(domains):
    result = []
    for domain in domains:
        host = canonical_host(domain)
        if host is None:
            raise AuditError('Domain must contain valid DNS labels, without scheme, path, query, port, or wildcard')
        result.append(host)
    if not result:
        raise AuditError('At least one target domain is required')
    return tuple(sorted(set(result)))


def host_matches(host, domains):
    h = canonical_host(host, allow_cookie_dot=True)
    if h is None:
        return False
    return any(h == d or h.endswith('.' + d) for d in domains)


def url_host(value):
    try:
        u = urllib.parse.urlsplit(value)
        if u.scheme.lower() not in ('http', 'https'):
            return None
        return u.hostname
    except (ValueError, TypeError):
        return None


def url_matches(value, domains):
    return host_matches(url_host(value), domains)


def db_failure(exc):
    if isinstance(exc, UnverifiedDatabase):
        return {'status': exc.audit_status}
    if isinstance(exc, PermissionError):
        return {'status': 'permission_denied'}
    if isinstance(exc, FileNotFoundError):
        return {'status': 'missing'}
    if isinstance(exc, AuditError):
        return {'status': 'unsafe_path'}
    msg = str(exc).lower()
    if 'locked' in msg or 'busy' in msg:
        return {'status': 'locked'}
    if 'no such table' in msg or 'no such column' in msg:
        return {'status': 'unsupported_schema'}
    if 'permission' in msg or 'readonly database' in msg:
        return {'status': 'permission_denied_or_readonly_wal_unavailable'}
    return {'status': 'read_error', 'error_type': type(exc).__name__}


@contextlib.contextmanager
def ro_db(path):
    p = safe_path(path)
    if not p.is_file():
        raise AuditError('Expected database file')
    # mode=ro does NOT guarantee sidecar immutability. SQLite may rebuild even
    # an existing SHM. Refuse all journal/WAL sidecars and WAL-header databases.
    # We never checkpoint, copy, repair, remove sidecars, or use immutable=1.
    with directory_fd(p.parent) as dfd:
        for suffix in ('-wal', '-shm', '-journal'):
            try:
                os.stat(p.name + suffix, dir_fd=dfd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise UnverifiedDatabase('wal_or_journal_present_unverified')
        fd = os.open(p.name, os.O_RDONLY | NOFOLLOW, dir_fd=dfd)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise AuditError('Expected regular database file')
            header = os.read(fd, 100)
        finally:
            os.close(fd)
    if header[:16] != b'SQLite format 3\x00' or len(header) < 100:
        raise UnverifiedDatabase('unsupported_database_header')
    if header[18] == 2 or header[19] == 2:
        raise UnverifiedDatabase('wal_mode_unverified')
    if header[18:20] != b'\x01\x01':
        raise UnverifiedDatabase('unsupported_database_header')
    # Normal browser shutdown and no concurrent writers remain prerequisites.
    # A live external writer can change modes after this preflight check.
    con = sqlite3.connect(p.as_uri() + '?mode=ro', uri=True, timeout=0)
    try:
        con.execute('PRAGMA query_only=ON')
        yield con
    finally:
        con.close()


def columns(con, table):
    # Only caller-controlled fixed table names are passed here.
    return {r[1] for r in con.execute('PRAGMA table_info("' + table + '")')}


def require(con, table, names):
    cols = columns(con, table)
    if not set(names).issubset(cols):
        raise sqlite3.OperationalError('no such column or table in supported schema')
    return cols


def cookie_check(path, domains):
    try:
        with ro_db(path) as con:
            cols = require(con, 'cookies', ('host_key',))
            partition = next((x for x in ('top_frame_site_key', 'partition_key') if x in cols), None)
            sql = 'SELECT host_key' + (', "' + partition + '"' if partition else '') + ' FROM cookies'
            total, partitioned, counts = 0, 0, collections.Counter()
            for row in con.execute(sql):
                if host_matches(row[0], domains):
                    total += 1
                    if partition and row[1]:
                        partitioned += 1
                        # Report only the partition type, never a URL or partition contents.
                        value = str(row[1])
                        if value.startswith('chrome-extension://'):
                            category = 'official_claude_extension' if value.rstrip('/') == 'chrome-extension://' + EXTENSION else 'other_extension'
                        elif value.startswith(('http://', 'https://')):
                            category = 'target_site' if url_matches(value, domains) else 'other_site'
                        else:
                            category = 'opaque_or_unknown'
                        counts[category] += 1
            return {'status': 'ok' if partition else 'partially_unsupported_schema', 'target_cookie_count': total,
                    'partition_schema': 'supported' if partition else 'column_absent_unverified',
                    'target_partitioned_cookie_count': partitioned if partition else None,
                    'partition_categories': dict(counts)}
    except (OSError, sqlite3.Error, AuditError) as e:
        return db_failure(e)


def history_check(path, domains):
    report = {}
    try:
        with ro_db(path) as con:
            try:
                require(con, 'urls', ('id', 'url'))
                target = {r[0] for r in con.execute('SELECT id,url FROM urls') if url_matches(r[1], domains)}
                report['urls'] = {'status': 'ok', 'target_url_count': len(target)}
                try:
                    require(con, 'visits', ('url',))
                    count = sum(1 for r in con.execute('SELECT url FROM visits') if r[0] in target)
                    report['visits'] = {'status': 'ok', 'target_visit_count': count}
                except sqlite3.Error as e:
                    report['visits'] = db_failure(e)
            except sqlite3.Error as e:
                report['urls'] = db_failure(e)
                report['visits'] = {'status': 'dependency_unavailable'}
            try:
                require(con, 'downloads_url_chains', ('id', 'url'))
                matched = [r[0] for r in con.execute('SELECT id,url FROM downloads_url_chains') if url_matches(r[1], domains)]
                ids = set(matched)
                download = {'status': 'ok', 'target_chain_row_count': len(matched), 'target_unique_download_ids': len(ids)}
                try:
                    require(con, 'downloads', ('id',))
                    allids = {r[0] for r in con.execute('SELECT id FROM downloads')}
                    download.update({'downloads_table': {'status': 'ok'}, 'matching_download_records': len(ids & allids), 'orphan_target_chain_ids': len(ids - allids)})
                except sqlite3.Error as e:
                    download['downloads_table'] = db_failure(e)
                report['downloads'] = download
            except sqlite3.Error as e:
                report['downloads'] = db_failure(e)
    except (OSError, sqlite3.Error, AuditError) as e:
        status = db_failure(e)
        return {'urls': status.copy(), 'visits': status.copy(), 'downloads': status.copy()}
    return report


def login_check(path, domains):
    try:
        with ro_db(path) as con:
            cols = require(con, 'logins', ())
            if not cols:
                raise sqlite3.OperationalError('no such table logins')
            selected = [x for x in ('origin_url', 'action_url', 'signon_realm') if x in cols]
            if not selected:
                raise sqlite3.OperationalError('no such column login URL')
            count = sum(any(url_matches(v, domains) for v in r) for r in con.execute('SELECT ' + ','.join(selected) + ' FROM logins'))
            return {'status': 'ok', 'target_login_record_count': count}
    except (OSError, sqlite3.Error, AuditError) as e:
        return db_failure(e)


def json_source(path):
    try:
        return load_json(path), None
    except (OSError, AuditError) as e:
        return None, db_failure(e)
    except (json.JSONDecodeError, UnicodeError):
        return None, {'status': 'invalid_json'}


def bookmark_check(path, domains):
    data, failure = json_source(path)
    if failure:
        return failure
    if not isinstance(data, dict) or not isinstance(data.get('roots'), dict):
        return {'status': 'unsupported_schema'}
    count = 0
    def walk(node):
        nonlocal count
        if isinstance(node, dict):
            if node.get('type') == 'url' and url_matches(node.get('url'), domains):
                count += 1
            for value in node.values():
                if isinstance(value, (dict, list)):
                    walk(value)
        elif isinstance(node, list):
            for child in node:
                walk(child)
    walk(data['roots'])
    return {'status': 'ok', 'target_bookmark_count': count}


def preference_key_matches(key, domains):
    # Chrome ContentSettingsPattern pairs: primary,secondary. Parse host only;
    # wildcards are recognized only as leading [*.] or *., never substring matches.
    if not isinstance(key, str):
        return False
    for part in key.split(','):
        part = part.strip()
        if part in ('*', '<all_urls>'):
            continue
        candidate = part.replace('[*.]', '', 1) if part.startswith('[*.]') else part
        if '://' in candidate:
            candidate = candidate.replace('://[*.]', '://', 1).replace('://*.', '://', 1)
            try:
                host = urllib.parse.urlsplit(candidate).hostname
            except ValueError:
                continue
        else:
            candidate = candidate.removeprefix('*.') if hasattr(candidate, 'removeprefix') else (candidate[2:] if candidate.startswith('*.') else candidate)
            host = candidate.split(':', 1)[0] if '/' not in candidate else None
        if host_matches(host, domains):
            return True
    return False


def preferences_check(path, domains):
    data, failure = json_source(path)
    if failure:
        return failure
    try:
        exceptions = data['profile']['content_settings']['exceptions']
    except (KeyError, TypeError):
        return {'status': 'unsupported_schema', 'detail': 'content_settings.exceptions absent; not proof of zero preferences'}
    if not isinstance(exceptions, dict):
        return {'status': 'unsupported_schema'}
    counts = {}
    unknown = 0
    for category, entries in exceptions.items():
        if not isinstance(entries, dict):
            unknown += 1
            continue
        c = sum(preference_key_matches(key, domains) for key in entries)
        if c:
            # Category is a schema key, but suppress unexpected arbitrary content.
            safe_category = category if re.fullmatch(r'[a-z_]{1,80}', category) else '[unrecognized_category]'
            counts[safe_category] = counts.get(safe_category, 0) + c
    return {'status': 'ok' if not unknown else 'partially_unsupported_schema', 'target_keys_by_category': counts,
            'target_key_count': sum(counts.values()), 'unsupported_category_count': unknown,
            'scope': 'profile.content_settings.exceptions only; no values or complete preference URLs exported'}


def indexeddb_check(path, domains):
    try:
        p = safe_path(path)
        if not p.is_dir():
            return {'status': 'unsupported_layout'}
        targets, skipped_links, unsupported = [], 0, 0
        for ent in os.scandir(p):
            if ent.is_symlink():
                skipped_links += 1
                continue
            name = ent.name
            # Chromium origin serialization has a strict terminal store suffix.
            m = re.fullmatch(r'(https?)_([A-Za-z0-9.-]+)_([0-9]+)\.indexeddb\.(leveldb|blob)', name)
            if m and canonical_host(m.group(2)) and ent.is_dir(follow_symlinks=False):
                if host_matches(m.group(2), domains):
                    targets.append(name)
            else:
                unsupported += 1
        return {'status': 'partially_unsupported_layout' if skipped_links or unsupported else 'ok', 'target_origin_store_names': sorted(targets), 'target_origin_store_count': len(targets),
                'symlink_entries_skipped': skipped_links, 'unrecognized_entries': unsupported,
                'scope': 'Recognized http(s) serialized origin names only; store contents are not read'}
    except (OSError, AuditError) as e:
        return db_failure(e)


def extension_check(path):
    try:
        p = safe_path(path)
        return {'status': 'ok', 'official_extension_directory_exists': p.is_dir()}
    except FileNotFoundError:
        return {'status': 'absent', 'official_extension_directory_exists': False}
    except (OSError, AuditError) as e:
        return db_failure(e)


def safe_profile_component(name):
    return (isinstance(name, str) and bool(name) and name not in ('.', '..')
            and '/' not in name and '\\' not in name and not Path(name).is_absolute()
            and not any(ord(c) < 32 or ord(c) == 127 for c in name)
            and len(name.encode('utf-8')) <= 255)


def chrome_audit(user_data_dir, domains):
    root = safe_path(user_data_dir)
    domains = normalize_domains(domains)
    profiles = collections.defaultdict(set)
    warnings = []
    standard = re.compile(r'(?:Default|Profile [0-9]+)')
    special = {'System Profile': 'system', 'Guest Profile': 'guest'}
    state, failure = json_source(root / 'Local State')
    if failure:
        warnings.append({'source': 'Local State', **failure})
    else:
        try:
            cache = state['profile']['info_cache']
            if not isinstance(cache, dict):
                raise TypeError()
            rejected = 0
            for name in cache:
                if not safe_profile_component(name):
                    rejected += 1
                else:
                    profiles[name].add('local_state_index')
            if rejected:
                warnings.append({'source': 'Local State', 'status': 'unsafe_profile_keys_ignored', 'count': rejected})
        except (KeyError, TypeError):
            warnings.append({'source': 'Local State', 'status': 'unsupported_schema'})
    uninspected_links = 0
    markers = ('Preferences', 'History', 'Cookies', 'Network/Cookies',
               'Login Data', 'Login Data For Account', 'Bookmarks')
    for ent in os.scandir(root):
        name = ent.name
        if not safe_profile_component(name):
            warnings.append({'source': 'directory_scan', 'status': 'unsafe_directory_name_ignored'})
            continue
        if ent.is_symlink():
            if name in profiles or standard.fullmatch(name) or name in special:
                profiles[name].add('directory_scan_symlink')
            else:
                uninspected_links += 1
            continue
        if not ent.is_dir(follow_symlinks=False):
            continue
        if name in profiles or standard.fullmatch(name) or name in special:
            profiles[name].add('directory_scan')
            continue
        # Discover unindexed custom profiles from known file markers. Never open
        # their contents merely to discover them, and do not traverse marker links.
        for marker in markers:
            try:
                marker_path = safe_path(root / name / marker)
                if marker_path.is_file():
                    profiles[name].add('directory_scan_marker')
                    break
            except FileNotFoundError:
                continue
            except (OSError, AuditError):
                profiles[name].add('directory_scan_marker_unverified')
                break
    if uninspected_links:
        warnings.append({'source': 'directory_scan', 'status': 'uninspected_symlink_entries', 'count': uninspected_links})
    results = []
    custom_number = 0
    for name in sorted(profiles):
        if standard.fullmatch(name) or name in special:
            label = name
        else:
            custom_number += 1
            label = 'CustomProfile-' + str(custom_number).zfill(3)
        meta = {'profile': label, 'profile_kind': special.get(name, 'standard' if standard.fullmatch(name) else 'custom'),
                'discovery_sources': sorted(profiles[name])}
        profile = root / name
        try:
            safe_path(profile)
            if not profile.is_dir():
                raise AuditError('Invalid profile')
        except (OSError, AuditError) as e:
            results.append({**meta, 'status': db_failure(e)['status']})
            continue
        cookie_candidates = [profile / 'Network' / 'Cookies', profile / 'Cookies']
        # Both layouts may coexist. Inspect every existing database, never double-sum silently.
        existing = [p for p in cookie_candidates if p.exists() or p.is_symlink()]
        cookie_results = [{'relative_path': str(p.relative_to(profile)), **cookie_check(p, domains)} for p in (existing or [cookie_candidates[0]])]
        result = {**meta, 'cookies': cookie_results,
                  'history': history_check(profile / 'History', domains),
                  'passwords': {p: login_check(profile / p, domains) for p in ('Login Data', 'Login Data For Account')},
                  'bookmarks': bookmark_check(profile / 'Bookmarks', domains),
                  'preferences': preferences_check(profile / 'Preferences', domains),
                  'official_extension': extension_check(profile / 'Extensions' / EXTENSION),
                  'indexeddb': indexeddb_check(profile / 'IndexedDB', domains)}
        results.append(result)
    status_counts = collections.Counter()
    def statuses(obj):
        if isinstance(obj, dict):
            if 'status' in obj:
                status_counts[obj['status']] += 1
            for value in obj.values():
                statuses(value)
        elif isinstance(obj, list):
            for value in obj:
                statuses(value)
    statuses(results)
    statuses(warnings)
    summary = {'profiles': len(results), 'status_counts': dict(status_counts),
               'complete': bool(results) and not warnings and all(k in ('ok', 'absent') for k in status_counts),
               'interpretation': 'Missing/locked/denied/unsupported sources are unverified, not zero. No cookie values, passwords, account identities, or URL query/fragment values are exported. Browser must be closed normally for a reliable final check; this tool does not launch or stop it.'}
    return {'schema_version': VERSION, 'kind': 'chrome_audit', 'created_at': now(), 'user_data_root': str(root),
            'domains': domains, 'summary': summary, 'profiles': results, 'warnings': warnings,
            'profile_label_policy': 'Custom directory names are anonymous per-run labels. System and Guest directories, when present, are inspected; missing/unsupported records remain unverified.'}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    s = sub.add_parser('snapshot'); s.add_argument('--root', required=True); s.add_argument('--out', required=True); s.add_argument('--hash', action='store_true')
    c = sub.add_parser('compare'); c.add_argument('--before', required=True); c.add_argument('--after', required=True); c.add_argument('--out', required=True)
    d = sub.add_parser('duplicates'); d.add_argument('--copies', required=True); d.add_argument('--original', action='append', required=True); d.add_argument('--out', required=True)
    b = sub.add_parser('chrome'); b.add_argument('--user-data-dir', required=True); b.add_argument('--out', required=True); b.add_argument('--domain', action='append')
    args = parser.parse_args(argv)
    try:
        roots = []
        if args.command == 'snapshot':
            roots = [safe_path(args.root)]
        elif args.command == 'duplicates':
            roots = [safe_path(args.copies)] + [safe_path(p) for p in args.original]
        elif args.command == 'chrome':
            roots = [safe_path(args.user_data_dir)]
        check_output(args.out, roots)
        if args.command == 'snapshot':
            result = scan_tree(args.root, args.hash)
        elif args.command == 'compare':
            result = compare_snapshots(load_json(args.before), load_json(args.after))
            roots = [result['root']]
        elif args.command == 'duplicates':
            result = duplicates(args.copies, args.original)
        else:
            result = chrome_audit(args.user_data_dir, args.domain or DEFAULT_DOMAINS)
        output = write_new(args.out, result, roots)
        print(json.dumps({'report': str(output), 'summary': result['summary']}, ensure_ascii=False))
        return 0 if result['summary'].get('complete', True) else 2
    except (OSError, AuditError, ValueError, KeyError, TypeError) as e:
        # No SQL data or sensitive input payload is printed on errors.
        print(json.dumps({'status': 'failed', 'error_type': type(e).__name__,
                          'reason': str(e) if isinstance(e, AuditError) else 'Input/output validation failed'}, ensure_ascii=False), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
