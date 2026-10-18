#!/usr/bin/env python3
"""Policy-bound CC Clean adapter. Audit/copy/observe only; never delete or restore."""
import argparse
import builtins
from collections import Counter
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from urllib.parse import urlsplit

sys.dont_write_bytecode = True
import audit_tools as local_audit
import fetch_cc_clean as dependency

VENDOR = Path(__file__).resolve().parent.parent / 'vendor/cc-clean/runtime/cc-clean/scripts'


class GuardError(ValueError):
    pass


class VendorIntegrityError(GuardError):
    pass


def verified_vendor_bytes():
    """Verify exactly the two Python modules, then execute those same checked bytes."""
    def read(path):
        for node in (path, *path.parents):
            if node.is_symlink():
                raise VendorIntegrityError('Vendored source contains a linked path; source verification failed')
        fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
        with os.fdopen(fd, 'rb') as source:
            before = os.fstat(source.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise VendorIntegrityError('Vendored source must be a regular file')
            data = source.read()
            after = os.fstat(source.fileno())
        fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        if tuple(getattr(before, key) for key in fields) != tuple(getattr(after, key) for key in fields):
            raise VendorIntegrityError('Vendored source changed during verification')
        return data
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise VendorIntegrityError('Vendored provenance contains duplicate keys')
            result[key] = value
        return result
    try:
        status = dependency.inspect_installation(VENDOR.parent.parent, dependency.MANIFEST)
        if status['status'] == 'absent':
            raise FileNotFoundError
        manifest = json.loads(read(VENDOR.parent.parent / 'SOURCE.json'), object_pairs_hook=unique)
        files = manifest['files']
        checked = {}
        for filename in ('review_tools.py', 'local_state.py'):
            expected = [row['sha256'] for row in files if row['path'] == 'cc-clean/scripts/' + filename]
            data = read(VENDOR / filename)
            if len(expected) != 1 or hashlib.sha256(data).hexdigest() != expected[0]:
                raise VendorIntegrityError('Vendored source changed; review provenance before execution')
            checked[filename] = data
        return checked
    except FileNotFoundError:
        raise VendorIntegrityError(
            'Optional CC Clean dependency is absent. Read the optional dependency notice in README.md; '
            'to obtain the pinned source explicitly, run scripts/fetch_cc_clean.py --accept-unlicensed-source. '
            'Auth inspection and basic Mac evidence tools work without it.') from None
    except dependency.DependencyError:
        raise VendorIntegrityError('Optional CC Clean dependency is incomplete or changed; inspect its provenance before use') from None
    except VendorIntegrityError:
        raise
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        raise VendorIntegrityError('Vendored provenance could not be verified') from None


def load_upstream():
    """Keep upstream names out of sys.path/sys.modules, including its lazy import."""
    checked = verified_vendor_bytes()
    spec = importlib.util.spec_from_file_location('_claude_cleanup_vendor_review', VENDOR / 'review_tools.py')
    review = importlib.util.module_from_spec(spec)
    exec(compile(checked['review_tools.py'], str(VENDOR / 'review_tools.py'), 'exec'), review.__dict__)
    spec = importlib.util.spec_from_file_location('_claude_cleanup_vendor_core', VENDOR / 'local_state.py')
    core = importlib.util.module_from_spec(spec)
    imported = builtins.__import__
    def isolated_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == 'review_tools' and level == 0:
            return review
        return imported(name, globals, locals, fromlist, level)
    core.__dict__['__builtins__'] = dict(vars(builtins), __import__=isolated_import)
    exec(compile(checked['local_state.py'], str(VENDOR / 'local_state.py'), 'exec'), core.__dict__)
    core.GuardError = GuardError
    return core, review


_LOADED = None


class OptionalModule:
    def __init__(self, index):
        self.index = index

    def __getattr__(self, name):
        global _LOADED
        if _LOADED is None:
            _LOADED = load_upstream()
        return getattr(_LOADED[self.index], name)


CORE, REVIEW = OptionalModule(0), OptionalModule(1)
ENV_KEYS = ('ANTHROPIC_API_KEY', 'ANTHROPIC_AUTH_TOKEN', 'CLAUDE_CODE_OAUTH_TOKEN',
            'ANTHROPIC_BASE_URL', 'CLAUDE_CONFIG_DIR', 'CLAUDE_SECURESTORAGE_CONFIG_DIR')
POLICY_REQUIRED = {'schema', 'mode', 'backup_policy', 'roots', 'reviewed_files',
                   'writer_state', 'authorization_ref', 'retention_note'}
POLICY_OPTIONAL = {'accept_sensitive_originals'}
CLASSIFICATIONS = {'work_product', 'nonsecret_config', 'sensitive_state'}


def need(condition, message):
    if not condition:
        raise GuardError(message)


def safe_read(value):
    def pairs(items):
        result = {}
        for key, entry in items:
            need(key not in result, 'Duplicate JSON keys are forbidden')
            result[key] = entry
        return result
    def invalid(_):
        raise GuardError('Nonstandard JSON constants are forbidden')
    try:
        path = local_audit.safe_path(value)
        with local_audit.directory_fd(path.parent) as parent:
            fd = os.open(path.name, os.O_RDONLY | local_audit.NOFOLLOW | getattr(os, 'O_NONBLOCK', 0), dir_fd=parent)
            with os.fdopen(fd, 'r', encoding='utf-8') as stream:
                need(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), 'Input must be a regular file')
                return json.load(stream, object_pairs_hook=pairs, parse_constant=invalid)
    except local_audit.AuditError:
        raise GuardError('Input path contains an unsupported link or unsafe component') from None


def new_output(value, sources):
    try:
        return local_audit.check_output(value, sources.values())
    except local_audit.AuditError:
        raise GuardError('Output must be new, outside source roots, and free of linked path components') from None


def explicit_inputs(values):
    roots = {}
    for value in values:
        need(isinstance(value, str) and '=' in value, 'Inputs must use label=absolute-path')
        label, raw = value.split('=', 1)
        need(re.fullmatch('[a-z][a-z0-9_-]{0,31}', label) and label not in roots, 'Invalid or repeated root label')
        expanded = os.path.expanduser(raw)
        need(os.path.isabs(expanded), 'Input roots must be absolute paths')
        try:
            path = local_audit.safe_path(expanded, must_exist=False)
        except local_audit.AuditError:
            raise GuardError('Input root contains a linked path component') from None
        need(not any(local_audit.inside(path, old) or local_audit.inside(old, path) for old in roots.values()),
             'Input roots must not overlap')
        roots[label] = path
    return roots


def audit(values, output, state_file=None):
    roots = explicit_inputs(values)
    out = new_output(output, roots)
    # Upstream performs all state parsing, duplicate-key checks, and relationship work.
    return CORE.audit(roots, out, state_file)


def value_type(value):
    if value is None:
        return 'null'
    if type(value) is bool:
        return 'boolean'
    if isinstance(value, str):
        return 'string'
    if isinstance(value, dict):
        return 'object'
    if isinstance(value, list):
        return 'array'
    return 'number'


def endpoint(value):
    """No URL path, credentials, query, fragment, or raw fallback is emitted."""
    if not isinstance(value, str) or not value.strip():
        return {'status': 'empty_or_nonstring'}
    try:
        parsed = urlsplit(value)
        need(parsed.scheme in ('http', 'https') and bool(parsed.hostname), 'Invalid endpoint')
        host = parsed.hostname
        need(not any(c.isspace() or c in '/@?#\\%' for c in host), 'Invalid endpoint host')
        port = parsed.port
        return {'status': 'parsed', 'scheme': parsed.scheme, 'host': host, 'port': port}
    except (ValueError, GuardError):
        return {'status': 'invalid_or_unsupported', 'value_recorded': False}


def presence(mapping, key):
    exists = key in mapping
    value = mapping.get(key)
    row = {'present': exists, 'value_recorded': False, 'value_hash_recorded': False,
           'value_type': value_type(value) if exists else None,
           'empty': (value is None or (isinstance(value, str) and not value.strip())) if exists else None}
    if exists and key == 'ANTHROPIC_BASE_URL':
        row['endpoint'] = endpoint(value)
    return row


def auth(values, output, include_process_env=False, environment=None):
    # Process environment is opt-in. Unrelated settings are never reported or evaluated.
    roots = explicit_inputs(values) if values else {}
    out = new_output(output, roots)
    rows = []
    for label, path in roots.items():
        data = safe_read(path)
        need(isinstance(data, dict), 'Settings JSON must be an object')
        env = data.get('env', {})
        need(isinstance(env, dict), 'Settings environment must be an object')
        rows.append({'label': label, 'variables': {key: presence(env, key) for key in ENV_KEYS},
                     'apiKeyHelper': dict(presence(data, 'apiKeyHelper'), executed=False)})
    # Do not access os.environ at all when the option is absent, including empty checks.
    process_env = {}
    if include_process_env:
        env = os.environ if environment is None else environment
        process_env = {key: presence(env, key) for key in ENV_KEYS}
    data = {'schema': 1, 'kind': 'auth-candidates', 'created_at': local_audit.now(),
            'settings': rows, 'helper_environment': process_env,
            'process_environment_included': bool(include_process_env),
            'helper_environment_source': 'current-helper-inherited' if include_process_env else 'not-inspected',
            'effective_configuration_unknown': True,
            'effective_authentication_verified': False, 'precedence_resolved': False,
            'keychain_read': False, 'other_process_environment_read': False,
            'helper_executed': False, 'source_changed_by_tool': False,
            'limitations': ['Only explicit settings and optionally this helper environment were inspected.',
                            'Presence is not proof of the authentication used by an application.',
                            'Unrelated settings and environment keys are ignored without being reported.',
                            'Inherited helper environment is not evidence of another application environment.']}
    local_audit.write_new(out, data, roots.values())
    return {'status': 'auth_candidates_written', 'settings_count': len(rows),
            'effective_authentication_verified': False}


def known_sensitive(root, relative):
    parts = list(root.parts if relative == '.' else (root / relative).parts)
    names = [part.lower() for part in parts]
    name = names[-1]
    if name in {'.claude.json', '.credentials.json', 'credentials.json', 'history.jsonl',
                'keychain.json', 'cookies', 'login data', 'login data for account',
                '.zsh_history', '.bash_history'}:
        return True
    if name == '.env' or name.startswith('.env.') or name.startswith('.claude.json.backup'):
        return True
    if any(part in {'session-env', 'shell-snapshots', 'transcripts'} for part in names):
        return True
    return ('.claude' in names and (name.endswith('.jsonl') or 'debug' in names)) or (
        'projects' in names and name.endswith('.jsonl'))


def policy_roots(policy):
    need(isinstance(policy, dict) and POLICY_REQUIRED <= set(policy) <= POLICY_REQUIRED | POLICY_OPTIONAL,
         'Unsupported or incomplete backup policy schema')
    need(type(policy['schema']) is int and policy['schema'] == 1, 'Unsupported backup policy schema')
    need(policy['mode'] in {'maintenance', 'uninstall'}, 'Invalid backup mode')
    need(policy['backup_policy'] in {'work-products', 'sensitive-recovery'}, 'Invalid backup policy')
    need(policy['writer_state'] == 'confirmed_stopped', 'Writers must be confirmed stopped before copying')
    for key in ('authorization_ref', 'retention_note'):
        need(isinstance(policy[key], str) and bool(policy[key].strip()), 'Policy reference and retention note are required')
    need(isinstance(policy['roots'], dict) and bool(policy['roots']), 'Explicit backup roots are required')
    need(all(isinstance(k, str) and isinstance(v, str) for k, v in policy['roots'].items()), 'Invalid backup roots')
    roots = CORE.parse_roots([k + '=' + v for k, v in policy['roots'].items()], allow_missing=True)
    if policy['backup_policy'] == 'sensitive-recovery':
        need(policy['mode'] == 'maintenance' and policy.get('accept_sensitive_originals') is True,
             'Sensitive originals require explicit acceptance in maintenance mode')
    else:
        need(policy.get('accept_sensitive_originals', False) is False,
             'Sensitive acceptance is incompatible with work-product backup')
    return roots


def validate_review(policy, roots, trees):
    reviewed = policy['reviewed_files']
    need(isinstance(reviewed, list), 'Reviewed files must be an explicit list')
    all_files = {}
    for label, data in trees.items():
        for rel, entry in data['entries'].items():
            need(entry['kind'] in {'file', 'directory'}, 'Links and special files are not permitted in policy backups')
            if entry['kind'] == 'file':
                all_files[(label, rel)] = entry
    seen = set()
    for row in reviewed:
        need(isinstance(row, dict) and {'root', 'path', 'classification'} <= set(row) <=
             {'root', 'path', 'classification', 'sha256'}, 'Invalid reviewed-file record')
        label, rel, cls = row['root'], row['path'], row['classification']
        need(isinstance(label, str) and label in roots, 'Reviewed file root is not selected')
        REVIEW.safe_relative(CORE, rel)
        need(isinstance(cls, str) and cls in CLASSIFICATIONS, 'Unknown file classification')
        key = (label, rel)
        need(key not in seen and key in all_files, 'Duplicate, missing, or non-regular reviewed file')
        seen.add(key)
        if 'sha256' in row:
            need(isinstance(row['sha256'], str) and re.fullmatch('[0-9a-f]{64}', row['sha256']) and
                 row['sha256'] == all_files[key].get('sha256'), 'Reviewed content digest does not match source')
        if policy['backup_policy'] == 'work-products':
            need(cls in {'work_product', 'nonsecret_config'} and not known_sensitive(roots[label], rel),
                 'Known sensitive state cannot be classified as work products or nonsecret configuration')
    need(seen == set(all_files), 'Reviewed files do not cover the entire current source tree')
    return Counter(row['classification'] for row in reviewed)


def backup(policy_file, output):
    policy_path = CORE.lexical_path(policy_file)
    policy = safe_read(policy_path)
    roots = policy_roots(policy)
    out = new_output(output, {**roots, '_policy': policy_path})
    before = CORE.snapshot(roots, hashed=True)
    classifications = validate_review(policy, roots, before)
    need(any(not row['missing'] for row in before.values()), 'At least one backup root must exist')
    result = CORE.backup(roots, out, allow_missing=True)
    # Anchor preflight to the exact inventory copied by the unchanged upstream engine.
    manifest = safe_read(out / 'manifest.json')
    need(manifest['trees'] == before and CORE.snapshot(roots, hashed=True) == before,
         'Source changed after policy validation; partial backup must not authorize cleanup')
    receipt = {'schema': 1, 'kind': 'policy-backup-receipt', 'status': 'policy_backup_verified',
               'policy': policy, 'policy_sha256': CORE.canonical_digest(policy),
               'manifest_sha256': CORE.canonical_digest(manifest),
               'backup_dir': str(out), 'classification_counts': dict(classifications),
               'contains_sensitive_originals': True if policy['backup_policy'] == 'sensitive-recovery' else 'possible_unverified',
               'known_sensitive_paths_blocked': policy['backup_policy'] == 'work-products',
               'arbitrary_embedded_secrets_detected': False,
               'authorization_verified_by_helper': False, 'writer_state_verified_by_helper': False,
               'copied_source_unchanged': True, 'source_changed_by_tool': False,
               'reviewed_hash_coverage': sum('sha256' in row for row in policy['reviewed_files']),
               'integrity_scope': 'local consistency checks; not a signature or proof of human approval'}
    receipt['receipt_sha256'] = CORE.canonical_digest(receipt)
    CORE.private_json(out / 'policy-receipt.json', receipt)
    return {**result, 'status': 'policy_backup_verified', 'backup_policy': policy['backup_policy'],
            'contains_sensitive_originals': receipt['contains_sensitive_originals'],
            'authorization_verified_by_helper': False}


def policy_bundle(directory):
    directory = CORE.lexical_path(directory)
    receipt = safe_read(directory / 'policy-receipt.json')
    need(isinstance(receipt, dict), 'Policy receipt must be an object')
    body = {k: v for k, v in receipt.items() if k != 'receipt_sha256'}
    need(CORE.canonical_digest(body) == receipt.get('receipt_sha256'), 'Policy receipt changed')
    need(receipt.get('schema') == 1 and receipt.get('kind') == 'policy-backup-receipt' and
         receipt.get('status') == 'policy_backup_verified', 'Unsupported or incomplete policy receipt')
    need(receipt.get('backup_dir') == str(directory), 'Policy receipt belongs to a different backup directory')
    policy = receipt.get('policy')
    roots = policy_roots(policy)
    need(CORE.canonical_digest(policy) == receipt.get('policy_sha256'), 'Policy changed after verification')
    live_roots, manifest, upstream_receipt = CORE.verified_bundle(directory)
    need(roots == live_roots and policy['roots'] == manifest['roots'], 'Policy and backup scopes differ')
    need(CORE.canonical_digest(manifest) == receipt.get('manifest_sha256'), 'Policy manifest changed')
    counts = validate_review(policy, roots, manifest['trees'])
    need(dict(counts) == receipt.get('classification_counts'), 'Classification receipt changed')
    sensitive = True if policy['backup_policy'] == 'sensitive-recovery' else 'possible_unverified'
    need(receipt.get('contains_sensitive_originals') == sensitive and
         receipt.get('authorization_verified_by_helper') is False and
         receipt.get('writer_state_verified_by_helper') is False and
         receipt.get('copied_source_unchanged') is True and receipt.get('source_changed_by_tool') is False,
         'Policy receipt assurance flags are inconsistent')
    return roots, manifest, receipt


def verify(directory, check_source=False):
    roots, _, receipt = policy_bundle(directory)
    return {**CORE.verify(directory, check_source), 'policy_verified': True,
            'contains_sensitive_originals': receipt['contains_sensitive_originals'],
            'authorization_verified_by_helper': False}


def restore_pair(old_dir, current_dir):
    old_roots, _, old = policy_bundle(old_dir)
    current_roots, _, current = policy_bundle(current_dir)
    need(old_roots == current_roots, 'Restore scopes must match exactly')
    need(old['policy']['mode'] == current['policy']['mode'] and
         old['policy']['backup_policy'] == current['policy']['backup_policy'],
         'Restore policies must use the same mode and backup policy')
    return old_roots


def prepare_restore(old_dir, current_dir, selections, output):
    roots = restore_pair(old_dir, current_dir)
    out = new_output(output, {**roots, '_old': CORE.lexical_path(old_dir),
                              '_current': CORE.lexical_path(current_dir)})
    return REVIEW.prepare_restore(CORE, old_dir, current_dir, selections, out)


def record_restore(plan_file, output):
    plan = safe_read(plan_file)
    need(isinstance(plan, dict) and plan.get('kind') == 'restore-plan', 'Invalid restore plan')
    roots = restore_pair(plan['backup_dir'], plan['pre_restore_backup'])
    out = new_output(output, {**roots, '_plan': CORE.lexical_path(plan_file),
                              '_old': CORE.lexical_path(plan['backup_dir']),
                              '_current': CORE.lexical_path(plan['pre_restore_backup'])})
    return REVIEW.record_restore(CORE, plan_file, out)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('audit')
    p.add_argument('--root', action='append', required=True)
    p.add_argument('--state-file')
    p.add_argument('--out', required=True)
    p = sub.add_parser('auth')
    p.add_argument('--settings', action='append', default=[])
    p.add_argument('--include-process-env', action='store_true')
    p.add_argument('--out', required=True)
    p = sub.add_parser('backup')
    p.add_argument('--policy', required=True)
    p.add_argument('--out', required=True)
    p = sub.add_parser('verify')
    p.add_argument('--backup-dir', required=True)
    p.add_argument('--check-source', action='store_true')
    p = sub.add_parser('prepare-restore')
    p.add_argument('--backup-dir', required=True)
    p.add_argument('--pre-restore-backup', required=True)
    p.add_argument('--select', action='append', required=True)
    p.add_argument('--out', required=True)
    p = sub.add_parser('record-restore')
    p.add_argument('--plan', required=True)
    p.add_argument('--out', required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == 'audit':
            result = audit(args.root, args.out, args.state_file)
        elif args.command == 'auth':
            result = auth(args.settings, args.out, args.include_process_env)
        elif args.command == 'backup':
            result = backup(args.policy, args.out)
        elif args.command == 'verify':
            result = verify(args.backup_dir, args.check_source)
        elif args.command == 'prepare-restore':
            result = prepare_restore(args.backup_dir, args.pre_restore_backup, args.select, args.out)
        else:
            result = record_restore(args.plan, args.out)
        print(json.dumps(result, ensure_ascii=False))
        return 2 if result.get('status') in {'restore_partial', 'restore_failed'} else 0
    except GuardError as error:
        print('ERROR: ' + str(error), file=sys.stderr)
    except (OSError, ValueError, TypeError, KeyError, RecursionError, subprocess.SubprocessError):
        print('ERROR: operation could not be verified; raw paths, values and exceptions are withheld.', file=sys.stderr)
    return 2


if __name__ == '__main__':
    sys.exit(main())
