#!/usr/bin/env python3
"""Check a public file allowlist and optionally build a source-only release ZIP."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = 'release-files.json'
PROVENANCE = 'vendor/cc-clean/SOURCE.json'
EXAMPLE_USERS = {'example', 'user', 'sample', 'test', 'synthetic-user', 'sensitiveperson'}


def public_files(root=ROOT):
    data = json.loads((root / MANIFEST).read_text(encoding='utf-8'))
    files = data['files']
    if data.get('schema_version') != 1 or not isinstance(files, list) or not files or len(files) != len(set(files)):
        raise ValueError('Invalid release manifest')
    for name in files:
        if not isinstance(name, str) or name.startswith('/') or any(p in ('', '.', '..') for p in name.split('/')):
            raise ValueError('Invalid release path')
        if name.startswith('vendor/') and name != PROVENANCE:
            raise ValueError('Upstream source is excluded from public releases')
        if name.endswith(('.jsonl', '.sqlite', '.db', '.pem', '.key', '.zip', '.pyc')) or '/.git/' in '/' + name:
            raise ValueError('Private/generated file type is excluded')
        if name.endswith('.json') and name not in (MANIFEST, PROVENANCE):
            raise ValueError('Runtime JSON cannot be published')
        path = root / name
        if any(p.is_symlink() for p in (path, *path.parents)) or not path.is_file():
            raise ValueError('Release file is missing or linked')
    return sorted(files)


def check(root=ROOT, deny=(), tracked=False):
    files = public_files(root)
    issues = []
    digests = {}
    for name in files:
        raw = (root / name).read_bytes()
        content = raw.decode('utf-8')
        digests[name] = hashlib.sha256(raw).hexdigest()
        for line_number, line in enumerate(content.splitlines(), 1):
            if any(needle and needle.casefold() in line.casefold() for needle in deny):
                issues.append({'file': name, 'line': line_number, 'type': 'private-denylist-match'})
            for match in re.finditer(r"/(?:Users|home)/([^/\s\"'<>`]+)", line):
                if match.group(1) not in EXAMPLE_USERS:
                    issues.append({'file': name, 'line': line_number, 'type': 'non-example-home-path'})
            if re.search(r'(?:sk-(?:ant-|proj-)?[A-Za-z0-9_-]{24,}|gh[pousr]_[A-Za-z0-9]{24,}|github_pat_[A-Za-z0-9_]{30,}|-----BEGIN [A-Z ]*PRIVATE KEY-----)', line):
                issues.append({'file': name, 'line': line_number, 'type': 'possible-credential'})
            if re.search(r'/private/var/folders/[a-zA-Z0-9]{2}/[a-zA-Z0-9]{10,}', line):
                issues.append({'file': name, 'line': line_number, 'type': 'machine-temporary-path'})
    if tracked:
        command = lambda args: subprocess.run(['git', '-C', str(root), *args], check=True, capture_output=True).stdout
        actual = command(['ls-files', '-z']).decode().split('\0')
        if set(filter(None, actual)) != set(files):
            issues.append({'type': 'tracked-file-set-differs-from-public-allowlist'})
        for name in files:
            staged = command(['show', ':' + name])
            if hashlib.sha256(staged).hexdigest() != digests[name]:
                issues.append({'file': name, 'type': 'index-differs-from-reviewed-file'})
    return {'schema_version': 1, 'status': 'passed' if not issues else 'failed',
            'files_checked': len(files), 'issues': issues, 'file_sha256': digests,
            'scope': 'Public allowlist only; pattern checks supplement human privacy review.'}


def build_zip(destination, root=ROOT):
    destination = Path(os.path.abspath(str(destination)))
    if destination.exists() or root == destination or root in destination.parents:
        raise ValueError('Archive must be new and outside the source checkout')
    if not destination.parent.is_dir() or any(p.is_symlink() for p in (destination, *destination.parents)):
        raise ValueError('Unsafe archive destination')
    files = public_files(root)
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as stream, zipfile.ZipFile(stream, 'w', zipfile.ZIP_DEFLATED) as archive:
        for name in files:
            info = zipfile.ZipInfo('claude-mac-cleanup/' + name)
            info.external_attr = 0o100600 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, (root / name).read_bytes())
    with zipfile.ZipFile(destination) as archive:
        if archive.testzip() is not None or len(archive.namelist()) != len(files):
            raise ValueError('Archive verification failed')
        for name in files:
            if archive.read('claude-mac-cleanup/' + name) != (root / name).read_bytes():
                raise ValueError('Archive readback mismatch')
    return {'files': len(files), 'sha256': hashlib.sha256(destination.read_bytes()).hexdigest(),
            'readback_verified': True, 'upstream_source_included': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--private-denylist', type=Path, help='Local JSON array of private strings; never commit it')
    parser.add_argument('--tracked', action='store_true')
    parser.add_argument('--zip', type=Path)
    args = parser.parse_args()
    try:
        deny = json.loads(args.private_denylist.read_text()) if args.private_denylist else []
        if not isinstance(deny, list) or not all(isinstance(x, str) for x in deny):
            raise ValueError('Invalid private denylist')
        result = check(args.root, deny, args.tracked)
        if result['status'] == 'passed' and args.zip:
            result['archive'] = build_zip(args.zip, args.root)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if result['status'] == 'passed' else 2
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print(json.dumps({'status': 'failed', 'reason': 'Public release validation failed; no private input values are displayed.'}), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
