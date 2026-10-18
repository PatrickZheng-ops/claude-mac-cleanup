#!/usr/bin/env python3
"""Explicitly obtain an optional, pinned CC Clean dependency; never execute it.

The public skill contains no upstream implementation. The reviewed upstream
commit did not include a LICENSE. This opt-in records an informed choice to
fetch it for local evaluation; it does not grant redistribution permission.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from urllib import request
from urllib.error import URLError

sys.dont_write_bytecode = True
import audit_tools as audit

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / 'vendor/cc-clean/SOURCE.json'
DESTINATION = ROOT / 'vendor/cc-clean/runtime'
COMMIT = '0be9fdafa4fdd7894997db8335eaa47720c36627'
FILES = frozenset(('cc-clean/scripts/local_state.py', 'cc-clean/scripts/review_tools.py',
    'cc-clean/assets/report.html', 'test_local_state.py', 'test_review_tools.py', 'test_device_ids.py'))
MAX_FILE_BYTES = 8 * 1024 * 1024


class DependencyError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise DependencyError(message)


def read_file(path):
    try:
        p = audit.safe_path(path)
        with audit.directory_fd(p.parent) as dfd:
            fd = os.open(p.name, os.O_RDONLY | audit.NOFOLLOW | getattr(os, 'O_NONBLOCK', 0), dir_fd=dfd)
            with os.fdopen(fd, 'rb') as stream:
                require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), 'Dependency metadata must be a regular file')
                data = stream.read(MAX_FILE_BYTES + 1)
                require(len(data) <= MAX_FILE_BYTES, 'Dependency file exceeds the size limit')
                return data
    except (OSError, audit.AuditError):
        raise DependencyError('Dependency file is missing, inaccessible, or linked') from None


def decode(data):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'Dependency metadata has duplicate keys')
            result[key] = value
        return result
    try:
        return json.loads(data, object_pairs_hook=pairs)
    except (UnicodeError, ValueError, TypeError):
        raise DependencyError('Dependency metadata is invalid') from None


def manifest(path=MANIFEST):
    data = decode(read_file(path))
    require(isinstance(data, dict) and data.get('commit') == COMMIT and
            data.get('upstream') == 'https://github.com/luwill/cc-clean', 'Unexpected dependency source or commit')
    rows = data.get('files')
    require(isinstance(rows, list) and len(rows) == len(FILES), 'Expected six pinned dependency files')
    found = {}
    for row in rows:
        require(isinstance(row, dict), 'Invalid dependency file entry')
        name, digest = row.get('path'), row.get('sha256')
        require(name in FILES and name not in found, 'Unexpected, repeated, or unsafe dependency path')
        require(isinstance(digest, str) and re.fullmatch('[0-9a-f]{64}', digest), 'Invalid dependency digest')
        require(row.get('upstream_url') == 'https://github.com/luwill/cc-clean/blob/' + COMMIT + '/' + name,
                'Unexpected dependency URL')
        found[name] = digest
    require(set(found) == FILES, 'Dependency manifest is incomplete')
    return data, found


class NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise DependencyError('Dependency redirects are not permitted')


def download(url):
    require(url.startswith('https://raw.githubusercontent.com/luwill/cc-clean/' + COMMIT + '/'),
            'Dependency URL is outside the pinned source')
    # Respect the caller's existing network configuration; never change it.
    # Redirects to a second host or URL are refused.
    opener = request.build_opener(NoRedirect())
    req = request.Request(url, headers={'User-Agent': 'claude-mac-cleanup-optional-fetch'})
    with opener.open(req, timeout=30) as response:
        require(response.geturl() == url and response.status == 200, 'Dependency response is not the pinned URL')
        data = response.read(MAX_FILE_BYTES + 1)
    require(len(data) <= MAX_FILE_BYTES, 'Dependency response exceeds the size limit')
    return data


def inspect_installation(destination=DESTINATION, manifest_path=MANIFEST):
    """Read only six fixed files and completion metadata. Never run the dependency."""
    expected_manifest, expected = manifest(manifest_path)
    try:
        target = audit.safe_path(destination, must_exist=False)
    except audit.AuditError:
        raise DependencyError('Dependency destination has a linked path component') from None
    if not target.exists():
        return {'status': 'absent', 'files_verified': 0, 'commit': COMMIT}
    require(target.is_dir(), 'Dependency destination is not a directory')
    receipt = decode(read_file(target / 'INSTALLATION.json'))
    require(isinstance(receipt, dict) and receipt.get('schema') == 1 and receipt.get('status') == 'complete'
            and receipt.get('commit') == COMMIT and receipt.get('file_hashes') == expected,
            'Dependency installation is incomplete or has changed')
    installed_manifest = decode(read_file(target / 'SOURCE.json'))
    require(installed_manifest == expected_manifest, 'Installed dependency provenance differs from the public manifest')
    for name, digest in expected.items():
        require(hashlib.sha256(read_file(target / name)).hexdigest() == digest, 'Installed dependency digest mismatch')
    allowed_files = FILES | {'SOURCE.json', 'INSTALLATION.json'}
    # No extra executable files or links may be silently included in the runtime.
    for current, dirs, filenames in os.walk(target, followlinks=False):
        for name in dirs + filenames:
            path = Path(current) / name
            require(not path.is_symlink(), 'Dependency installation contains a linked entry')
        for name in filenames:
            require(str((Path(current) / name).relative_to(target)) in allowed_files,
                    'Dependency installation contains an unexpected file')
    return {'status': 'verified', 'files_verified': len(expected), 'commit': COMMIT}


def fetch(accepted=False, destination=DESTINATION, manifest_path=MANIFEST, downloader=None):
    require(accepted is True, 'No download performed. Read the no-LICENSE notice, then explicitly pass --accept-unlicensed-source to fetch for local evaluation.')
    metadata, expected = manifest(manifest_path)
    state = inspect_installation(destination, manifest_path)
    if state['status'] == 'verified':
        return dict(state, status='already_verified', network_used=False, executed=False)
    try:
        target = audit.check_output(destination)
        require(target.parent.is_dir(), 'Dependency destination parent must exist')
    except (OSError, audit.AuditError):
        raise DependencyError('Dependency destination must be new, with an existing unlinked parent') from None
    obtain = downloader or download
    contents = {}
    for name, digest in expected.items():
        value = obtain('https://raw.githubusercontent.com/luwill/cc-clean/' + COMMIT + '/' + name)
        require(isinstance(value, bytes) and len(value) <= MAX_FILE_BYTES, 'Invalid dependency download')
        require(hashlib.sha256(value).hexdigest() == digest, 'Dependency download digest mismatch; nothing installed')
        contents[name] = value
    # All network data has passed hashes before destination creation. O_EXCL and
    # directory descriptors reject replacement and symlink traversal. Completion
    # metadata is written last; an interrupted directory never passes inspect.
    with audit.directory_fd(target.parent) as parent:
        try:
            os.mkdir(target.name, mode=0o700, dir_fd=parent)
        except FileExistsError:
            raise DependencyError('Dependency destination appeared during download; refusing to overwrite') from None
    try:
        for name, value in contents.items():
            path = target / name
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            # pathlib parents=True follows umask for intermediate directories.
            for folder in path.parents:
                if folder == target.parent:
                    break
                os.chmod(folder, 0o700, follow_symlinks=False)
            with audit.directory_fd(path.parent) as dfd:
                fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | audit.NOFOLLOW, 0o600, dir_fd=dfd)
                with os.fdopen(fd, 'wb') as stream:
                    stream.write(value)
                    stream.flush()
                    os.fsync(stream.fileno())
        audit.write_new(target / 'SOURCE.json', metadata)
        audit.write_new(target / 'INSTALLATION.json', {'schema': 1, 'status': 'complete', 'commit': COMMIT,
            'file_hashes': expected, 'license_granted_by_this_tool': False, 'downloaded_code_executed': False})
        state = inspect_installation(target, manifest_path)
    except (OSError, DependencyError, audit.AuditError):
        raise DependencyError('Dependency installation did not verify. Any partial runtime directory is untrusted; inspect it before removing and retrying.') from None
    return dict(state, status='installed_verified', network_used=downloader is None,
                transport='https' if downloader is None else 'injected', executed=False)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--accept-unlicensed-source', action='store_true',
                        help='Explicit local-evaluation opt-in; not a license or permission to redistribute')
    args = parser.parse_args(argv)
    try:
        print(json.dumps(fetch(args.accept_unlicensed_source), sort_keys=True))
        return 0
    except (DependencyError, OSError, URLError):
        # DependencyError messages are fixed strings; raw request exceptions may
        # contain machine/network details and are deliberately not echoed.
        error = sys.exc_info()[1]
        print('ERROR: ' + (str(error) if isinstance(error, DependencyError) else 'Optional dependency retrieval failed; nothing was executed.'), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
