#!/usr/bin/env python3
"""Install a new skill directory from the public file allowlist; never overwrite."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import shutil
import sys

ROOT = Path(__file__).resolve().parents[1]
SKILL = 'claude-mac-cleanup'


def no_links(path):
    for item in (path, *path.parents):
        if item.is_symlink():
            raise ValueError('Symbolic links are not accepted')


def install(destination, root=ROOT):
    destination = Path(os.path.abspath(os.path.expanduser(str(destination))))
    no_links(destination)
    if destination.exists():
        raise ValueError('Destination exists; keep it and select a new destination')
    if destination == root or root in destination.parents or destination in root.parents:
        raise ValueError('Installation and source directories must not overlap')
    manifest = json.loads((root / 'release-files.json').read_text())
    files = manifest['files']
    if not isinstance(files, list) or len(files) != len(set(files)):
        raise ValueError('Invalid release manifest')
    prepared = []
    for name in files:
        if not isinstance(name, str) or name.startswith('/') or any(p in ('', '.', '..') for p in name.split('/')):
            raise ValueError('Invalid manifest path')
        path = root / name
        no_links(path)
        if not path.is_file():
            raise ValueError('Release file is missing')
        if name.startswith('vendor/') and name != 'vendor/cc-clean/SOURCE.json':
            raise ValueError('Optional upstream source cannot be installed by this installer')
        prepared.append((name, path))
    # Install exactly the public allowlist, including its self-test and source notes.
    # Per-machine settings and separately fetched dependencies never enter this copy.
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    no_links(destination.parent)
    destination.mkdir(mode=0o700)
    for name, source in prepared:
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with source.open('rb') as read, target.open('xb') as write:
            os.chmod(target, 0o600)
            shutil.copyfileobj(read, write)
    return {'status': 'installed', 'files': len(prepared), 'overwrote_existing': False,
            'local_configuration_copied': False, 'upstream_dependency_copied': False,
            'next_step': 'Declare local protected folders before any cleanup.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument('--agent', choices=('codex', 'claude'))
    target.add_argument('--destination', help='A new absolute skill-directory path')
    args = parser.parse_args()
    destination = args.destination or str(Path.home() / ('.codex' if args.agent == 'codex' else '.claude') / 'skills' / SKILL)
    if args.destination and not Path(args.destination).is_absolute():
        parser.error('Use an absolute destination path')
    try:
        print(json.dumps(install(destination), ensure_ascii=False))
        return 0
    except (OSError, ValueError, KeyError, TypeError):
        print(json.dumps({'status': 'failed', 'reason': 'Installation preconditions failed; existing directories are never overwritten. A partial new destination may require inspection.'}), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
