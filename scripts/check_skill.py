#!/usr/bin/env python3
"""Validate the public skill in private, synthetic fixtures, with no network.

The default suite covers dependency-free features and reports optional tests as
skipped. --require-upstream verifies and tests the explicitly fetched dependency.
"""
from __future__ import annotations

import argparse
import ast
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

sys.dont_write_bytecode = True
import fetch_cc_clean as dependency

ROOT = Path(__file__).resolve().parents[1]


def structure_checks(require_upstream=False) -> dict:
    source, expected = dependency.manifest()
    optional = dependency.inspect_installation() if require_upstream else {
        'status': 'not_checked_in_base_mode', 'files_verified': 0, 'commit': source['commit']}
    if require_upstream and optional['status'] != 'verified':
        raise ValueError('--require-upstream requires the complete pinned dependency; run the explicit fetch command first')
    python_files = sorted(p for p in ROOT.rglob('*.py')
        if 'runtime' not in p.relative_to(ROOT).parts or require_upstream)
    for path in python_files:
        ast.parse(path.read_text(encoding='utf-8'), filename=str(path.relative_to(ROOT)))
    links = 0
    for path in ROOT.rglob('*.md'):
        if any(part in {'runtime', '.git'} for part in path.relative_to(ROOT).parts):
            continue
        for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)', path.read_text()):
            target = target.split('#', 1)[0]
            if not target or re.match(r'[a-zA-Z][a-zA-Z0-9+.-]*:', target):
                continue
            if target.startswith('<') and target.endswith('>'):
                target = target[1:-1]
            if target.startswith('/'):
                raise ValueError('Skill links must be portable: ' + path.name)
            resolved = (path.parent / target).resolve()
            if not resolved.is_relative_to(ROOT) or not resolved.exists():
                raise ValueError('Broken local reference in ' + path.name + ': ' + target)
            links += 1
    return {'upstream_files_verified': optional['files_verified'], 'upstream_commit': source['commit'],
            'optional_dependency': optional['status'], 'python_files_parsed': len(python_files),
            'local_links_checked': links, 'pinned_files_in_metadata': len(expected)}


def check_javascript(node: str | None, work: Path, env: dict, require_upstream=False) -> dict:
    executable = node or shutil.which('node')
    if not executable:
        return {'status': 'not_checked', 'reason': 'Node.js unavailable; pass --node PATH'}
    count = 0
    html_files = [ROOT / 'assets/report.html']
    if require_upstream:
        html_files.append(dependency.DESTINATION / 'cc-clean/assets/report.html')
    for html in html_files:
        text = html.read_text(encoding='utf-8')
        for attrs, script in re.findall(r'<script\b([^>]*)>(.*?)</script>', text, re.S | re.I):
            if re.search(r'type=[\"\x27]application/(?:json|ld\+json)[\"\x27]', attrs, re.I) or not script.strip():
                continue
            target = work / f'syntax-{count}.js'
            target.write_text(script, encoding='utf-8')
            result = subprocess.run([executable, '--check', str(target)], env=env,
                                    capture_output=True, text=True, timeout=30)
            if result.returncode:
                raise ValueError('JavaScript syntax failure in ' + str(html.relative_to(ROOT)))
            count += 1
    return {'status': 'passed', 'scripts_checked': count}


def suite(path: Path, env: dict) -> dict:
    result = subprocess.run([sys.executable, '-B', '-m', 'unittest', 'discover',
                             '-s', str(path), '-p', 'test_*.py', '-v'],
                            cwd=path, env=env, capture_output=True, text=True, timeout=240)
    output = result.stdout + result.stderr
    count = re.search(r'Ran (\d+) tests? in', output)
    skipped = re.search(r'OK \(skipped=(\d+)\)', output)
    if result.returncode or not count or int(count.group(1)) == 0:
        print(output, file=sys.stderr)
        raise ValueError('Synthetic test suite failed')
    total, skipped_count = int(count.group(1)), int(skipped.group(1)) if skipped else 0
    return {'status': 'passed', 'tests_discovered': total, 'tests_passed': total - skipped_count,
            'tests_skipped': skipped_count}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--node', help='Optional Node.js executable for report script syntax')
    parser.add_argument('--require-upstream', action='store_true', help='Require and test all pinned optional dependency files')
    args = parser.parse_args()
    if sys.version_info < (3, 10):
        parser.error('Python 3.10 or newer is required')
    try:
        summary = {'schema_version': 1, 'kind': 'skill_validation',
                   'generated_at': datetime.now(timezone.utc).isoformat(),
                   'python': sys.version.split()[0], 'real_user_sources_read': False,
                   'network_used': False, 'mode': 'full_optional' if args.require_upstream else 'base',
                   'structure': structure_checks(args.require_upstream)}
        with tempfile.TemporaryDirectory(prefix='claude-skill-check-') as temporary:
            work = Path(temporary).resolve()
            home = work / 'synthetic-home'; home.mkdir(mode=0o700)
            env = {'HOME': str(home), 'PATH': os.environ.get('PATH', '/usr/bin:/bin'),
                   'TMPDIR': str(work), 'PYTHONDONTWRITEBYTECODE': '1',
                   'LC_ALL': 'en_US.UTF-8', 'LANG': 'en_US.UTF-8'}
            copy = work / 'skill'
            excluded = ['__pycache__', '*.pyc', 'test-artifacts', '.git']
            if not args.require_upstream:
                excluded.append('runtime')
            shutil.copytree(ROOT, copy, ignore=shutil.ignore_patterns(*excluded))
            summary['javascript'] = check_javascript(args.node, work, env, args.require_upstream)
            summary['local_tests'] = suite(copy / 'scripts', env)
            summary['upstream_tests'] = suite(copy / 'vendor/cc-clean/runtime', env) if args.require_upstream else {
                'status': 'not_covered', 'tests_passed': 0, 'tests_skipped': None,
                'reason': 'Optional dependency is not executed in base mode; use --require-upstream after explicit fetch'}
        summary['tests_passed_total'] = summary['local_tests']['tests_passed'] + summary['upstream_tests']['tests_passed']
        summary['optional_features_covered'] = args.require_upstream
        summary['status'] = 'passed' if summary['javascript']['status'] == 'passed' else 'incomplete'
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        return 0 if summary['status'] == 'passed' else 2
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        print('Skill validation failed: ' + str(exc), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
