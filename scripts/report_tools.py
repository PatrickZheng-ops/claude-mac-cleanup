#!/usr/bin/env python3
"""Render saved cleanup evidence only. Never probes or changes source environments.

The pinned cc-clean relationship and Device ID validators are reused, while every
display field is rebuilt through a whitelist. JSON inputs are untrusted evidence,
not authorization. All output is review-only and newly created with mode 0600.
"""
import argparse
import base64
import collections
import hashlib
import html
import json
import os
from pathlib import Path
import re
import stat
import sys
from types import ModuleType
import urllib.parse

sys.dont_write_bytecode = True
import audit_tools as audit
import fetch_cc_clean as dependency

VERSION = 1
BASE = Path(__file__).absolute().parent.parent
LEDGER_STATUSES = {'planned', 'approved', 'verified_removed', 'moved_to_trash', 'retained',
                   'not_found', 'access_denied', 'not_checked', 'attempted_unverified', 'failed', 'residual'}
LABELS = {'planned': '待处理', 'approved': '账本记载已批准', 'verified_removed': '账本记载已验证移除',
          'moved_to_trash': '已移入废纸篓', 'retained': '保留', 'not_found': '本项未发现',
          'access_denied': '无法读取', 'not_checked': '未完整核验', 'attempted_unverified': '尝试后未验收',
          'failed': '失败', 'residual': '有目标记录或残留', 'checked': '已检查本项', 'changed': '发现变化',
          'partial': '部分验证', 'verified': '回执记载已验证', 'observed': '已观察到，未判断可删'}
PRIORITY = {s: i for i, s in enumerate(('failed', 'access_denied', 'residual', 'attempted_unverified',
            'not_checked', 'partial', 'changed', 'planned', 'approved', 'observed', 'retained',
            'moved_to_trash', 'verified_removed', 'verified', 'checked', 'not_found'))}
DB_STATUSES = {'ok', 'absent', 'missing', 'locked', 'permission_denied', 'unsafe_path', 'read_error',
    'permission_denied_or_readonly_wal_unavailable', 'unsupported_schema', 'partially_unsupported_schema',
    'unsupported_layout', 'partially_unsupported_layout', 'dependency_unavailable', 'invalid_json',
    'wal_or_journal_present_unverified', 'wal_mode_unverified', 'unsupported_database_header',
    'unsafe_profile_keys_ignored', 'unsafe_directory_name_ignored', 'uninspected_symlink_entries'}
UNITS = {'file', 'directory', 'entry', 'byte', 'url', 'visit', 'download_id', 'chain_rows', 'cookie',
         'record', 'field', 'group', 'origin_store', 'profile', 'item', 'metadata', 'unknown'}
UNIT_LABELS = {'file': '文件', 'directory': '目录', 'entry': '条目', 'byte': '逻辑字节', 'url': 'URL',
              'visit': '访问记录', 'download_id': '独立下载 ID', 'chain_rows': '下载链行', 'cookie': 'Cookie',
              'record': '记录', 'field': '字段', 'group': '组', 'origin_store': '来源存储目录',
              'profile': 'Profile', 'item': '项', 'metadata': '元数据项', 'unknown': '未指定单位'}
NOTICES = [
    '这是已保存证据的离线汇总，不读取当前 Claude、Chrome、钥匙串或项目状态；各输入时间可能不同。',
    '报告成功生成、summary.complete、身份字段存在或会话关联，均不代表清理完成、当前认证有效或允许删除。',
    '批准和验证结论仅引用输入账本/回执，报告不核实人类授权或证据真实性，也不执行删除、恢复或联网。',
    '缺失、锁定、WAL、权限不足和不支持的格式均保留为未核验，不能算作零；不同统计单位不合并。',
    '默认遮罩常见身份、密钥格式及 URL 参数，但任意文件名、自由文本仍可能含敏感信息。报告为私有本地文件，分享前请复核。',
    '备份、恢复和保全结果只覆盖各自明确范围；未列出的应用、Profile、密码钥匙、云端账号和其他项目不在本报告验收范围。',
]


def require(condition, message):
    if not condition:
        raise audit.AuditError(message)


def obj(value, context='object'):
    require(isinstance(value, dict), 'Invalid ' + context)
    return value


def seq(value, context='list'):
    require(isinstance(value, list), 'Invalid ' + context)
    return value


def number(value, optional=True):
    if value is None and optional:
        return None
    require(type(value) is int and value >= 0, 'Invalid nonnegative count')
    return value


def flag(value, optional=True):
    if value is None and optional:
        return None
    require(type(value) is bool, 'Invalid boolean flag')
    return value


def text_value(value):
    require(isinstance(value, str), 'Invalid text field')
    return value


def safe_text(value):
    """Allowlisted free text still needs masking; this is not a secret detector."""
    value = text_value(value)
    def clean_url(match):
        try:
            u = urllib.parse.urlsplit(match.group(0))
            if not u.hostname:
                return '[URL]'
            hostname = u.hostname
            if ':' in hostname:
                hostname = '[' + hostname + ']'
            port = ':' + str(u.port) if u.port else ''
            return u.scheme.lower() + '://' + hostname + port + u.path
        except ValueError:
            return '[URL]'
    value = re.sub(r'[A-Za-z][A-Za-z0-9+.-]*://[^\s<>"\x27`，。；！？、（）【】「」]+', clean_url, value)
    value = re.sub(r'/(?:Users|home)/[^/\s]+', '<home>', value)
    value = re.sub(r'-(?:Users|home)-[^/\s]+', '<encoded-project>', value)
    value = re.sub(r'[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}', '<email>', value)
    value = re.sub(r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}', '<id>', value)
    value = re.sub(r'(?i)(?:sk-(?:proj-|ant-)?|gh[pousr]_|github_pat_|Bearer[ _-])[A-Za-z0-9_-]{6,}', '<secret>', value)
    value = re.sub(r'(?i)\b(?:token|password|api[_-]?key|authorization|cookie|code|state)\s*[=:]\s*[^\s,;]+', '<sensitive-field>', value)
    value = re.sub(r'(?i)\b[a-f0-9]{24,}\b', '<fingerprint>', value)
    value = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', value)
    return value


def lexical_root(value):
    # Deliberately no resolve/stat/exists: saved roots may have disappeared.
    value = text_value(value)
    require(os.path.isabs(value) and '\x00' not in value, 'Source roots must be absolute paths')
    return Path(os.path.abspath(value))


def load_saved_json(path):
    """Strict JSON with pinned no-follow reads and no duplicate keys at any depth."""
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'Duplicate JSON key')
            result[key] = value
        return result
    def invalid_constant(_):
        raise audit.AuditError('Nonstandard JSON constant')
    p = audit.safe_path(path)
    with audit.directory_fd(p.parent) as dfd:
        fd = os.open(p.name, os.O_RDONLY | audit.NOFOLLOW | getattr(os, 'O_NONBLOCK', 0), dir_fd=dfd)
        with os.fdopen(fd, 'r', encoding='utf-8') as stream:
            require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), 'Input must be a regular file')
            return json.load(stream, object_pairs_hook=pairs, parse_constant=invalid_constant)


def relative(value):
    value = text_value(value)
    require(value == '.' or (not value.startswith('/') and '\\' not in value and
            all(x not in ('', '.', '..') for x in value.split('/'))), 'Invalid relative path')
    return value


def schema(data, kind=None, upstream=False):
    obj(data)
    key = 'schema' if upstream else 'schema_version'
    require(type(data.get(key)) is int and data[key] == VERSION, 'Unsupported input schema')
    if kind:
        require(data.get('kind') == kind, 'Unexpected input kind')


def root_map(data):
    roots = obj(data.get('roots'), 'roots')
    require(bool(roots), 'Source roots are empty')
    result = {}
    for label, value in roots.items():
        require(isinstance(label, str) and re.fullmatch(r'[a-z][a-z0-9_-]{0,31}', label), 'Invalid root label')
        result[label] = lexical_root(value)
    return result


def vendor_modules():
    # Load only the installed, pinned helper; no source trees or external code.
    vendor = BASE / 'vendor' / 'cc-clean' / 'runtime'
    require(vendor.is_dir(), 'Optional CC Clean dependency is absent; Code and restore inputs need scripts/fetch_cc_clean.py --accept-unlicensed-source. Other report modules work without it.')
    try:
        dependency.inspect_installation(vendor, BASE / 'vendor/cc-clean/SOURCE.json')
    except dependency.DependencyError:
        raise audit.AuditError('Optional CC Clean dependency is incomplete or changed; inspect its provenance before use') from None
    provenance = load_saved_json(vendor / 'SOURCE.json')
    obj(provenance)
    require(provenance.get('commit') == '0be9fdafa4fdd7894997db8335eaa47720c36627', 'Unexpected pinned upstream commit')
    expected = {}
    for entry in seq(provenance.get('files')):
        obj(entry)
        path = entry.get('path'); digest = entry.get('sha256')
        require(isinstance(path, str) and path not in expected and isinstance(digest, str)
                and re.fullmatch('[0-9a-f]{64}', digest), 'Invalid provenance file entry')
        expected[path] = digest
    modules = []
    for name in ('local_state', 'review_tools'):
        relative_path = 'cc-clean/scripts/' + name + '.py'
        path = audit.safe_path(vendor / relative_path)
        content = path.read_bytes()
        require(hashlib.sha256(content).hexdigest() == expected.get(relative_path), 'Vendored helper differs from pinned provenance')
        # Execute exactly the bytes just verified, not a second mutable path read.
        module = ModuleType('cleanup_report_vendor_' + name)
        module.__file__ = str(path)
        exec(compile(content, str(path), 'exec'), module.__dict__)
        modules.append(module)
    return modules


class Builder:
    def __init__(self):
        self.rows = []
        self.inputs = []
        self.source_roots = []
        self.current = None

    def source(self, module, data, path):
        sid = 'source-' + str(len(self.inputs) + 1)
        entry = {'id': sid, 'module': module, 'file': safe_text(str(path)),
                 'observed_at': safe_text(data.get('observed_at', data.get('created_at', '时间未提供'))),
                 'coverage': '仅所提供文件中可识别的字段；未对源环境重新检查'}
        self.inputs.append(entry)
        self.current = entry

    def row(self, category, target, status='not_checked', counts=(), note='', evidence=(), approval=None):
        require(status in LABELS, 'Unknown normalized status')
        count_rows = []
        for name, value, unit in counts:
            require(unit in UNITS, 'Unknown metric unit')
            count_rows.append({'label': safe_text(name), 'value': number(value), 'unit': unit,
                               'unit_label': UNIT_LABELS[unit]})
        result = {'id': 'row-' + str(len(self.rows) + 1), 'source_id': self.current['id'],
                  'module': self.current['module'], 'category': safe_text(category),
                  'target': safe_text(target), 'status': status, 'status_label': LABELS[status],
                  'counts': count_rows, 'note': safe_text(note),
                  'evidence_refs': [safe_text(text_value(x)) for x in evidence],
                  'approval_ref': safe_text(approval) if approval else None}
        self.rows.append(result)

    def roots(self, values):
        for value in values:
            self.source_roots.append(lexical_root(str(value)))

    def build(self):
        self.rows.sort(key=lambda r: (PRIORITY[r['status']], r['module'], r['source_id'], r['id']))
        summary = dict(collections.Counter(r['status'] for r in self.rows))
        return {'schema_version': VERSION, 'kind': 'cleanup_review', 'mode': 'review-only',
                'generated_at': audit.now(), 'cleanup_authorized': False, 'restore_authorized': False,
                'operations': [], 'cleanup_completion': 'not_determined_by_report',
                'notices': NOTICES[:], 'sources': self.inputs, 'status_counts': summary,
                'row_count': len(self.rows), 'rows': self.rows}


def normalize_code(b, data):
    schema(data, upstream=True)
    require(data.get('mode') == 'metadata-only', 'Code input must be metadata-only')
    roots = root_map(data)
    b.roots(roots.values())
    trees = obj(data.get('trees'), 'trees')
    require(set(trees) == set(roots), 'Code tree roots mismatch')
    clean = {}
    core, review = vendor_modules()
    for label, tree in trees.items():
        obj(tree)
        missing = flag(tree.get('missing'), optional=False)
        entries = obj(tree.get('entries'), 'tree entries')
        require(not missing or not entries, 'Missing tree contains entries')
        rebuilt = {}
        for path, record in entries.items():
            relative(path); obj(record)
            kind = record.get('kind')
            require(kind in ('file', 'directory', 'symlink'), 'Invalid code entry kind')
            size = number(record.get('bytes', 0), optional=False)
            rebuilt[path] = {'kind': kind, 'bytes': size}
            if kind == 'directory':
                continue
            category = review.classify(path, kind, roots[label].name)
            b.row('文件元数据/' + category, label + ':' + path, 'retained', [('大小', size, 'byte')],
                  '存在性不证明属于旧账号。' + review.REASONS[category])
        clean[label] = {'missing': missing, 'entries': rebuilt}
        b.row('扫描范围', str(roots[label]), 'not_checked' if missing else 'observed',
              [('条目数', None if missing else len(entries), 'entry')],
              '源缺失，无法据此证明无使用痕迹。' if missing else '保存的元数据清单；未读取内容，也不代表清理已执行。')
    # Recompute groups from whitelisted entries, never trust an imported graph.
    graph = review.relationships(clean)
    for index, group in enumerate(graph['groups'], 1):
        b.row('会话关联', group['root'] + ':关联组-' + str(index), 'retained',
              [('关联条目', len(group['items']), 'entry')],
              '同一显式根内路径标识一致；不证明账号归属、当前使用状态或可删。' +
              ' 涉及路径：' + '；'.join(item['path'] for item in group['items']))
    if graph['unresolved']:
        b.row('会话关联', '未识别关联', 'not_checked', [('条目数', len(graph['unresolved']), 'entry')],
              '未识别标识或符号链接不能视为孤儿文件。')
    state = data.get('state')
    if state is None:
        b.row('账号状态摘要', '.claude.json', 'not_checked', note='输入没有状态摘要；认证来源、钥匙串及当前生效账号未检查。')
        return
    obj(state)
    try:
        review.validate_device_id_summary(core, state)
    except core.GuardError as exc:
        raise audit.AuditError('Invalid device-ID metadata summary') from exc
    if state.get('missing') is True:
        b.row('账号状态摘要', '.claude.json', 'not_checked', note='源状态文件缺失。')
        return
    for field, allow in (('identity_keys_present', core.IDENTITY_KEYS), ('cache_keys_present', core.CACHE_KEYS)):
        if field not in state:
            continue
        values = seq(state[field])
        require(all(isinstance(v, str) and v in allow for v in values), 'Unexpected identity/cache key')
        b.row('账号状态摘要', '身份字段' if field.startswith('identity') else '缓存字段', 'observed',
              [('存在字段', len(values), 'field')], '仅字段名：' + '、'.join(values) + '；不输出值，不据此判断实际认证来源。')
    for key, title in (('projects_count', '项目配置'), ('mcp_servers_count', 'MCP 配置'),
                       ('unclassified_top_level_key_count', '未分类顶层字段')):
        if key in state:
            b.row('账号状态摘要', title, 'observed', [(title, number(state[key]), 'entry')], '仅数量；配置存在不代表当前有效。')
    if 'device_id_field_count' in state:
        b.row('设备标识摘要', 'Device ID', 'retained', [('存在字段', state['device_id_field_count'], 'field')],
              '仅认可结构化元数据；原值、哈希、祖先键均不导出。归属未验证，默认保留。')
    else:
        b.row('设备标识摘要', 'Device ID', 'not_checked', note='旧版输入未包含递归设备标识检查。')
    b.row('认证覆盖边界', '当前有效认证', 'not_checked', note='元数据盘点未验证环境变量优先级、钥匙串载荷或真实请求所用认证。')


def db_status(record):
    obj(record)
    raw = record.get('status')
    return raw if isinstance(raw, str) and raw in DB_STATUSES else 'unrecognized_status'


def chrome_part(b, title, target, record, metrics, extra=''):
    record = obj(record)
    raw = db_status(record)
    trusted = raw == 'ok'
    partial = raw in ('partially_unsupported_schema', 'partially_unsupported_layout')
    counts = [(label, number(record.get(key)) if key in record and (trusted or partial) else None, unit)
              for key, label, unit in metrics]
    # Only the first metric is the target count. Unsupported layout counts are
    # uncertainty, never evidence of a target residual.
    positive = bool(counts and counts[0][1] is not None and counts[0][1] > 0)
    if raw in ('permission_denied', 'permission_denied_or_readonly_wal_unavailable'):
        status = 'access_denied'
    elif positive:
        status = 'residual'
    elif trusted and counts and all(v is not None for _, v, _ in counts):
        status = 'checked'
    else:
        status = 'not_checked'
    note = '保存的检查状态：' + raw + '。'
    if not trusted:
        note += ' 未完整核验；缺失或部分已观察数量不能替代整体数量，不能当作零。'
    b.row(title, target, status, counts, note + extra)


def normalize_chrome(b, data):
    schema(data, 'chrome_audit')
    b.roots([lexical_root(data.get('user_data_root'))])
    profiles = seq(data.get('profiles'), 'profiles')
    if not profiles:
        b.row('Profile 发现', '没有可用 Profile 记录', 'not_checked', note='未发现 Profile 不等于所有账号已清理。')
    for index, profile in enumerate(profiles, 1):
        obj(profile)
        raw_label = profile.get('profile')
        target = raw_label if isinstance(raw_label, str) and re.fullmatch(r'Default|Profile [0-9]+|System Profile|Guest Profile|CustomProfile-[0-9]+', raw_label) else 'Profile-' + str(index)
        if 'status' in profile:
            chrome_part(b, 'Profile 可读性', target, profile, [])
            continue
        cookies = seq(profile.get('cookies', []))
        if not cookies:
            b.row('Cookie', target, 'not_checked', note='输入未提供 Cookie 检查。')
        for cindex, cookie in enumerate(cookies, 1):
            chrome_part(b, 'Cookie', target + '/Cookie 源-' + str(cindex), cookie,
                        [('target_cookie_count', '目标 Cookie', 'cookie'),
                         ('target_partitioned_cookie_count', '其中分区 Cookie', 'cookie')],
                        ' 两个数据库布局如同时存在，分别列示，不自动相加。')
        history = obj(profile.get('history', {}))
        for key, title, metrics in (
            ('urls', '历史 URL', [('target_url_count', 'URL 数', 'url')]),
            ('visits', '历史访问', [('target_visit_count', '访问次数', 'visit')]),
            ('downloads', '下载记录', [('target_unique_download_ids', '独立下载 ID', 'download_id'),
                ('target_chain_row_count', '来源链行', 'chain_rows'),
                ('matching_download_records', '实际下载记录', 'download_id'),
                ('orphan_target_chain_ids', '未匹配下载 ID', 'download_id')])):
            record = obj(history.get(key, {}))
            chrome_part(b, title, target, record, metrics, ' UI 行数不能替代数据库结果。')
            if key == 'downloads' and 'downloads_table' in record:
                part = obj(record['downloads_table'])
                if db_status(part) != 'ok':
                    chrome_part(b, '下载主表', target, part, [])
        passwords = obj(profile.get('passwords', {}))
        for name in ('Login Data', 'Login Data For Account'):
            chrome_part(b, '保存的登录记录', target + '/' + name, passwords.get(name, {}),
                        [('target_login_record_count', '目标记录', 'record')], ' 不包含 Passkey、远端同步或有效会话验收。')
        for key, title, metrics in (
            ('bookmarks', '书签', [('target_bookmark_count', '目标书签', 'record')]),
            ('preferences', '网站权限元数据', [('target_key_count', '目标键', 'field'),
                ('unsupported_category_count', '未支持分类', 'entry')]),
            ('indexeddb', 'IndexedDB', [('target_origin_store_count', '识别到的目标存储', 'origin_store'),
                ('unrecognized_entries', '未识别条目', 'entry'), ('symlink_entries_skipped', '跳过的链接', 'entry')])):
            chrome_part(b, title, target, profile.get(key, {}), metrics,
                        ' 未识别布局、跳过链接不能当作目标为零；仅覆盖记录列明的检查面。')
        extension = obj(profile.get('official_extension', {}))
        exists = flag(extension.get('official_extension_directory_exists'))
        raw = db_status(extension)
        status = 'residual' if exists is True else ('not_found' if exists is False and raw in ('ok', 'absent') else 'not_checked')
        b.row('官方扩展目录', target, status, [('存在目录', int(exists) if exists is not None else None, 'directory')],
              '只检查已知官方扩展目录；不覆盖所有扩展、PWA、NativeHost 或运行状态。')
    for warning in seq(data.get('warnings', [])):
        chrome_part(b, '发现阶段未核验项', 'Profile 枚举', warning, [])
    b.row('浏览器覆盖边界', '未由此工具检查的内容', 'not_checked',
          note='LocalStorage、Service Worker、全部缓存、Passkey、同步、远端账号状态须由其他证据另行核实。')


def normalize_protection(b, data):
    schema(data, 'comparison')
    root = lexical_root(data.get('root')); b.roots([root])
    summary = obj(data.get('summary'))
    changes = seq(data.get('changes'))
    errors = number(summary.get('source_errors'))
    hashes = obj(summary.get('hash_comparisons', {}))
    counts = [('元数据变化', len(changes), 'entry'), ('源扫描错误', errors, 'entry')]
    for key, title in (('equal', '双方哈希一致'), ('different', '双方哈希不同'),
                       ('both_absent', '双方无哈希'), ('before_absent', '之前无哈希'), ('after_absent', '之后无哈希')):
        if key in hashes:
            counts.append((title, number(hashes[key]), 'file'))
    b.row('项目保护比对', str(root), 'not_checked' if errors is None or errors else ('changed' if changes else 'checked'), counts,
          '元数据相同不等于字节一致；哈希覆盖只限双方提供的文件。活跃目录扫描不是原子快照。')
    for change in changes:
        obj(change); path = relative(change.get('path'))
        action = change.get('change')
        require(action in ('added', 'missing', 'changed'), 'Invalid comparison change')
        category = 'Finder 元数据变化' if Path(path).name == '.DS_Store' else '项目条目变化'
        b.row(category, path, 'changed', note='比对结果：' + action + '；记录变化，不自动推定由清理造成。')


def normalize_duplicates(b, data):
    schema(data, 'duplicates')
    roots = [lexical_root(data.get('copies_root'))] + [lexical_root(p) for p in seq(data.get('original_roots'))]
    b.roots(roots)
    matches, unmatched = seq(data.get('matches')), seq(data.get('unmatched'))
    errors = seq(data.get('errors', []))
    b.row('保留副本比对', str(roots[0]), 'partial' if errors else 'observed',
          [('匹配副本', len(matches), 'file'), ('未匹配副本', len(unmatched), 'file'), ('错误', len(errors), 'entry')],
          '仅在显式原件根的可读候选中比较。未匹配不表示无用、全局唯一或可删；按副本路径计数，不等于物理磁盘占用。')
    for match in matches:
        obj(match); path = relative(match.get('path'))
        originals = seq(match.get('originals'))
        targets = []
        for original in originals:
            obj(original)
            oroot = lexical_root(original.get('root'))
            require(oroot in roots[1:], 'Duplicate mapping root outside declared roots')
            targets.append(str(oroot) + '/' + relative(original.get('path')))
        require(bool(targets), 'Duplicate match lacks original')
        require(isinstance(match.get('sha256'), str) and re.fullmatch(r'[0-9a-f]{64}', match['sha256']), 'Invalid duplicate hash evidence')
        b.row('字节匹配副本', path, 'retained', [('大小', number(match.get('size')), 'byte')],
              '输入记载同大小及 SHA-256 匹配；未重新读取文件，不能自动删除。对应：' + '；'.join(targets))
    for item in unmatched:
        obj(item); path = relative(item.get('path'))
        status = item.get('status')
        known = {'no_same_size_candidate_in_readable_inventory', 'hash_read_failed', 'no_equal_hash_in_readable_candidates'}
        require(status in known, 'Invalid unmatched status')
        b.row('未匹配副本', path, 'not_checked' if status == 'hash_read_failed' else 'retained',
              [('大小', number(item.get('size')), 'byte')], '输入结果：' + status + '。用途和保留价值仍需判断。')


def normalize_restore(b, data):
    schema(data, 'restore-observation', upstream=True)
    roots = root_map(data); b.roots(roots.values())
    for key in ('backup_dir', 'pre_restore_backup'):
        if key in data:
            b.roots([lexical_root(data[key])])
    selected = seq(data.get('selected_results')); changes = seq(data.get('unselected_changes'))
    claimed = data.get('status')
    require(claimed in ('verified', 'partial', 'failed'), 'Invalid restore status')
    unchanged = flag(data.get('unselected_unchanged'), optional=False)
    good = 0
    core, review = vendor_modules()
    for item in selected:
        obj(item)
        require(item.get('root') in roots and item.get('result') in ('verified', 'unverified', 'mismatch'), 'Invalid restore result')
        relative(item.get('path'))
        result = item['result']
        try:
            expected = review.receipt_metadata(core, item.get('expected'))
            observed = review.receipt_metadata(core, item.get('observed'))
        except core.GuardError as exc:
            raise audit.AuditError('Invalid restore observation metadata') from exc
        if result == 'verified' and (expected is None or expected != observed):
            result = 'unverified'
        good += result == 'verified'
        b.row('恢复选中项', item['root'] + ':' + item['path'],
              'verified' if result == 'verified' else ('changed' if result == 'mismatch' else 'not_checked'),
              note='回执结果：' + result + '；报告未重新读取目标，不输出文件哈希、链接目标或其他载荷。')
    for item in changes:
        obj(item)
        require(item.get('root') in roots and item.get('result') == 'unselected-entry-changed', 'Invalid unselected change')
        b.row('恢复未选中项', item['root'] + ':' + relative(item.get('path')), 'changed',
              note='回执记载未选中条目发生变化，不能宣称完整恢复验收。')
    consistent = bool(selected) and good == len(selected) and not changes and unchanged and data.get('observation_error') is None
    overall = 'verified' if consistent and claimed == 'verified' else ('partial' if good else 'failed')
    b.row('恢复验收范围', '输入回执', overall,
          [('选中项', len(selected), 'file'), ('回执验证项', good, 'file'), ('未选中变化', len(changes), 'entry')],
          '本报告没有执行恢复，也没有核验授权。只引用回执；ACL 与扩展属性内容须独立验收。' +
          (' 输入总状态与细项不一致，已降低结论。' if claimed == 'verified' and not consistent else ''))


def normalize_ledger(b, data):
    schema(data, 'cleanup_ledger')
    require(data.get('mode') in ('audit', 'maintenance', 'uninstall'), 'Invalid ledger mode')
    text_value(data.get('run_id')); text_value(data.get('observed_at'))
    scope = obj(data.get('scope', {}))
    b.roots([lexical_root(p) for p in seq(scope.get('protected_roots', []))])
    seen = set()
    for item in seq(data.get('objects')):
        obj(item); identity = text_value(item.get('id'))
        require(identity and identity not in seen, 'Duplicate or empty ledger identity'); seen.add(identity)
        status = item.get('status'); require(status in LEDGER_STATUSES, 'Invalid ledger status')
        evidence = [text_value(x) for x in seq(item.get('evidence_refs', []))]
        evidence = [x for x in evidence if x.strip()]
        limitations = [text_value(x) for x in seq(item.get('limitations', []))]
        before_count = number(item.get('before_count'))
        after_count = number(item.get('after_count'))
        if status == 'verified_removed':
            if after_count is not None and after_count > 0:
                status = 'residual'
                limitations.append('数量与结论冲突：之后数量仍大于零，不能保持已验证移除状态，按残留列示。')
            elif not evidence:
                status = 'attempted_unverified'
                limitations.append('缺少非空验收证据引用，不能保持已验证移除状态。')
        unit = item.get('unit', 'unknown'); require(unit in UNITS, 'Invalid ledger unit')
        kind = text_value(item.get('kind', '未分类'))
        batch = text_value(item.get('batch', '未分批'))
        action = text_value(item.get('action', '未说明'))
        locator = text_value(item.get('locator', identity))
        b.row('清理账本/' + batch + '/' + kind, locator, status,
              [('之前', before_count, unit), ('之后', after_count, unit)],
              '动作记载：' + action + '。' + '；'.join(limitations) +
              ' 批准引用及证据仅作展示，报告不确认授权真实性或执行结果。', evidence,
              text_value(item['approval_ref']) if item.get('approval_ref') is not None else None)


def normalize_auth(b, data):
    schema(data, 'auth-candidates', upstream=True)
    keys = ('ANTHROPIC_API_KEY', 'ANTHROPIC_AUTH_TOKEN', 'CLAUDE_CODE_OAUTH_TOKEN',
            'ANTHROPIC_BASE_URL', 'CLAUDE_CONFIG_DIR', 'CLAUDE_SECURESTORAGE_CONFIG_DIR')
    if 'roots' in data and data['roots']:
        b.roots(root_map(data).values())
    def candidate(source, key, value):
        obj(value)
        present = flag(value.get('present'), optional=False)
        require(value.get('value_recorded') is False and value.get('value_hash_recorded') is False,
                'Authentication candidate must not contain recorded values or hashes')
        typ = value.get('value_type')
        require(typ in ('null', 'boolean', 'number', 'string', 'array', 'object', None), 'Invalid authentication value type')
        empty = flag(value.get('empty'))
        require((not present and typ is None and empty is None) or (present and typ is not None and empty is not None),
                'Inconsistent authentication presence metadata')
        note = '候选存在：' + ('是' if present else '否') + '；类型：' + (typ or '未提供') + '；空值：' + ('未核验' if empty is None else ('是' if empty else '否')) + '。'
        if key == 'apiKeyHelper':
            require(value.get('executed') is False, 'Report accepts unexecuted helper metadata only')
            note += '未执行辅助程序。'
        endpoint = value.get('endpoint')
        if endpoint is not None:
            require(key == 'ANTHROPIC_BASE_URL', 'Unexpected endpoint metadata')
            obj(endpoint)
            status = endpoint.get('status')
            require(status in ('parsed', 'empty_or_nonstring', 'invalid_or_unsupported'), 'Invalid endpoint status')
            if status == 'parsed':
                scheme = endpoint.get('scheme'); host = endpoint.get('host'); port = endpoint.get('port')
                require(scheme in ('http', 'https') and isinstance(host, str) and bool(host)
                        and not any(c.isspace() or c in '/@?#\\%' for c in host), 'Unsafe endpoint metadata')
                require(port is None or (type(port) is int and 0 <= port <= 65535), 'Invalid endpoint port')
                display_host = '[' + host + ']' if ':' in host else host
                note += '端点：' + scheme + '://' + display_host + (':' + str(port) if port else '') + '。仅显示主机和端口。'
            else:
                note += '端点未解析。'
        note += '不据此断言有效认证、优先级、账号归属或可删除。'
        b.row('认证来源候选', source + '/' + key, 'observed', note=note)
    for index, setting in enumerate(seq(data.get('settings')), 1):
        obj(setting)
        label = setting.get('label')
        source = label if isinstance(label, str) and re.fullmatch(r'[a-z][a-z0-9_-]{0,31}', label) else '设置源-' + str(index)
        variables = obj(setting.get('variables'))
        for key in keys:
            if key in variables:
                candidate(source, key, variables[key])
            else:
                b.row('认证来源候选', source + '/' + key, 'not_checked', note='输入缺少该变量存在性检查。')
        if 'apiKeyHelper' in setting:
            candidate(source, 'apiKeyHelper', setting['apiKeyHelper'])
    inherited = data.get('helper_environment')
    if inherited is not None:
        obj(inherited)
        for key in keys:
            if key in inherited:
                candidate('辅助进程继承环境', key, inherited[key])
        if not inherited:
            b.row('认证覆盖边界', '辅助进程继承环境', 'not_checked', note='输入未提供环境候选检查。')
    else:
        b.row('认证覆盖边界', '辅助进程继承环境', 'not_checked', note='未读取继承环境；未检查其他进程的环境。')
    b.row('认证覆盖边界', '实际生效认证与账号', 'not_checked',
          note='仅已保存候选元数据；不读取钥匙串、不执行 apiKeyHelper、不发起认证请求，不解析优先级。')


def normalize_backup(b, data):
    schema(data, 'policy-backup-receipt', upstream=True)
    require(data.get('status') == 'policy_backup_verified', 'Unsupported policy backup status')
    policy = obj(data.get('policy'))
    require(type(policy.get('schema')) is int and policy['schema'] == 1, 'Unsupported backup policy schema')
    mode = policy.get('mode'); strategy = policy.get('backup_policy')
    require(mode in ('maintenance', 'uninstall') and strategy in ('work-products', 'sensitive-recovery'),
            'Invalid backup mode or strategy')
    b.roots(root_map(policy).values())
    b.roots([lexical_root(data.get('backup_dir'))])
    counts = obj(data.get('classification_counts'))
    known = {'work_product': '工作成果', 'nonsecret_config': '经人工分类的非敏感配置', 'sensitive_state': '敏感状态'}
    require(set(counts) <= set(known), 'Unexpected backup classification')
    metrics = [(known[key], number(value, optional=False), 'file') for key, value in counts.items()]
    coverage = number(data.get('reviewed_hash_coverage'), optional=False)
    require(coverage <= sum(value for _, value, _ in metrics), 'Backup hash coverage exceeds classified files')
    metrics.append(('审阅时提供哈希', coverage, 'file'))
    sensitive = data.get('contains_sensitive_originals')
    require(sensitive is True or sensitive == 'possible_unverified', 'Invalid sensitive-originals flag')
    require(data.get('authorization_verified_by_helper') is False and data.get('writer_state_verified_by_helper') is False,
            'Backup helper must not claim human authorization or writer-state verification')
    require(data.get('arbitrary_embedded_secrets_detected') is False, 'Unexpected arbitrary secret detection claim')
    blocked = flag(data.get('known_sensitive_paths_blocked'), optional=False)
    flag(data.get('copied_source_unchanged'), optional=False)
    flag(data.get('source_changed_by_tool'), optional=False)
    if strategy == 'sensitive-recovery':
        require(mode == 'maintenance' and sensitive is True and blocked is False,
                'Sensitive recovery is inconsistent with backup policy')
    else:
        require(sensitive == 'possible_unverified' and blocked is True and not counts.get('sensitive_state', 0),
                'Work-product policy cannot assert secret-free or classify sensitive copies')
    note = '模式：' + mode + '；策略：' + strategy + '；contains_sensitive_originals=' + ('true' if sensitive is True else 'possible_unverified') + '。'
    note += ('明确保留了敏感原件。' if sensitive is True else '已阻止已知敏感路径，但不能保证任意文件内容没有秘密。')
    note += '只描述已保存回执，未实时检查备份或源；不输出策略原文、文件清单或哈希。授权和写入者静止性未由辅助工具验证；审阅哈希覆盖不等于全部文件无敏感内容。'
    b.row('备份保留情况', '已保存策略回执', 'residual' if sensitive is True else 'not_checked', metrics, note)


NORMALIZERS = {'code': normalize_code, 'auth': normalize_auth, 'chrome': normalize_chrome, 'protection': normalize_protection,
               'duplicates': normalize_duplicates, 'backup': normalize_backup, 'restore': normalize_restore, 'ledger': normalize_ledger}
MODULE_NAMES = {'code': 'Claude Code', 'auth': '认证来源', 'chrome': 'Chrome', 'protection': '项目保护',
                'duplicates': '副本价值核查', 'backup': '备份保留', 'restore': '恢复验收', 'ledger': '清理账本'}


def load_sources(specifications):
    builder = Builder()
    specifications = list(specifications)
    require(bool(specifications), 'At least one saved evidence input is required')
    require(sum(kind == 'ledger' for kind, _ in specifications) <= 1,
            'Only one cleanup ledger is supported per report')
    files = []
    for kind, path in specifications:
        require(kind in NORMALIZERS, 'Unknown input module')
        p = audit.safe_path(path)
        require(p.is_file(), 'Evidence input must be a file')
        data = load_saved_json(p)
        obj(data)
        builder.source(MODULE_NAMES[kind], data, p)
        NORMALIZERS[kind](builder, data)
        files.append(p)
    return builder.build(), builder.source_roots, files


def md_text(value):
    value = html.escape(str(value), quote=False).replace('\r', ' ').replace('\n', ' ')
    return re.sub(r'([\\`*_{}\[\]()#+.!|~-])', r'\\\1', value)


def metric_text(row):
    return '；'.join(m['label'] + '：' + ('未核验' if m['value'] is None else str(m['value'])) + ' ' + m['unit_label'] for m in row['counts'])


def render_markdown(payload):
    lines = ['# Claude Mac 清理证据汇总', '', '只读审阅 · 不授予删除或恢复权限', '',
             '生成时间：' + md_text(payload['generated_at']), '', '**本报告不判定整机清理完成。**', '']
    lines += ['- ' + md_text(x) for x in payload['notices']]
    lines += ['', '## 输入覆盖范围', '', '| 模块 | 保存的证据 | 观察时间 |', '|---|---|---|']
    for source in payload['sources']:
        lines.append('| ' + ' | '.join(md_text(source[k]) for k in ('module', 'file', 'observed_at')) + ' |')
    lines += ['', '## 对象与检查项', '', '| 模块 / 类别 | 状态 | 对象 | 数量和单位 | 证据与限制 |', '|---|---|---|---|---|']
    for row in payload['rows']:
        detail = row['note']
        if row['evidence_refs']:
            detail += ' 证据引用：' + '；'.join(row['evidence_refs'])
        if row['approval_ref']:
            detail += ' 批准引用：' + row['approval_ref']
        lines.append('| ' + ' | '.join(md_text(v) for v in (row['module'] + ' / ' + row['category'],
            row['status_label'], row['target'], metric_text(row), detail)) + ' |')
    lines += ['', '本文件仅汇总证据：cleanup_authorized=false；restore_authorized=false；operations=[]。', '']
    return '\n'.join(lines)


def render_html(payload):
    asset = audit.safe_path(BASE / 'assets' / 'report.html')
    template = asset.read_text(encoding='utf-8')
    require(template.count('__PAYLOAD__') == 1 and template.count('__CSP__') == 1, 'Invalid report asset')
    scripts = re.findall(r'<script>([\s\S]*?)</script>', template)
    styles = re.findall(r'<style>([\s\S]*?)</style>', template)
    require(len(scripts) == 1 and len(styles) == 1, 'Unexpected inline asset blocks')
    hashed = lambda s: base64.b64encode(hashlib.sha256(s.encode('utf-8')).digest()).decode('ascii')
    policy = "default-src 'none'; connect-src 'none'; img-src 'none'; font-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; script-src 'sha256-" + hashed(scripts[0]) + "'; style-src 'sha256-" + hashed(styles[0]) + "'"
    # A data JSON node cannot close its own script tag, even with malicious input.
    raw = json.dumps(payload, ensure_ascii=False, separators=(',', ':')).replace('&', '\\u0026').replace('<', '\\u003c').replace('>', '\\u003e').replace('\u2028', '\\u2028').replace('\u2029', '\\u2029')
    return template.replace('__CSP__', html.escape(policy, quote=True)).replace('__PAYLOAD__', raw)


def write_text_new(path, content, roots):
    p = audit.check_output(path, roots)
    with audit.directory_fd(p.parent) as dfd:
        pinned = os.fstat(dfd)
        fd = os.open(p.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | audit.NOFOLLOW, 0o600, dir_fd=dfd)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(content.encode('utf-8')); stream.flush(); os.fsync(stream.fileno())
        with audit.directory_fd(p.parent) as current_fd:
            current = os.fstat(current_fd)
            require((current.st_dev, current.st_ino) == (pinned.st_dev, pinned.st_ino), 'Output directory changed; location unverified')
    return p


def render(specifications, out_html, out_md):
    payload, roots, inputs = load_sources(specifications)
    outputs = [audit.check_output(path, roots) for path in (out_html, out_md)]
    require(outputs[0] != outputs[1], 'HTML and Markdown outputs must differ')
    require(all(p not in inputs for p in outputs), 'Outputs cannot replace inputs')
    # Render and validate both before writing either. A later filesystem failure
    # can leave one newly created report; never delete a pre-existing artifact.
    documents = [render_html(payload), render_markdown(payload)]
    for path, document in zip(outputs, documents):
        write_text_new(path, document, roots)
    return payload


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for kind in NORMALIZERS:
        parser.add_argument('--' + kind, action='append')
    parser.add_argument('--out-html', required=True); parser.add_argument('--out-md', required=True)
    args = parser.parse_args(argv)
    if len(args.ledger or []) > 1:
        parser.error('--ledger may be provided only once')
    try:
        specifications = []
        for kind in NORMALIZERS:
            value = getattr(args, kind)
            specifications.extend((kind, p) for p in value or [])
        payload = render(specifications, args.out_html, args.out_md)
        print(json.dumps({'status': 'review_only_report_written', 'inputs': len(payload['sources']),
                          'rows': payload['row_count'], 'cleanup_authorized': False,
                          'restore_authorized': False, 'operations': []}, ensure_ascii=False))
        return 0
    except (OSError, ValueError, KeyError, TypeError, ImportError, RecursionError) as exc:
        # Never echo raw JSON, free-form data, source paths, URLs or exception text.
        print(json.dumps({'status': 'failed', 'error_type': type(exc).__name__,
                          'reason': 'Input or output validation failed; any already-created outputs are review-only.'}), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
