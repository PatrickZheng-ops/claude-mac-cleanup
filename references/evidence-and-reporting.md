# 证据、辅助工具、交付与续跑

## 建立本轮目录

使用本机当前时间和唯一后缀，在有效本地配置的 `audit_base` 下创建 `Claude_Cleanup_Audit_<本轮时间>_<唯一标识>`，权限 700；审计文件 600。审计目录不得位于待删除树或保护基线根内。目录必须新建，不能复用旧轮路径或覆盖历史证据。配置格式和校验见 [first-run.md](first-run.md)。配置与本轮审计都只存于使用者本机，不提交到技能仓库。

| 文件 | 内容 |
|---|---|
| `00_scope.md` | 用户目标、模式、保护根、排除项、批准依据、远端和同步范围 |
| `01_inventory.json` | 本轮发现的对象、身份与依赖、风险、发现错误 |
| `02_batch_plan.md` | B1–B4 的具体对象、删除方式、数量/大小、批准状态及最终结果 |
| `03_actions.jsonl` | 逐动作追加日志；尝试前记意图，完成后记结果，不改写历史 |
| `04_verification.md` | 各类对象前后证据、保护验证、覆盖范围、时间与失败 |
| `05_restore_map.json` | 原路径、保留/废纸篓目的路径、哈希和恢复限制；不可恢复项明确标注 |
| `06_remaining.md` | 每个残留/受限/未检查项、原因、尝试、影响及下一步 |
| `Claude_Cleanup_Report.md` / `.html` | 同一终态生成的中文最终报告；不再残留“待执行”旧结论 |

另附必要的快照、比对与只读浏览器结果，文件名区分 before/after 和检查轮次。日志不需要装下全部原始数据；数量和证据足够支持结论即可。

## 对象台账约定

每个对象有稳定的本轮 ID，至少包含：`kind`、`batch`、`locator`、`identity_evidence`、`dependencies`、`protection_conflicts`、`action`、`approval_ref`、`before`、`after`、`status`、`observed_at`、`restore_ref`、`limitations`。

- 文件 locator：绝对路径、lstat 类型、dev/inode，按需要增加哈希；不把可执行命令当路径拼接。用参数数组或正确 shell 引号，不能用 JSON 字符串替代 shell 转义。
- 浏览器 locator：本地匿名 Profile 标识、域、数据类别、必要的非秘密内部记录 ID；完整 URL/账号/凭据不入报告。
- Keychain locator：service+类型+脱敏账户标识。需要精确账户值定位时只在受控工具内部使用，不回显。
- 数量保留单位，例如“根对象”“普通文件”“UI 行”“URL”“visit”“download ID”“chain row”“Cookie”。缺失数值写 `null` 和原因，不填 0。
- 大小分别为逻辑字节、分配字节。父子根去重、硬链接按 dev+inode 去重；APFS 克隆、稀疏文件、系统快照会影响真实空间，不能把逻辑字节当释放空间。若测可用空间，给前后时点且说明并行活动影响。

终态采用下列词汇之一，另存结果时间：

| 状态 | 含义 |
|---|---|
| `verified_removed` | 本轮确已删除并通过对应持久化检查 |
| `moved_to_trash` | 已从原路径移入准确废纸篓位置；不等于永久清除 |
| `retained` | 明确保留，说明保护理由 |
| `not_found` | 在明确可读范围和时间内未发现；不是错误/未检查 |
| `access_denied` / `not_checked` | 受限或尚未检查，不能归零 |
| `attempted_unverified` | 已提交动作但结果未被可靠复核，例如数据库仍锁定 |
| `failed` / `residual` | 操作失败，或复核确认目标仍存在 |

历史记录另设 `evidence_level=historical`，不能假装是当前终态。辅助脚本有更细的技术状态，映射进台账时保留原状态及限制。

## 只读工具调用

先确认 Python 3.10+ 可用；macOS 系统版本不足时使用 Codex 已有依赖运行时的绝对路径，不修改全局安装。以下相对命令在技能目录执行；实际路径用工具参数或正确引号传入。`AUDIT_DIR`、`PROJECT_ROOT`、`PRESERVED_ROOT`、`CHROME_DATA_ROOT` 代表本轮已经核准的路径，不要原样运行占位符。审计输出父目录必须存在，输出文件必须不存在。

```text
python3 scripts/audit_tools.py snapshot --root PROJECT_ROOT --out AUDIT_DIR/project_before.json
python3 scripts/audit_tools.py snapshot --root PROJECT_ROOT --out AUDIT_DIR/project_after.json
python3 scripts/audit_tools.py compare --before AUDIT_DIR/project_before.json --after AUDIT_DIR/project_after.json --out AUDIT_DIR/project_comparison.json
python3 scripts/audit_tools.py duplicates --copies PRESERVED_ROOT --original PROJECT_ROOT --out AUDIT_DIR/duplicates.json
python3 scripts/audit_tools.py chrome --user-data-dir CHROME_DATA_ROOT --out AUDIT_DIR/chrome_before.json
```

- `snapshot --hash` 为普通文件增加 SHA-256，适用于内部保全副本/重要小范围。不是每轮必须对全部大型项目算哈希。
- `duplicates` 支持重复 `--original`，比较根不能互相包含，也不能与副本根重叠。同大小候选才读内容；输出详细匹配路径，但终端只显示汇总。
- `chrome --domain claude.ai --domain example.org` **替换**默认域集合，不是追加；先核准目标归属。默认候选域为 Claude/Anthropic 官方域名；额外目标须有本轮归属证据，结果本身不授权清理。
- 输出 `summary.complete` 只表示该工具声明覆盖的读取完成情况，**不表示清理完成、无残留或整个浏览器已完整检查**。完整检查也可以发现非零目标。
- 退出码 0：工具所覆盖读取完成；2：已保存报告但有未核验来源；1：输入/输出校验失败。只读报告中的缺失源需进一步判断布局/未使用，不能直接据此声称全零。
- 活跃文件系统扫描不是原子快照；最终对照应在相关写入源正常退出后进行。不读/复制秘密值，不执行源目录里的任何脚本。
- 工具拒绝路径中的符号链接；macOS 的 `/tmp` 等系统别名也会被拒绝。确需临时目录时先核实其真实路径，再显式传入例如 `/private/tmp` 下的本轮目录；不要因此放宽源树内符号链接越界检查。

### 覆盖范围和局限

`snapshot`：元数据和可选内容哈希，符号链接不跟随，文件硬链接去重计算容量；它不是 APFS 快照，也不测量实际释放空间。

`compare`：只接受同一根的快照；缺失哈希明确列出；`.DS_Store` 变化单独归类但仍呈现。扫描错误导致完整性不足。

`duplicates`：相同 SHA-256 是扫描时字节一致的证据；未匹配与无价值无关，文件读取失败时比较不完整。统计副本路径数，不把副本字节合计当磁盘物理占用。

`chrome`：Cookie 总数与分区分类、History URL/visit、下载唯一 ID/来源链、两种 Login Data、书签、部分 Preferences、官方扩展历史 ID 目录、可识别 IndexedDB 来源目录。合并标准目录、Local State 的安全单层目录名，以及含已知标记的自定义目录；现存 System/Guest 也检查。自定义 Profile 输出本轮匿名编号，跨轮可能变化，动作定位需重新核准实际目录，不能把编号当固定路径。Preferences **仅** `profile.content_settings.exceptions`；IndexedDB **仅**可识别 origin 命名，不解析 LevelDB。Local Storage、Service Worker、Cache、Passkey、同步、PWA、扩展实际启用状态仍需单独检查。发现额外用户数据根必须另运行并列明。

SQLite 使用只读连接且不以 `immutable` 忽略日志；只要存在 WAL/SHM/journal，或数据库头显示 WAL 模式，就不连接，返回明确未核验状态。遇到此状态，正常关闭写入源后再试；仍然存在就登记未核验，不修复/检查点/删日志、不复制整库来绕过。它不能隔离其他进程在检查后重新打开数据库的竞争，执行前必须正常关闭相关写入程序，不能宣称提供原子快照。

辅助测试：`python3 scripts/test_audit_tools.py`。测试使用临时合成资料，验证边界与计数，不代表已在当前真实 Chrome 版本上完成清理验收。

## 统一报告工具

`scripts/report_tools.py` 仅导入已保存 JSON，不再打开这些报告所指向的 Claude/Chrome/项目源。至少提供一种输入；除单一 `--ledger` 外，各输入参数可以重复，用于多个显式配置根或 Chrome 用户数据目录。其输出只是证据汇总，Agent 仍须依照本节末尾完成门槛写出范围明确的最终结论。

```text
python3 -B scripts/report_tools.py --code AUDIT_DIR/code.json --auth AUDIT_DIR/auth.json --chrome AUDIT_DIR/chrome_after.json --protection AUDIT_DIR/project_comparison.json --duplicates AUDIT_DIR/duplicates.json --backup BACKUP_DIR/policy-receipt.json --restore AUDIT_DIR/restore-receipt.json --ledger AUDIT_DIR/final-ledger.json --out-html AUDIT_DIR/Claude_Cleanup_Report.html --out-md AUDIT_DIR/Claude_Cleanup_Report.md
```

只保留本轮实际已产生的输入参数。缺少模块就披露未覆盖，不制作假的全零输入凑齐报告。输入来源时间与报告生成时间分别显示，历史结果不能冒充本轮验收。恢复或备份回执在此只被读取，不代表重新验证备份、签名或当前源。

报告兼容的台账是完整动作日志的终态投影，采用以下格式；原始追加动作日志仍独立保留，不用覆盖旧记录的方法生成投影：

```json
{
  "schema_version": 1,
  "kind": "cleanup_ledger",
  "run_id": "current-run-unique-id",
  "mode": "uninstall",
  "observed_at": "2000-01-01T00:00:00Z",
  "scope": {"protected_roots": ["/本轮已确认的原项目"]},
  "objects": [{
    "id": "browser-cookie-1",
    "kind": "partitioned_cookie",
    "batch": "B2",
    "status": "residual",
    "locator": "本轮匿名 Profile / 已核准域 / 分区 Cookie",
    "action": "精确网站数据清理后复核",
    "before_count": 1,
    "after_count": 1,
    "unit": "cookie",
    "evidence_refs": ["chrome_after.json:对应条目"],
    "approval_ref": "本轮同范围批准引用",
    "limitations": ["持久化复核仍存在；不能算作已删除"]
  }]
}
```

上例仅为格式示意，不是当前机器观察。数量只接收非负整数或 null，布尔值不能冒充整数。支持的单位为 `file`、`directory`、`entry`、`byte`、`url`、`visit`、`download_id`、`chain_rows`、`cookie`、`record`、`field`、`group`、`origin_store`、`profile`、`item`、`metadata`、`unknown`；不把不同单位加成一个“文件数”。

状态使用前述终态词汇，另接受 `planned`、`approved` 表达未完成项。`verified_removed` 缺少非空 `evidence_refs` 会降为 `attempted_unverified`；如果明确 `after_count > 0`，改为 `residual` 并标注数量与结论矛盾。after_count 为 null 不单独证明失败，但需有其他验收证据。有引用也只是引用输入声明，报告不会替用户批准或证明引用真实。CLI 和程序入口均拒绝多份 ledger，避免同一对象产生两个最终结论。恢复选中项成功但未选项改变，整体验收仍为部分/失败。

HTML 与 Markdown 来自同一个规范化数据集，残留、失败和未核验项靠前，默认显示全部条目；HTML 支持搜索、模块/状态筛选、可选分页和审阅 JSON 导出。打印时展示全部当前筛选项，打印后恢复分页。导出恒为 `cleanup_authorized=false`、`restore_authorized=false`、`operations=[]`，筛选和导出不能触发操作。

HTML 为离线文件，内容通过白名单重建及文本节点展示，脚本/样式使用 CSP 哈希，网络连接禁用。生成器遮罩常见身份、密钥格式与 URL 参数，但任意文件名或自由文字不保证完全无敏感信息；权限为 600，分享前仍须复核。不能直接把含秘密的原始 JSON 嵌入 HTML，不能把原始错误文字当安全显示文本。

输入和输出均拒绝符号链接；输出不覆盖旧文件，不落入所提供证据声明的源根或保护根。生成中后段失败可能留下一个新报告，必须如实登记；不清理用户已有文件来掩盖失败。退出码 0 仅表示报告已生成，1 表示输入/输出验证失败。

统一自测：`python3 -B scripts/check_skill.py --node /实际Node路径`。只运行技能文件结构、来源哈希、脚本语法与临时合成夹具；临时 HOME 与精简环境防止借用真实认证。未找到 Node 时 JavaScript 验证明确为 `not_checked`，整体不记全通过。可选上游未取得时，其测试标为未执行，基础套件通过不能代替完整套件通过。技能格式可另用所在 Agent 平台的技能校验器验收。

## 中断后继续

先确认审计目录确实是本轮，读取 scope、批准、动作台账与 remaining。按对象恢复：已验证对象必要时只读复核；已提交未验证对象先验收，不直接再次删除；未执行对象复核身份后继续。

新发现对象先追加 inventory，不覆盖原批准。对象范围未变可继续；新增共享/不可逆风险另行判断。报告丢失时不能伪造重建原始执行日志；建立新核查记录，标明哪些来自历史对话、哪些是当前证据。

## 最终报告与完成门槛

报告开头先给“截至什么时间，哪些本机范围已完成，哪些明确保留/残留/未检查”。随后包括批次终态、删除方式与恢复边界、容量口径、保护验证、保留产出价值、各 Profile 分类结果、Office 四层结论、失败路径及剩余项。

残留说明必须包含：精确安全身份、最后观察时间、做过什么、当前证据、为什么没有继续扩大、下一步需要的唯一动作/新增方法。不能将“本技能限制直接写库”包装成“系统技术上永久不能删”。

交付前检查：

- 所有批准对象有终态，未验证动作没有伪装成成功。
- 原项目、保留副本、共享服务的关键检查已完成并说明证据强度。
- 每个实际发现 Profile 有覆盖记录，缺失/锁定/未知不是零。
- 报告与 inventory/plan/actions/remaining 数量、方式和状态一致。
- Markdown/HTML 均已实际保存，链接存在；HTML 若未渲染，只说已保存，不称显示验证通过。
- 不访问用户未授权远端，不为强行全零删除系统备份/同步数据或安全擦除磁盘。

最终面向用户的解释示例：

> 本轮已完成……，采用……方式。原项目……（说明检查覆盖）；保留目录……用于……。仍有……，证据与下一步见报告。当前结论仅覆盖列明的本机范围。
