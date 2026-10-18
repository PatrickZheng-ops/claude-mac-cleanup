# Claude Code 账号检查、受控备份与恢复核验

本模块通过策略包装器约束账号检查、备份与恢复核验。相关引擎可选使用 [CC Clean v0.2.2 固定提交](https://github.com/luwill/cc-clean/tree/0be9fdafa4fdd7894997db8335eaa47720c36627)，来源及预期哈希见 `../vendor/cc-clean/SOURCE.json`。公开包不包含其源码与测试；需要相关功能时，使用者须主动运行 `python3 -B scripts/fetch_cc_clean.py --accept-unlicensed-source` 取得固定文件。来源完整性检查失败就停止调用，不自动替换或跟随 main 更新。

审阅提交未声明 LICENSE。主动获取标记仅表示使用者选择取得该来源，不构成本项目授予上游使用或再分发许可。不要将下载源码加入公开仓库，也不能直接执行上游完整目录备份示例来绕过本技能策略。本模块不控制 Mac App、浏览器、网络或真实 Keychain，不替代那些模块。

## 1. 确定配置和认证候选

从已知入口和用户范围核准实际 `CLAUDE_CONFIG_DIR`、主状态 `.claude.json` 与 settings。默认配置目录和目录外主状态是两个对象；内部主状态已包含在目录根时不再重复传为根。用户排除的独立环境不查不改。

`auth` 默认只读取明确所选 JSON 的结构摘要，说明允许变量是否配置、是否为空、类型，以及去掉身份/路径/参数后的 endpoint。只有显式传入 `--include-process-env` 才检查辅助进程继承的六个允许变量；这仍不等于目标 Claude 进程环境。它不调用 `apiKeyHelper`、不刷新 token、不发模型请求。因此结论是**认证候选存在，实际生效来源仍需核准**。不要把一份旧 settings 的 Key 存在性写成“当前在用该 Key”。

必要时由 Agent 在现有授权范围内补充当前入口/进程的允许字段，只输出存在性和脱敏地址；不得转储进程环境、shell 文件或 `.env`。区分客户端访问本地网关的占位认证、供应商密钥、Claude OAuth 与网关自身配置，不自动停用共享路由。

### 只读命令

以下是参数示意，路径必须换成本轮核准的绝对路径。输出为新的私密文件，不能在源目录内；不要原样运行占位符。

```text
python3 -B scripts/code_tools.py audit --root default=/实际配置目录 --root state=/实际目录外/.claude.json --state-file /实际目录外/.claude.json --out /本轮审计目录/code.json
python3 -B scripts/code_tools.py auth --settings main=/实际配置目录/settings.json --out /本轮审计目录/auth.json
```

`audit` 默认只读文件元数据，不解析历史/凭据正文。显式 `--state-file` 允许解析该主状态 JSON：旧账号及缓存输出允许字段的存在性和数量；精确识别嵌套 `deviceId`、`device_id`、`deviceID`，输出类型与结构序号，不输出值、值哈希或可能携带身份的祖先键名。重复 JSON 键、未知结构及解析失败不得声称完成。发现 Device ID 仅说明字段存在；不证明有效、属于旧账号、已发给服务器或可安全删除。本工具不获取/重置硬件标识。

`auth` 可重复传入多个有明确本地标签的 settings，关注 `ANTHROPIC_API_KEY`、`ANTHROPIC_AUTH_TOKEN`、`CLAUDE_CODE_OAUTH_TOKEN`、`ANTHROPIC_BASE_URL`、配置目录和安全存储覆盖设置。完整 settings 中无关字段忽略且不回显；重复键或关注字段格式错误不能当作“没有认证”。它不自动搜索全机或读取秘密值来做在线验证。

## 2. 会话关系是理解依据，不是删除依据

同一显式根内，将 `projects`、`session-env`、`file-history`、`debug`、`todos` 中符合已知格式的 UUID 路径关联。不同根不合并；同标识出现于多个项目时仍属归属未核验。项目 `memory`、`CLAUDE.md` 属工作资产；历史、plans、tasks、skills 默认保留，完整卸载时先执行工作成果保全流程。

缺少 session-env、旧时间戳、原项目不在原路径，都不能单独证明文件没用。目录编码不擅自反解为真实项目。关联记录固定不授予删除权限；当前可用清单来自总流程的对象台账。

## 3. 混合凭据须拆分判断

只读盘点通过平台凭据工具查询准确 service/type/account 的非秘密元数据，不查询 Keychain 数据库、不显示密码。Keychain 权限、锁定、命名空间错误不算没有凭据。

自定义配置目录可能有路径派生命名空间，也可能受 `CLAUDE_SECURESTORAGE_CONFIG_DIR` 覆盖而共享存储；这些是版本相关发现线索，必须现场核准。文件型 `.credentials.json` 回退和不同平台 profiles 也只在明确范围中检查，不假定所有账号都在默认 service。

一条凭据 bundle 可能同时包含 `claudeAiOauth`、`mcpOAuth` 或其他服务。先判断“整项删除”是否会使其他 MCP 退出；需要保留时，准备精确子项方案。读取具体 named item 的秘密 payload 必须在当前授权覆盖内，且只在受控本地内存解析，输出根字段/数量/存在性而非值。不能通过 `security ... -w <秘密>` 这类明文参数传递 payload，不把秘密写到报告或临时日志。

包装器不会自动读取或编辑 Keychain，也不会把发现文件凭据直接变成可删除项。不能安全处理混合项时保留该项并继续其他独立批次；不要为避开细分判断删除整个命名空间。

## 4. 备份政策先于复制

只读复查不额外复制。需要备份时创建本轮政策文件，记录真实任务和批准引用；helper 仅验证格式与安全前提，不能验证人类批准。已有同范围批准直接引用，不重复询问。

| 策略 | 可用模式 | 内容与边界 |
|---|---|---|
| `work-products` | maintenance / uninstall | 逐文件已审阅的工作成果或非秘密配置；已知认证、环境秘密、原始历史不允许伪装为普通成果 |
| `sensitive-recovery` | 仅 maintenance | 当前明确接受的敏感恢复原件；要求接受标记、批准引用和保存说明；仍然是秘密副本，目录权限不是加密 |

政策 JSON 的主要结构如下。`reviewed_files` 必须覆盖每个根下全部普通文件，不能以一行目录名代替分类；源新增文件或漏项应停止该次备份。路径是标准相对文件路径，文件根使用 `.`。具体字段以 `code_tools.py --help` 和合成测试为准。

```json
{
  "schema": 1,
  "mode": "uninstall",
  "backup_policy": "work-products",
  "roots": {"output": "/本轮已审阅的成果目录"},
  "reviewed_files": [
    {"root": "output", "path": "report.docx", "classification": "work_product"}
  ],
  "writer_state": "confirmed_stopped",
  "authorization_ref": "本轮用户要求保护工作成果的消息引用",
  "retention_note": "供用户复核内部旧稿；后续处置另列"
}
```

敏感恢复政策另需 `accept_sensitive_originals: true`，模式为 maintenance，敏感文件分类为 `sensitive_state`。这不是只要写 true 就得到授权，Agent 仍须核对真实消息范围。已知文件名检查只是一道防线；脚本不能发现任意文档或脚本中嵌入的秘密，逐文件业务分类仍需要 Agent 判断。疑似秘密不得靠改文件扩展名绕过。

每条 `reviewed_files` 建议填写 `sha256`，把审阅时的内容和执行时的源绑定。不填时仅验证清单覆盖和复制期间源稳定，不能证明政策创建后内容没有变化。回执记录哈希覆盖数；成果策略的 `contains_sensitive_originals` 为 `possible_unverified`，敏感策略为 `true`，不能把分类宣称为自动内容脱密检查。

```text
python3 -B scripts/code_tools.py backup --policy /本轮审计目录/backup-policy.json --out /已选私密目录/new-backup
python3 -B scripts/code_tools.py verify --backup-dir /已选私密目录/new-backup --check-source
```

备份只复制到新位置，检查文件 SHA-256、基础权限/属主、链接目标和复制期间源的一致性，并生成恢复样本与政策回执。Mac 原生复制请求保留 ACL/xattr，但自动校验不证明全部扩展属性一致。文件备份不包含 Keychain；不把文件字节合计当释放空间。

本技能包装器不接受链接/特殊文件作为备份工作清单；共享链接记录保留，不能跟随复制目标。备份失败留下的部分副本也可能敏感，必须登记，不能冒称没有写过输出；不自动清除失败副本。

目标 Claude 会话或其他程序仍在写入时，不执行依赖静止源的备份/核验；不能靠给参数写“已停止”替代实际检查，也不强杀共享程序。源发生变化就重新审查和准备，批准范围没变不重问。

`policy-receipt.json` 将政策和上游 manifest 的摘要绑定；后续验证与恢复拒绝缺失回执、摘要变化和范围/模式/策略混用。摘要只检验本地一致性，不是数字签名；无法抵抗全部记录同时被有意重写。`authorization_verified_by_helper` 与 `writer_state_verified_by_helper` 均为 false，真实批准和静止性由总流程核实。

## 5. 恢复计划与观察回执

恢复是明确的用户动作，不能清理失败后擅自把旧账号恢复回去。先验证旧备份，再保存并验证当前状态；两份备份必须经过本包装器政策检查并对应同样根。所选普通文件用 `label:relative-file`，文件根用 `label:.`。工具可记录缺失根，但每次备份至少一个所选根必须存在；缺失根无需伪造文件或审阅清单。全部根已缺失时须另做恢复前状态方案，不能为让工具通过而添加无关根、制造空文件或绕过政策回执。

```text
python3 -B scripts/code_tools.py prepare-restore --backup-dir /旧备份 --pre-restore-backup /恢复前备份 --select output:report.docx --out /本轮审计目录/restore-plan.json
python3 -B scripts/code_tools.py record-restore --plan /本轮审计目录/restore-plan.json --out /本轮审计目录/restore-receipt.json
```

`prepare-restore` 只写精确计划；真正恢复由 Agent 核准当前指纹、用户范围后执行。`record-restore` 只观察所选文件是否与旧备份一致，及所有未选项是否与恢复前备份一致。选中项成功但未选项变化不能判整轮成功；备份篡改、无法完整读取或仍在写入均须明确失败/未核验。

不要用整份旧 `.claude.json` 覆盖新账号资料来恢复一个字段；字段级或 Keychain 恢复需要专项方案，不被普通文件回执覆盖。helper 的恢复观察不证明授权、执行者、模型可用或账号正常。

工具成功退出 0；保护条件失败、异常、部分或失败的恢复观察退出 2。失败输出不等于没有写过副本；检查已产生的私密输出并登记。

## 6. 汇入统一报告

账号 audit、auth 摘要、备份政策、恢复回执使用本轮时间和同一范围引用。只有本轮对象台账负责动作终态；上游默认保留与浏览器发现结果是证据，不是第二套批准系统。报告采用 `scripts/report_tools.py`，不能将上游审阅清单导出的 `operations: []` 当可执行计划。
