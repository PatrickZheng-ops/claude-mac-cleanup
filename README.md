# Claude Mac Cleanup

从实际 Mac 清理经验整理的 Agent Skill：先确认范围，保护工作成果，再清理 Claude 的本机登录和运行痕迹，最后逐项验收。

**公共版 v2.1.0 · macOS · 中文优先 · 默认只读。** 支持 Codex 和 Claude Code。安装技能不会启动卸载，不会收集或上传本机路径、账号、Cookie、报告或备份。

## 能做什么

| 场景 | 行为 |
|---|---|
| 只读检查 | 盘点 App/CLI、专属服务、浏览器 Profile 和可能的内部产出，说明覆盖范围 |
| 换账号维护 | 按当前选择处理本地账号状态；保留 App、工作成果与共享环境 |
| 完整卸载 | 先保全内部工作成果，形成 B1–B4 具体清单，再按授权执行并核验 |
| 保留副本评估 | 对比指定原项目，区分字节相同、版本不同和未判定材料 |
| 最终报告 | 同源 Markdown/离线 HTML，明确列出已删除、残留、保留和未核验项 |

这是由 Agent 执行的流程和核查工具，不是一个自动递归删除脚本。实际清理需要宿主具备相应的本机文件、浏览器或电脑操作工具。没有相应能力时应说明具体未完成项；不要用“命令成功”代替清理验收。

## 安装

需要 Python **3.10+**；HTML 自测还需要 Node.js。先检查版本，macOS 的系统 Python 可能较旧。Codex 可使用已有的工作区依赖运行时，无需改变全局 Python。

```sh
git clone https://github.com/PatrickZheng-ops/claude-mac-cleanup.git
cd claude-mac-cleanup
python3 -B scripts/install_skill.py --agent codex
```

在 Claude Code 使用时，把最后一行换为：

```sh
python3 -B scripts/install_skill.py --agent claude
```

安装位置分别是 `~/.codex/skills/claude-mac-cleanup/` 和 `~/.claude/skills/claude-mac-cleanup/`。已有同名目录时安装器会拒绝覆盖；先自行保留旧版本，或用 `--destination` 指向一个新的绝对路径。安装器只复制公开发布清单中的文件，不带本地配置、审计数据或下载后的可选依赖。

## 第一次使用：告诉它哪些目录必须保留

不需要公开你的路径。安装后直接对 Agent 说：

> 使用 `$claude-mac-cleanup`，先只读检查。我的工作目录是「这里填写实际路径」，这些内容必须保留。请帮我核实并保存本机路径声明，把报告放在独立的私密目录。

Claude Code 中可用 `/claude-mac-cleanup`。默认提示只做盘点；要换账号或卸载时，在本轮请求中明确说明。**保护路径没有声明前，可先做有限只读准备，不能进入删除。** 路径声明不会成为永久删除授权。

[首次配置说明](references/first-run.md) 提供命令行示例。它支持多个保护目录、多个 Chrome 用户数据目录、共享配置目录及独立审计位置。配置保存在仓库外，换机器重新声明。公开版没有预置作者的业务目录、旧中转域名、专属服务或历史删除名单。

## 基础功能与可选增强

基础 Mac 工作流程、保护快照、重复性比对、Chrome 只读核查，以及非 Code/恢复类证据汇总，可以直接使用。

Claude Code 深度字段/会话审计、受控备份、恢复计划和恢复观察使用固定版本 CC Clean。**本仓库和下载压缩包不包含该上游源码。** 如果需要这些增强功能，请阅读 [第三方来源说明](THIRD_PARTY.md)，然后从实际安装的技能目录运行：

```sh
python3 -B scripts/fetch_cc_clean.py --accept-unlicensed-source
```

这会向公开上游下载六个固定文件并逐个核对 SHA-256，不会执行下载的文件、不自动更新版本，也不上传本机资料。缺少明确标记时不联网；下载或哈希失败不能算安装完成。此标记只表示你选择在本机获取源码，不代表上游给予了新的许可。

上游审阅版本没有 LICENSE，因此我们的 MIT 许可仅覆盖本仓库自己的公开文件。上游代码、许可和取得方式见 [THIRD_PARTY.md](THIRD_PARTY.md)。

## 工作边界

- 项目源代码、Git、文档、用户技能和共享环境默认保护。目录名包含 Claude 不构成删除理由。
- 不整体重置 Chrome Profile，不直接写 SQLite/LevelDB，不更改 VPN/系统网络出口，不停止共享运行时。
- 完整卸载默认只保全工作成果。敏感恢复原件只能用于明确选择的账号维护，报告不会把它称为已脱敏。
- 残留 Cookie 不等于登录仍有效；锁库、权限失败和未知格式不等于零。下载记录与实际文件分开判断。
- 本机清理不等于远端聊天、其他设备、云端会话或磁盘物理痕迹消失。远端账号动作需要单独明确范围。
- 从目标 Claude Code 会话内使用时，先做检查和计划；退出目标会话后，从外部环境完成依赖静止状态的备份、清理及验收。

完整操作流程见 [SKILL.md](SKILL.md)，各工具参数见 `python3 -B scripts/工具名.py --help`。

## 自测与发布

```sh
# 基础能力：只用临时合成资料，不读真实 Claude/Chrome 数据，不联网。
python3 -B scripts/check_skill.py

# 先自行取得可选依赖，再要求完整验证；缺依赖时必须失败。
python3 -B scripts/check_skill.py --require-upstream

# 检查明确的公开文件清单；不会打包工作目录里其他文件。
python3 -B scripts/release_guard.py --tracked
```

基础测试会明确列出未执行的可选测试，不能把它们算作通过。报告中的凭据只检查允许的存在性/类型，不导出原值；审阅报告不会授予删除或恢复权限。

v2.1.0 发布准备验证：基础模式 **115 项通过、33 项可选测试明确跳过**；显式取得并校验依赖后，**148 项本地 + 67 项上游 = 215 项通过**。另有独立新用户模拟，实际走通安装、路径声明、认证候选检查、保护快照对照和报告生成；未读取真实用户数据或执行清理。GitHub Actions 的远端运行状态以该仓库实际记录为准。

发布前同时检查 [release-files.json](release-files.json)、Git 暂存内容及压缩包。真实配置、审计报告、原始历史、浏览器库、备份、安装回执、API key 和可选上游源码都不能进入公开仓库。模式扫描仅辅助人工复核，不能保证任意文件名或自由文本均无秘密。

## License / Acknowledgements

本仓库自己的文件：[MIT](LICENSE)。可选增强来源：[luwill/cc-clean](https://github.com/luwill/cc-clean)；其许可不由本项目代授。

English: A macOS Agent Skill for scoped Claude cleanup, protected work products, read-only browser audits and evidence-based verification. Private machine paths are declared locally. Optional upstream code is fetched separately and is not redistributed in this repository.
