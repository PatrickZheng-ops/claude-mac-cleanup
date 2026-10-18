# 首次声明本机路径

安装技能本身不需要填写账户、密码、API key、Cookie 或真实业务目录。首次使用、换机器，或工作目录发生变化时，再向 Agent 声明本机路径。技能不会把作者电脑上的目录当成你的目录，也不会从文件夹名称猜测哪些文件可以删除。

## 需要说明哪些目录

| 项目 | 用途 | 要求 |
| --- | --- | --- |
| `protected_roots` | 必须保留的项目、文档、代码、财务资料等 | 至少一个；确实没有时需明确声明 |
| `audit_base` | 保存本次盘点、批次清单和核验报告 | 已存在，与保护目录及下述源目录互不包含 |
| `chrome_user_data_dirs` | 需要检查的 Chrome 用户数据目录 | 可选；声明目录不等于批准删除整个 Profile |
| `shared_paths` | 多工具共用的配置、脚本或网关目录 | 可选；按保护对象处理，不自动修改 |

这些参数都接受**已存在的真实目录绝对路径**。共享配置是单个文件时，请声明其所在目录，Agent 再在本次清单中登记具体文件。文件、缺失目录、符号链接及带 `..` 的路径会被拒绝；不要为了通过检查而复制浏览器资料或放宽目录权限。某些 macOS 路径含系统别名，例如 `/tmp`；请声明其真实路径，并确认没有改指向其他目录。

## 最简单的用法

直接对 Agent 说：

> 使用 `$claude-mac-cleanup`。先只读盘点。我的保护目录是「实际目录 A」和「实际目录 B」，报告保存到「实际目录 C」。如需检查 Chrome，请先列明拟检查的用户数据目录。把声明配置保存到技能仓库以外的私密位置。

Agent 应核对这些目录存在，帮助生成本地配置，并在当前任务使用前检查一次。已有声明可以复用；它只记录路径边界，**不包含删除批准**。`check` 只证明路径声明此刻有效，也不证明清理已经完成。

## 命令行示例

以下命令从技能根目录执行。先把变量改成自己的实际位置；`WORK_ROOT` 必须已有，另外两个新目录专门存放配置和报告，不应位于保护目录、Chrome 数据或共享目录内。

```sh
WORK_ROOT="$HOME/Documents/MyProjects"
LOCAL_CONFIG_DIR="$HOME/.config/claude-mac-cleanup"
AUDIT_BASE="$HOME/claude-cleanup-audits"
mkdir -p "$LOCAL_CONFIG_DIR" "$AUDIT_BASE"
chmod 700 "$LOCAL_CONFIG_DIR" "$AUDIT_BASE"

python3 -B scripts/setup_local.py init \
  --protected-root "$WORK_ROOT" \
  --audit-base "$AUDIT_BASE" \
  --out "$LOCAL_CONFIG_DIR/local.json"

python3 -B scripts/setup_local.py check \
  --config "$LOCAL_CONFIG_DIR/local.json"
```

有多个保护目录时，重复 `--protected-root`。需要声明浏览器或共享目录时，分别追加 `--chrome-user-data-dir`、`--shared-path`，也可以重复。这些可选项没有自动发现或默认扫描行为。

确实没有保护目录时，将示例中的 `--protected-root "$WORK_ROOT"` 替换为 `--no-protected-roots`。两种选项不能同时使用。声明“没有保护目录”仍不表示可以删除所有文件；工作成果检查和本次范围判断继续适用。

`init` 只新建一个权限为 `0600` 的配置文件，不覆盖已有文件、不读取源目录里的内容、不执行清理。配置文件的父目录须已存在、归当前用户所有且不能由其他用户写入；配置输出也不能放入任何已声明源目录。终端只输出状态、目录数量和 `deletion_authorized: false`，不会打印这些私密路径。路径本身只写在本地配置中。

## 配置变更与发布边界

- 路径变化时，重新运行 `init` 写入一个新的文件名，例如 `local-next.json`，检查通过后让 Agent 使用该文件。旧文件不会被覆盖。
- 默认模式固定为 `audit`。本次要做账号维护还是完整卸载，由当前请求和清单决定；配置不能授予长期删除权限。
- 不要把本地配置、审计报告、恢复副本、浏览器数据或密钥提交到 GitHub。配置应保存在仓库外；分享日志前仍需检查文件名和路径信息。
- 最终清理前，Agent 还需核对本次目标、保护边界、运行中的写入程序和已有授权。配置检查不会替代这些实际操作检查。

失败时会返回非零退出码及不含真实路径的错误类别。`FileNotFoundError` 表示声明目录或配置缺失；`NotADirectoryError` 可能表示给出了文件或符号链接；`FileExistsError` 表示输出已存在，应改用新文件名。其他错误应先检查输入和目录权限，不能把失败当成“没有残留”。
