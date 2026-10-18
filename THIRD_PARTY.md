# 第三方来源与发布边界

本项目的 Mac 操作经验、保护流程、本地适配器和统一报告由本项目维护。公开仓库中的这些文件使用根目录 MIT 许可证。

Claude Code 的可选深度审计、会话关联、备份与恢复模块调用 [luwill/cc-clean](https://github.com/luwill/cc-clean) 的固定版本：v0.2.2，commit `0be9fdafa4fdd7894997db8335eaa47720c36627`。来源文件名、原链接及 SHA-256 在 [SOURCE.json](vendor/cc-clean/SOURCE.json) 中记录。

该提交未声明 LICENSE。本项目不把上游源文件、HTML 模板或测试代码纳入 Git、发布压缩包或本项目的 MIT 授权。此处的引用和来源记录不构成代上游授予许可。

基础 Mac 工作流程、项目保护快照、重复性比对和 Chrome 只读核查无需下载该依赖。需要增强模块时，可检查上游条款后，显式运行 `python3 -B scripts/fetch_cc_clean.py --accept-unlicensed-source`，由自己的电脑直接获取并校验固定文件。此命令只下载本地依赖，不获得、声明或改变任何上游权利；不上传任何本机资料。

不要把下载后的 `vendor/cc-clean/` 整体上传到本项目，或通过截图、附件、测试产物和 Release 附件变相再发布。仓库忽略规则与发布清单同时排除这些文件。若将来上游补充适用许可，应重新核实对应提交，再决定是否改变分发方式。

关于未指定许可证的公开仓库，参见 [GitHub 官方说明](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/licensing-a-repository)。
