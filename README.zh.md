# AICAAH 0.1 Beta

**AI Coding Agent Architecture Harness**。用于检查源代码、设计文档与项目结构的一致性，采用 MIT 许可证。

支持 Python、C#、JavaScript、TypeScript、Java 和 Go 的结构提取。用户可设置目录、模块、类、接口、函数及变量的数量上限。引擎只解析源文本，不安装或运行目标语言的 SDK 或开发环境。

需要 Python 3.10 或更高版本。此版本尚待发布到 PyPI；发布前请在源码包目录执行 `python -m pip install .`，或安装提供的 wheel 文件。然后进入要检查的项目目录：

```sh
aicaah
```

安装向导保存 `aicaah.json`，重复执行会保留已有配置。安装保留现有工作模式；在代码地图中可以选择以代码或已批准的设计文档为依据。未编写文档的代码仍会产生检查结果。

左侧共享代码图，右侧分别显示问题和待实现内容。使用 `aicaah stop` 停止本项目服务器，使用 `aicaah selftest --portable` 验证安装。找不到命令时可使用 `python -m aicaah`。

界面可选择英、韩、中、日文；部分高级诊断和文档协议标题仍为韩文。完整语义引用分析尚未覆盖全部语言。安装不会自动启用代理钩子或信任设置。

[安装](docs/INSTALL.md) · [配置](docs/CONFIGURATION.md) · [性能](docs/PERFORMANCE.md) · [English](README.md)

## 编号安装向导

运行 `aicaah` 后，按编号选择：显示语言 → 项目文件夹 → 源代码语言 → 检查文件夹 → 模块边界 → 结构数量限制 → 确认并安装。文件夹可以通过编号浏览；限制只需选择单位、计数项、范围、统计深度并输入最大数量，无需语言参数或配置表达式。菜单中 0 返回、-1 取消；最大数量 0 是有效限制。最后确认前不写入文件，现有配置会保留。安装后在所选项目文件夹运行 `aicaah ask status`，打开显示的地址并在界面选择工作模式。
