# PassManager

[English](README.md) | 简体中文

面向 AI Agent 的抗量子密码管理器。

- 你在 **TUI**（键盘 + 鼠标）里保存"密钥 + 域名"。
- 任意 AI Agent（Claude Code、Codex、Cursor、Gemini CLI……）通过 **MCP** 或 **CLI** 让 PassManager **代为使用**密钥：发 HTTPS 请求、SSH 执行命令、SCP 传文件。
- Agent **全程看不到明文**，返回结果自动脱敏；密钥只会被发往它绑定的域名。
- 库文件采用 **ML-KEM-1024（aws-lc-rs）+ Classic McEliece（liboqs）** 双层抗量子加密；设备密钥尽量由 **TPM / 系统** 封存；随机数来自两个独立来源并带健康检测。

完整设计见 [docs/DESIGN.zh-CN.md](docs/DESIGN.zh-CN.md)，版本变更见 [CHANGELOG.zh-CN.md](CHANGELOG.zh-CN.md)。

## 安装

从 [Releases](../../releases) 下载对应平台的包（Linux / macOS / Windows，x64 与 arm64），解开后：

```sh
sudo ./PassManager install        # Linux / macOS（需要一次管理员权限）
PassManager.exe install           # Windows：双击或在终端运行（会弹出一次 UAC）
```

安装程序依次完成：复制程序到只有管理员可写的路径 → 创建专用服务账户 → 生成并封存设备密钥 → 启动服务 → 检查并加固账户配置 → 设置口令 → 打开管理界面。

- 安全等级：**L3** 硬件封存（TPM）/ **L2** 系统封存 / **L1** 仅文件权限（会持续显示警告）。
- **没有任何恢复机制**：换机器、重装系统、清空 TPM 后库将无法打开，密钥需要重新录入。
- 没有管理员权限时可用 `PassManager install --user`（L1，没有账户隔离）。
- 推荐的账户配置（安装程序会检查，能安全修改的项自动修改）：禁用内置管理员；日常账户提权必须输入口令；不要以管理员身份运行 AI Agent；不要在 Agent 的终端里执行 sudo。安全检查全部通过之前，库保持锁定。
- macOS 包没有 Apple 开发者签名；从浏览器下载后先运行 `xattr -d com.apple.quarantine PassManager`。
- 校验下载：`sha256sum -c SHA256SUMS`，或 `gh attestation verify <文件> --repo ViaCoder/PassManager` 验证构建来源。

## 日常使用

```sh
PassManager                         # 管理界面：条目 / 主机 / Agent 接入 / 诊断 / 设置
PassManager unlock                  # 开机后解锁一次
PassManager trust db1.example.com   # 主机重装或证书更换后信任新指纹（*.example.com 可批量）
```

每个条目只需要**密钥**（API 密钥、口令或 SSH 私钥）和**域名**（如 `api.github.com`、`*.example.com`、`10.0.0.5`）。

在"Agent 接入"页选中你的 Agent，按回车即可接入（为它生成专用令牌并写入 MCP 配置）。其他 Agent 可复制：

```json
{ "mcpServers": { "passmanager": { "command": "/usr/local/bin/PassManager", "args": ["mcp"], "env": { "PASSMANAGER_TOKEN": "pm_…" } } } }
```

## Agent 怎么用

| MCP 工具 | CLI | 说明 |
|---|---|---|
| `list` | `PassManager list` | 已保存密钥的主机 |
| `http` | `PassManager http https://api.github.com/user -H 'Authorization: Bearer {{secret}}'` | 在需要密钥的位置写 `{{secret}}`，按 URL 主机自动选择密钥；只支持 HTTPS |
| `ssh` | `PassManager ssh deploy@db1.example.com 'sudo systemctl restart nginx'` | 用保存的密码或私钥登录；命令以 `sudo` 开头时自动提供 sudo 密码 |
| `scp` | `PassManager scp ./app.conf deploy@db1.example.com:/etc/app.conf` | 远程一侧写成 `user@host:/path`；下载的内容会脱敏 |

- CLI 兼容常用写法：`http` 支持 curl 的 `-X`、`-H`、`-d`/`--data-raw`、`-d @文件`、`--json`；`ssh` 支持 `-p`、`-l`、`ssh://user@host:port`；`scp` 支持 `-P`。
- 同一主机保存了多个密钥时，用列表里的引用名指定：HTTP 中写 `{{引用名}}`，SSH/SCP 写 `引用名/user@host`。
- CLI 从环境变量 `PASSMANAGER_TOKEN` 读取令牌，输出 JSON。需要用户操作的错误会直接给出命令，例如 `LOCKED: Ask the user to run: PassManager unlock`。

## 卸载

```sh
sudo PassManager uninstall [--restore-hardening]   # 永久删除服务、服务账户与全部数据
```

## 开发

需要 Rust ≥ 1.88、CMake、C 编译器、libclang（liboqs 的 bindgen 需要）。

```sh
cargo build --release
cargo test --workspace --features pm-crypto/test-hooks
python3 -I tests/tui_pty_smoke.py target/debug/PassManager "$(mktemp -d)"   # TUI 伪终端测试（Linux/macOS）
python3 -I tests/release_smoke.py target/release/PassManager                # 发布包功能测试
```

- 只装了 `libclang` 没有 `clang` 时，设置 `BINDGEN_EXTRA_CLANG_ARGS="-I/usr/lib/gcc/x86_64-linux-gnu/<版本>/include"`。
- 调试构建中 `PASSMANAGER_INSECURE_TEST_KDF=1` 使用极小的 Argon2 参数（仅测试用，发布构建忽略）；`PASSMANAGER_HOME=<目录>` 把全部文件放到该目录下。
- 本地交叉构建（Linux 上构建 Linux x64/arm64 与 Windows x64，需要 zig ≥ 0.14 与 `cargo install cargo-zigbuild`）：`scripts/cross-build.sh`。macOS 版本需要在 Mac 上构建。

## 测试与发布

- **CI**（每次推送，`.github/workflows/ci.yml`）：在 Linux / macOS / Windows 的 x64 与 arm64 原生运行器上运行格式与静态检查、全部测试（含端到端测试：真实服务 + HTTPS + SSH/SFTP + MCP + CLI）、TUI 伪终端测试，并以系统模式实际安装、探测、卸载；另在加固后的 Linux 运行器上跑完整的 Agent 流程；`cargo deny` 供应链检查。
- **发布**：
  1. 修改 `Cargo.toml` 中的 `version`，在 `CHANGELOG.md`（英文，用作发布说明）与 `CHANGELOG.zh-CN.md` 中添加对应的 `## [x.y.z]` 一节；
  2. 提交；
  3. `git tag vx.y.z && git push origin vx.y.z`。

  `.github/workflows/release.yml` 会校验标签与版本一致，在每个平台的原生运行器上构建并**直接运行发布包做功能测试**（macOS 通用二进制分别以 arm64 原生和 Rosetta x86_64 运行），全部通过后发布 Release：附 `SHA256SUMS`、构建来源证明，发布说明取自 CHANGELOG；带 `-` 的标签（如 `v0.2.0-rc.1`）自动标为预发布。

## 许可证

[PolyForm Strict License 1.0.0](LICENSE) + [PassManager Contribution Terms](LICENSE-CONTRIBUTING.md)，许可方 ViaCoder。

- 可以为非商业目的（个人、教育、公益与政府机构等）使用官方发布的版本；不允许商业使用。
- 不允许分发本软件，也不允许制作或发布修改版。
- 欢迎贡献：可以 fork 本仓库并修改代码，但只能用于准备向本仓库提交的贡献，见 [CONTRIBUTING.md](CONTRIBUTING.md)。提交 PR 即表示同意贡献条款。

以上为摘要，以英文条款原文为准。
