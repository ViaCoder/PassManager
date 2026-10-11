//! 给 AI Agent 的文字：`passmanager agent-setup` 打印的一段可直接粘贴的接入说明，以及写入 Agent 全局指令文件的使用规则。
//!
//! - 接入说明只包含一个一次性注册码（10 分钟、只能用一次）与服务端公钥指纹，没有其他秘密；
//! - 源码构建路径固定到服务器自身的构建信息（发布标签 + 提交）；开发构建没有对应的公开标签时给出明确说明，不给错误的固定值；
//! - 使用规则写在 `<!-- passmanager:begin -->` 与 `<!-- passmanager:end -->` 之间，原地更新、不重复。

/// 使用规则的版本（规则内容变化时加 1）。
pub const INSTRUCTIONS_VERSION: u32 = 1;
pub const BEGIN: &str = "<!-- passmanager:begin -->";
pub const END: &str = "<!-- passmanager:end -->";
/// 公开的源码仓库。
pub const REPO: &str = "https://github.com/ViaCoder/PassManager";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lang {
    En,
    Zh,
}

impl Lang {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "" | "en" => Ok(Lang::En),
            "zh" | "zh-cn" | "cn" => Ok(Lang::Zh),
            other => Err(format!("unknown language {other} (use en or zh)")),
        }
    }
}

/// 服务器的构建信息：只有从与版本号一致的发布标签构建时才有 `tag` 与 `commit`。
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BuildInfo {
    pub version: String,
    pub tag: Option<String>,
    pub commit: Option<String>,
}

impl BuildInfo {
    /// 标签与提交都合法（`v<version>`、40 位十六进制）时才算固定到公开源码。
    pub fn pinned(&self) -> Option<(&str, &str)> {
        let tag = self.tag.as_deref()?;
        let commit = self.commit.as_deref()?;
        let ok = tag == format!("v{}", self.version) && commit.len() == 40 && commit.bytes().all(|b| b.is_ascii_hexdigit());
        ok.then_some((tag, commit))
    }
}

/// 使用规则（写入 Agent 全局指令文件，也是接入说明的第 3 部分）。
pub fn rules(lang: Lang) -> &'static str {
    match lang {
        Lang::En => {
            "\
- Use the PassManager MCP tools (or the `passmanager` CLI). Call `list` first to see which hosts and entries exist.
- Never ask the user for a password, token or key, and never print, log or store plaintext secrets. Reference them only as
  placeholders in `http`, `ssh` and `scp` requests: `{{secret}}` (the entry for the target host), `{{entry}}`,
  `{{entry.field}}`, or `{{field}}`. PassManager fills them in on the server and redacts the results.
- For plain `ssh`/`scp`/`git` over SSH run `passmanager ssh-agent` and use the printed `SSH_AUTH_SOCK`; for git over HTTPS run
  `passmanager git-proxy` and apply the `git config` line it prints. Private keys and tokens never leave the server.
- Errors: `LOCKED`/`NOT_READY` → ask the user to unlock or fix the server; `DOMAIN_MISMATCH` or an unbound entry → ask the user
  to bind the entry to that host in the PassManager web UI; `NO_CREDENTIAL` → ask the user to add one; `HOST_KEY_CHANGED` →
  ask the user to verify and trust the new key. Do not try to work around these errors.
"
        }
        Lang::Zh => {
            "\
- 使用 PassManager 的 MCP 工具（或 `passmanager` 命令行）。先调用 `list` 查看有哪些主机与条目。
- 永远不要向用户索要口令、令牌或私钥，也不要打印、记录或保存明文。只在 `http`、`ssh`、`scp` 请求里用占位符引用：
  `{{secret}}`（目标主机对应的条目）、`{{条目}}`、`{{条目.字段}}` 或 `{{字段}}`。PassManager 在服务器上代入并对结果脱敏。
- 普通的 `ssh`/`scp`/基于 SSH 的 `git`：运行 `passmanager ssh-agent` 并使用它打印的 `SSH_AUTH_SOCK`；基于 HTTPS 的 git：
  运行 `passmanager git-proxy` 并执行它打印的 `git config`。私钥与令牌不会离开服务器。
- 错误：`LOCKED`/`NOT_READY` → 请用户解锁或处理服务器；`DOMAIN_MISMATCH` 或条目未绑定域名 → 请用户在 PassManager 网页里
  把条目绑定到该主机；`NO_CREDENTIAL` → 请用户添加；`HOST_KEY_CHANGED` → 请用户核实并信任新的密钥。不要设法绕过这些错误。
"
        }
    }
}

/// 写入 Agent 全局指令文件的块（含标记）。
pub fn instruction_block(lang: Lang) -> String {
    let title = match lang {
        Lang::En => format!("## PassManager (agent instructions v{INSTRUCTIONS_VERSION})"),
        Lang::Zh => format!("## PassManager（Agent 使用规则 v{INSTRUCTIONS_VERSION}）"),
    };
    format!("{BEGIN}\n{title}\n\n{}{END}\n", rules(lang))
}

/// 第 1 步的一行命令。
///
/// - `--proto '=https'` 加引号：zsh（macOS 默认）会把未加引号的 `=https` 当作命令路径展开（EQUALS 选项）而报错；
/// - 不用 `curl … | sh`：curl 失败时 sh 读到空输入、以 0 退出，错误被吞掉。这里 curl 失败时执行 `exit <curl 的退出码>`，
///   并且 `-S` 把 curl 的错误打印出来；退出码 35 表示 TLS 握手失败（客户端不支持 X25519MLKEM768）。
/// - 在 sh、bash、zsh 中行为相同（测试覆盖）。
pub fn one_liner(origin: &str, code: &str) -> String {
    format!("sh -c \"$(curl --proto '=https' --tlsv1.3 -fsSL {origin}/a/{code} || echo \"exit $?\")\"")
}

/// `passmanager agent-setup` 打印的接入说明。`origin` 例如 `https://pm.example.com`；`enroll_url` 是完整的
/// `pm-enroll://主机:端口/注册码#指纹`。
pub fn setup_text(lang: Lang, origin: &str, code: &str, enroll_url: &str, build: &BuildInfo, minutes: u64) -> String {
    let one_liner = one_liner(origin, code);
    let source = match (build.pinned(), lang) {
        (Some((tag, commit)), Lang::En) => format!(
            "   Prerequisites: git, a Rust toolchain (rustup, Rust >= 1.88), cmake, a C compiler and libclang (liboqs is built from source).
     git clone --branch {tag} --depth 1 {REPO} PassManager
     cd PassManager
     test \"$(git rev-parse HEAD)\" = {commit} || {{ echo 'commit mismatch - stop'; exit 1; }}
     cargo build --release --locked -p passmanager
     ./target/release/PassManager enroll '{enroll_url}'
   If the commit does not match, stop and tell the user. On Windows run the same steps in PowerShell
   (compare `git rev-parse HEAD` with {commit}; the binary is target\\release\\PassManager.exe).
"
        ),
        (Some((tag, commit)), Lang::Zh) => format!(
            "   前提：git、Rust 工具链（rustup，Rust >= 1.88）、cmake、C 编译器与 libclang（liboqs 从源码构建）。
     git clone --branch {tag} --depth 1 {REPO} PassManager
     cd PassManager
     test \"$(git rev-parse HEAD)\" = {commit} || {{ echo '提交不一致，停止'; exit 1; }}
     cargo build --release --locked -p passmanager
     ./target/release/PassManager enroll '{enroll_url}'
   提交不一致时停止，并告诉用户。Windows 上在 PowerShell 里执行同样的步骤
   （把 `git rev-parse HEAD` 与 {commit} 比较；程序是 target\\release\\PassManager.exe）。
"
        ),
        (None, Lang::En) => format!(
            "   This server runs a development build ({}) that does not correspond to a published release tag, so there is
   no pinned source to build. Do not build from an unpinned checkout; tell the user that step 1 failed and that the
   server needs a release build for the source fallback.
",
            build.version
        ),
        (None, Lang::Zh) => format!(
            "   本服务器运行的是开发构建（{}），没有对应的公开发布标签，因此没有可以固定的源码。不要从未固定的代码构建；
   请告诉用户第 1 步失败，并说明源码构建方式需要服务器使用发布版本。
",
            build.version
        ),
    };
    match lang {
        Lang::En => format!(
            "PassManager agent setup — instructions for the AI agent on the machine that should use PassManager.
The enrollment code below is valid for {minutes} minutes and works once. Do not store or share this text.

1. Install, enroll and configure (needs curl with TLS 1.3 and X25519MLKEM768; works in sh, bash and zsh):
     {one_liner}
   This installs the PassManager client to ~/.local/bin (SHA-256 verified), enrolls it with the server, configures the
   MCP server for the detected agents and adds the rules below to their global instruction files.
   If the download fails the command prints curl's error and exits with curl's exit code. Exit code 35
   (`curl: (35)`, TLS handshake failure) means this machine's curl cannot do X25519MLKEM768: go to step 2.
   Any other error (for example 22: the code expired or was already used; 6 or 7: server unreachable): stop and tell the user.

2. Only if step 1 exits with code 35 (TLS handshake failure; curl without ML-KEM support, e.g. macOS or older
   distributions) or on Windows: build the client from the pinned source and enroll with it (this configures MCP and the
   rules as well).
{source}
3. Restart the agent so that it loads the PassManager MCP server, then follow these rules:
{rules}",
            rules = rules(Lang::En)
        ),
        Lang::Zh => format!(
            "PassManager 接入说明——给需要使用 PassManager 的那台机器上的 AI Agent。
下面的注册码 {minutes} 分钟内有效，只能使用一次。不要保存或转发这段文字。

1. 安装、注册并配置（需要支持 TLS 1.3 与 X25519MLKEM768 的 curl；在 sh、bash、zsh 中都可以直接运行）：
     {one_liner}
   它把 PassManager 客户端装到 ~/.local/bin（校验 SHA-256），向服务器注册，为检测到的 Agent 配置 MCP 服务，
   并把下面的规则写入它们的全局指令文件。
   下载失败时命令会打印 curl 的错误，并以 curl 的退出码退出。退出码 35（`curl: (35)`，TLS 握手失败）表示本机的 curl
   不支持 X25519MLKEM768：转到第 2 步。其他错误（例如 22：注册码已过期或已用过；6 或 7：连不上服务器）：停止并告诉用户。

2. 只有第 1 步以退出码 35 失败（TLS 握手失败；curl 不支持 ML-KEM，例如 macOS 或较旧的发行版）或在 Windows 上时：
   从固定的源码构建客户端并用它注册（同样会配置 MCP 与规则）。
{source}
3. 重启 Agent 使其加载 PassManager MCP 服务，然后遵守以下规则：
{rules}",
            rules = rules(Lang::Zh)
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const URL: &str = "pm-enroll://pm.example.com:8443/CODE123#FPR";

    fn pinned() -> BuildInfo {
        BuildInfo { version: "0.3.0".into(), tag: Some("v0.3.0".into()), commit: Some("0123456789abcdef0123456789abcdef01234567".into()) }
    }

    #[test]
    fn pinned_build_info() {
        assert!(pinned().pinned().is_some());
        let mut b = pinned();
        b.tag = Some("v0.2.9".into());
        assert!(b.pinned().is_none(), "标签必须与版本一致");
        let mut b = pinned();
        b.commit = Some("abc".into());
        assert!(b.pinned().is_none());
        assert!(BuildInfo { version: "0.3.0".into(), ..Default::default() }.pinned().is_none());
    }

    #[test]
    fn setup_text_contents() {
        for lang in [Lang::En, Lang::Zh] {
            let t = setup_text(lang, "https://pm.example.com", "CODE123", URL, &pinned(), 10);
            assert_eq!(t.matches("CODE123").count(), 2, "一行命令与 enroll 各一次");
            assert!(t.contains("sh -c \"$(curl --proto '=https' --tlsv1.3 -fsSL https://pm.example.com/a/CODE123 || echo \"exit $?\")\""));
            assert!(t.contains("--proto '=https'") && !t.contains("--proto =https"), "zsh 下必须加引号");
            assert!(!t.contains("| sh"), "不能用会吞掉错误的 curl | sh");
            assert!(t.contains("35"), "说明握手失败的退出码");
            assert!(t.contains("--branch v0.3.0") && t.contains("0123456789abcdef0123456789abcdef01234567"));
            assert!(t.contains(&format!("enroll '{URL}'")));
            assert!(t.contains("{{entry.field}}") || t.contains("{{条目.字段}}"));
            assert!(!t.contains("install-agent.sh") && !t.contains("irm ") && !t.contains("iex"), "没有其他安装方式");
            let dev = setup_text(
                lang,
                "https://pm.example.com",
                "CODE123",
                URL,
                &BuildInfo { version: "0.3.0".into(), ..Default::default() },
                10,
            );
            assert!(!dev.contains("git clone") && !dev.contains("rev-parse"), "开发构建不给固定值");
            assert!(dev.contains("0.3.0"));
            assert_eq!(dev.matches("CODE123").count(), 1);
        }
    }

    #[test]
    fn instruction_block_has_markers() {
        let b = instruction_block(Lang::En);
        assert!(b.starts_with(BEGIN) && b.trim_end().ends_with(END));
        assert_eq!(b.matches(BEGIN).count(), 1);
        assert!(b.contains("v1") && b.contains("`list`"));
        assert_eq!(Lang::parse("ZH").unwrap(), Lang::Zh);
        assert!(Lang::parse("fr").is_err());
    }
}
