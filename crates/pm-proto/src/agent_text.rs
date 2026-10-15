//! 给 AI Agent 的文字（唯一来源）：`passmanager show` 打印的接入说明——服务器上的 root 加 `--label` 时含一次性注册码，
//! 否则是不含注册码的公开版本——以及写入 Agent 全局指令文件的使用规则（`show --rules`）。
//!
//! - 接入说明只包含一个一次性注册码（10 分钟、只能用一次）与服务端公钥指纹，没有其他秘密；公开版本两者都没有；
//! - 源码构建路径固定到服务器自身的构建信息（发布标签 + 提交）；开发构建没有对应的公开标签时给出明确说明，不给错误的固定值；
//! - 使用规则写在 `<!-- passmanager:begin -->` 与 `<!-- passmanager:end -->` 之间，原地更新、不重复。

/// 使用规则的版本（规则内容变化时加 1）。
pub const INSTRUCTIONS_VERSION: u32 = 4;
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

/// 使用规则（写入 Agent 全局指令文件，也是接入说明的最后一部分）。
///
/// 只写流程与边界；每个工具的用法在 MCP 工具描述里，具体写法由 `lookup` 的结果给出，错误的处理由 `Next:` 给出（逐步披露）。
pub fn rules(lang: Lang) -> &'static str {
    match lang {
        Lang::En => {
            "\
- Use the PassManager MCP tools (or the `passmanager` CLI). You never see secrets: you write placeholders and
  PassManager fills them in on the server and redacts the results.
- Workflow: 1. `lookup` the URL or user@host you need (CLI: `passmanager lookup <target>`). 2. Copy the `how` it
  returns into `http`, `ssh` or `scp`, replacing only the `<...>` parts.
- Never ask the user for a password, token or key; never print, log or store one; never try to reveal one.
- git over HTTPS: plain `git` with `https://` URLs (if git asks for credentials, run `passmanager git-proxy --install`).
  Plain `ssh`/`scp`/git over SSH: run `passmanager ssh-agent` and use the printed `SSH_AUTH_SOCK`.
- An error ends with a `Next:` line: do exactly that. Do not retry the same call and do not work around the error.
- Adding or changing a credential is done by an agent with root SSH on the PassManager server, not by the user:
    <command that prints the secret> | ssh root@<server> passmanager import --name <name> --domain <host> --ops <http|ssh|git> --note '<purpose>'
    ssh root@<server> passmanager update --name <name> --domain <host>      (also --add-op, --remove-domain, --note)
  The secret only travels through the pipe: never echo, cat or save it. A note is one short purpose: no paths, URLs,
  accounts or secrets. Without root SSH on the server, tell the user what is missing.
"
        }
        Lang::Zh => {
            "\
- 使用 PassManager 的 MCP 工具（或 `passmanager` 命令行）。你看不到秘密：只写占位符，PassManager 在服务器上代入并对结果脱敏。
- 流程：1. 用 `lookup` 查询要访问的 URL 或 user@host（命令行：`passmanager lookup <目标>`）。2. 把返回的 `how` 照抄到
  `http`、`ssh` 或 `scp`，只替换其中 `<...>` 的部分。
- 永远不要向用户索要口令、令牌或私钥；不要打印、记录或保存；不要设法还原秘密。
- 基于 HTTPS 的 git：直接用普通的 `git` 与 `https://` 地址（git 要求输入凭据时运行 `passmanager git-proxy --install`）。
  普通的 `ssh`/`scp`/基于 SSH 的 git：运行 `passmanager ssh-agent`，使用它打印的 `SSH_AUTH_SOCK`。
- 错误的最后一行是 `Next:`：照它做。不要重复同样的调用，也不要绕过错误。
- 新增或修改凭据由拥有 PassManager 服务器 root SSH 的 Agent 完成，用户不手动操作：
    <输出秘密的命令> | ssh root@<服务器> passmanager import --name <名称> --domain <主机> --ops <http|ssh|git> --note '<用途>'
    ssh root@<服务器> passmanager update --name <名称> --domain <主机>      （还有 --add-op、--remove-domain、--note）
  秘密只经过管道：不要 echo、cat 或保存。备注只写一句用途：不含路径、URL、账号或秘密。没有服务器的 root SSH 时，告诉用户缺少什么。
"
        }
    }
}

/// 错误码对应的下一步（附在 MCP 与 CLI 的错误后面，写给 Agent）。`server` 是本机注册的服务器主机名（未注册时为 None）。
pub fn next_step(code: &str, server: Option<&str>) -> Option<String> {
    let srv = server.unwrap_or("<PassManager server>");
    let no_root = "Without root SSH on that server, tell the user exactly what is missing.";
    let s = match code {
        "NO_CREDENTIAL" => format!(
            "no credential is stored for this target. If you have root SSH on the PassManager server, import it without displaying it: \
             <command that prints the secret> | ssh root@{srv} passmanager import --name <name> --domain <host> --ops <http|ssh|git> \
             --note '<purpose>'. {no_root} Do not guess other credential names."
        ),
        "DOMAIN_MISMATCH" => format!(
            "this credential is not bound to that host. If it should be, bind it: ssh root@{srv} passmanager update --name <name> \
             --domain <host>. {no_root} Do not retry with other names."
        ),
        "OP_NOT_ALLOWED" => format!(
            "this credential is not allowed for that use. If it should be, allow it: ssh root@{srv} passmanager update --name <name> \
             --add-op <http|ssh|git>. {no_root} Do not retry."
        ),
        "AMBIGUOUS" => "ask the user which of the named credentials to use, then pick it by name: write {{name}} instead of \
                        {{secret}} in an http request, or name/user@host for ssh or scp (lookup accepts name/https://... too)."
            .into(),
        "UNKNOWN_CREDENTIAL" | "UNKNOWN_FIELD" | "USE_LOOKUP" => {
            "call lookup with the URL or user@host you want to use, then use exactly the names and placeholders it returns.".into()
        }
        "BAD_REQUEST" | "BAD_URL" => "fix the arguments; follow the example in the tool description or lookup's how.".into(),
        "USE_HTTPS" => "use an https:// URL.".into(),
        "LOCKED" | "NOT_READY" => "tell the user PassManager is not available (the message says why). Do not retry.".into(),
        "HOST_KEY_CHANGED" => {
            "tell the user the server's key or certificate changed; they must verify and trust it. Do not retry or work around it.".into()
        }
        "AUTH_REJECTED" | "AUTH_FAILED" | "BAD_CREDENTIAL" => {
            "the target rejected the stored credential. Do not retry and do not try other names; tell the user which target \
             rejected it."
                .into()
        }
        "UPSTREAM_ERROR" | "DISCONNECTED" => {
            "the target or the network failed (see the message). Retry once at most, then tell the user.".into()
        }
        "RATE_LIMITED" => "wait a minute before the next call.".into(),
        "TOO_LARGE" => "the file is over 64 MiB; split or compress it first.".into(),
        "NO_TOKEN" => "this machine is not enrolled with PassManager; tell the user.".into(),
        "FORBIDDEN" => "this is not allowed for agents. Do not retry.".into(),
        _ => return None,
    };
    Some(s)
}

/// 写入 Agent 全局指令文件的块（含标记）。`passmanager show --rules` 打印的也是它。
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

/// 源码构建的步骤。`pin` 为 None 时用占位符（公开说明：固定值在服务器打印的说明里）。
fn source_steps(lang: Lang, pin: Option<(&str, &str)>, enroll_url: &str) -> String {
    let (tag, commit) = pin.unwrap_or(match lang {
        Lang::En => ("<tag>", "<commit>"),
        Lang::Zh => ("<标签>", "<提交>"),
    });
    match lang {
        Lang::En => format!(
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
        Lang::Zh => format!(
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
    }
}

/// 注册后 git 的说明（接入说明与公开说明共用）。
fn git_note(lang: Lang) -> &'static str {
    match lang {
        Lang::En => {
            "   Enrollment also sets up git over HTTPS: it installs `passmanager git-proxy` as a per-user service that starts
   at boot or login (systemd user unit on Linux, LaunchAgent on macOS; on Windows it prints the manual steps) and
   adds a `url.<proxy>.insteadOf` line to the global git configuration for every host that has an entry with the
   `git` op (GitHub, a self-hosted git server, ...). The server adds the token; it never reaches this machine.
"
        }
        Lang::Zh => {
            "   注册同时配置基于 HTTPS 的 git：把 `passmanager git-proxy` 装成开机或登录时自动启动的用户服务（Linux 上是
   systemd 用户单元，macOS 上是 LaunchAgent；Windows 上打印手动步骤），并为服务器上每个有 `git` 用途条目的主机
   （GitHub、自建的 git 服务器等）在全局 git 配置里写入一行 `url.<代理>.insteadOf`。令牌由服务器带上，不会到达本机。
"
        }
    }
}

/// `passmanager show --label <名称>`（服务器上的 root）打印的接入说明（含一次性注册码）。`origin` 例如
/// `https://pm.example.com`；`enroll_url` 是完整的 `pm-enroll://主机:端口/注册码#指纹`。
pub fn setup_text(lang: Lang, origin: &str, code: &str, enroll_url: &str, build: &BuildInfo, minutes: u64) -> String {
    let one_liner = one_liner(origin, code);
    let source = match (build.pinned(), lang) {
        (Some(pin), _) => source_steps(lang, Some(pin), enroll_url),
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
{git}   If the download fails the command prints curl's error and exits with curl's exit code. Exit code 35
   (`curl: (35)`, TLS handshake failure) means this machine's curl cannot do X25519MLKEM768: go to step 2.
   Any other error (for example 22: the code expired or was already used; 6 or 7: server unreachable): stop and tell the user.

2. Only if step 1 exits with code 35 (TLS handshake failure; curl without ML-KEM support, e.g. macOS or older
   distributions) or on Windows: build the client from the pinned source and enroll with it (this configures MCP, the
   rules and git as well).
{source}
3. Restart the agent so that it loads the PassManager MCP server, then follow these rules:
{rules}",
            git = git_note(lang),
            rules = rules(Lang::En)
        ),
        Lang::Zh => format!(
            "PassManager 接入说明——给需要使用 PassManager 的那台机器上的 AI Agent。
下面的注册码 {minutes} 分钟内有效，只能使用一次。不要保存或转发这段文字。

1. 安装、注册并配置（需要支持 TLS 1.3 与 X25519MLKEM768 的 curl；在 sh、bash、zsh 中都可以直接运行）：
     {one_liner}
   它把 PassManager 客户端装到 ~/.local/bin（校验 SHA-256），向服务器注册，为检测到的 Agent 配置 MCP 服务，
   并把下面的规则写入它们的全局指令文件。
{git}   下载失败时命令会打印 curl 的错误，并以 curl 的退出码退出。退出码 35（`curl: (35)`，TLS 握手失败）表示本机的 curl
   不支持 X25519MLKEM768：转到第 2 步。其他错误（例如 22：注册码已过期或已用过；6 或 7：连不上服务器）：停止并告诉用户。

2. 只有第 1 步以退出码 35 失败（TLS 握手失败；curl 不支持 ML-KEM，例如 macOS 或较旧的发行版）或在 Windows 上时：
   从固定的源码构建客户端并用它注册（同样会配置 MCP、规则与 git）。
{source}
3. 重启 Agent 使其加载 PassManager MCP 服务，然后遵守以下规则：
{rules}",
            git = git_note(lang),
            rules = rules(Lang::Zh)
        ),
    }
}

/// 不含注册码的公开说明：`passmanager show` 不带 `--label`、或不是服务器上的 root 时打印。
/// `connected` 是本机已注册的服务器（`主机:端口`），没有注册时为 None。
pub fn public_text(lang: Lang, connected: Option<&str>) -> String {
    let placeholder_url = "pm-enroll://…";
    let example = one_liner(
        match lang {
            Lang::En => "https://<server>",
            Lang::Zh => "https://<服务器>",
        },
        match lang {
            Lang::En => "<code>",
            Lang::Zh => "<注册码>",
        },
    );
    let source = source_steps(lang, None, &format!("<{placeholder_url}>"));
    match lang {
        Lang::En => {
            let status = match connected {
                Some(s) => format!("This machine is enrolled with the PassManager server {s} (check: passmanager status)."),
                None => "This machine is not enrolled with a PassManager server.".to_string(),
            };
            format!(
                "PassManager agent setup (public guide: contains no enrollment code and no secret).
{status}

1. The administrator runs on the server, as root:
     passmanager show --label <name>
   and hands the complete output to the AI agent on the machine that should use PassManager. It contains a one-time
   enrollment code (valid for 10 minutes, works once) and one command:
     {example}
   The command installs the PassManager client to ~/.local/bin (SHA-256 verified), enrolls it with the server,
   configures the MCP server for the detected agents and adds the rules below to their global instruction files.
{git}
2. Fallback, only if that command exits with code 35 (`curl: (35)`: this machine's curl cannot do post-quantum TLS,
   X25519MLKEM768) or on Windows: build the client from the release source pinned to the tag and commit printed in
   the server's guide, then enroll with the pm-enroll:// URL from the guide (`passmanager show --label <name> --url`
   on the server prints only that URL):
{source}
3. Restart the agent so that it loads the PassManager MCP server, then follow these rules:
{rules}",
                git = git_note(lang),
                rules = rules(lang)
            )
        }
        Lang::Zh => {
            let status = match connected {
                Some(s) => format!("本机已注册到 PassManager 服务器 {s}（检查：passmanager status）。"),
                None => "本机尚未注册到 PassManager 服务器。".to_string(),
            };
            format!(
                "PassManager 接入说明（公开版本：不含注册码，也不含任何秘密）。
{status}

1. 管理员在服务器上以 root 运行：
     passmanager show --label <名称>
   并把完整的输出交给需要使用 PassManager 的那台机器上的 AI Agent。其中有一个一次性注册码（10 分钟内有效，只能使用一次）
   与一行命令：
     {example}
   这行命令把 PassManager 客户端装到 ~/.local/bin（校验 SHA-256），向服务器注册，为检测到的 Agent 配置 MCP 服务，
   并把下面的规则写入它们的全局指令文件。
{git}
2. 备用方式，只在那行命令以退出码 35 失败（`curl: (35)`：本机的 curl 不支持后量子 TLS，X25519MLKEM768）或在 Windows 上时：
   按服务器说明里给出的发布标签与提交从源码构建客户端，再用说明里的 pm-enroll:// 注册码注册
   （在服务器上运行 `passmanager show --label <名称> --url` 只打印这个注册码）：
{source}
3. 重启 Agent 使其加载 PassManager MCP 服务，然后遵守以下规则：
{rules}",
                git = git_note(lang),
                rules = rules(lang)
            )
        }
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
            assert!(t.contains("`lookup`") && t.contains("Next:"));
            assert!(!t.contains("install-agent.sh") && !t.contains("irm ") && !t.contains("iex"), "没有其他安装方式");
            assert!(t.contains("git-proxy") && t.contains("insteadOf"), "说明注册同时配置 git");
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

    /// 公开说明（不带 --label、或不是服务器上的 root）：没有注册码、没有 /a/<注册码>、没有 pm-enroll:// 注册码，
    /// 但有完整的流程、备用方式（退出码 35 → 固定源码构建 → enroll）、git 与规则；已注册时说明连接的服务器。
    #[test]
    fn public_text_has_no_code() {
        for lang in [Lang::En, Lang::Zh] {
            for connected in [None, Some("pm.example.com:8121")] {
                let t = public_text(lang, connected);
                assert!(t.contains("passmanager show --label"), "{t}");
                assert!(t.contains("35") && t.contains("git rev-parse HEAD") && t.contains("enroll '<pm-enroll://…>'"), "{t}");
                assert!(t.contains("--url") && t.contains("git-proxy") && t.contains("insteadOf"));
                assert!(t.contains("--proto '=https'") && !t.contains("| sh"));
                // 没有任何形如注册码的内容：/a/ 后面只有占位符，pm-enroll:// 后面没有主机与注册码。
                for (i, _) in t.match_indices("/a/") {
                    let rest = &t[i + 3..];
                    assert!(rest.starts_with("<code>") || rest.starts_with("<注册码>"), "{t}");
                }
                for (i, _) in t.match_indices("pm-enroll://") {
                    assert!(t[i + 12..].starts_with(['…', ' ']), "{t}");
                }
                assert!(!t.split(|c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_').any(|w| w.len() == 43));
                assert_eq!(t.contains("pm.example.com:8121"), connected.is_some());
                assert!(t.contains("`lookup`") && t.contains("Next:"));
            }
        }
        assert!(public_text(Lang::En, None).contains("not enrolled"));
    }

    #[test]
    fn next_steps() {
        let n = next_step("NO_CREDENTIAL", Some("pm.example.com")).unwrap();
        assert!(n.contains("ssh root@pm.example.com passmanager import") && n.contains("Do not guess"), "{n}");
        assert!(next_step("DOMAIN_MISMATCH", None).unwrap().contains("<PassManager server> passmanager update"));
        assert!(next_step("OP_NOT_ALLOWED", None).unwrap().contains("--add-op"));
        for c in
            ["AMBIGUOUS", "UNKNOWN_CREDENTIAL", "USE_LOOKUP", "LOCKED", "NOT_READY", "HOST_KEY_CHANGED", "AUTH_REJECTED", "BAD_REQUEST"]
        {
            assert!(next_step(c, None).is_some(), "{c}");
        }
        assert!(next_step("INTERNAL", None).is_none());
    }

    #[test]
    fn instruction_block_has_markers() {
        let b = instruction_block(Lang::En);
        assert!(b.starts_with(BEGIN) && b.trim_end().ends_with(END));
        assert_eq!(b.matches(BEGIN).count(), 1);
        assert!(b.contains(&format!("v{INSTRUCTIONS_VERSION}")) && b.contains("`lookup`") && !b.contains("`list`"));
        for blk in [b.clone(), instruction_block(Lang::Zh)] {
            for must in ["git-proxy --install", "ssh-agent", "Next:", "passmanager import", "passmanager update", "`how`"] {
                assert!(blk.contains(must), "{must}: {blk}");
            }
        }
        // 规则块保持简短（详细用法在工具描述、lookup 结果与 Next: 里）。
        assert!(rules(Lang::En).lines().count() <= 16, "{}", rules(Lang::En));
        assert_eq!(Lang::parse("ZH").unwrap(), Lang::Zh);
        assert!(Lang::parse("fr").is_err());
    }
}
