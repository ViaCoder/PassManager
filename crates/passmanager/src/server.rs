//! 服务器模式（局域网在线版）的 root 命令：`init`、`login`、`token`、`status`、`lock`/`unlock`、`reseal`、
//! 以及 systemd 的 `ExecStartPre=+… service-prepare` 中服务器模式的部分。只支持 Linux。

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::Duration;

use pm_platform::seal::linux::{self as sl, CredKind, METHOD_HOST, METHOD_TPM};
use pm_platform::seal::{self, Sealer};
use pm_platform::service_files::{
    EXIT_CONFIG, EXIT_TRANSIENT, LINUX_TMPFILES_PATH, LINUX_UNIT_PATH, linux_server_tmpfiles, linux_server_unit,
};
use pm_platform::{InstallInfo, Layout, Mode, ServerConfig};
use pm_proto::{Client, EnrollView, Hello, PROTO_V, PendingEnrollView, Request, ServerStatusView, TokenView};
use pm_service::server_files as sf;
use pm_vault::Vault;
use zeroize::Zeroizing;

use crate::install::fail;

pub const BIN: &str = "/usr/local/bin/PassManager";
pub const SVC: &str = "passmanager";
/// 开机时等待 TPM（swtpm 套接字或 /dev/tpmrm0）出现的上限。
pub const TPM_WAIT: Duration = Duration::from_secs(60);

const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const RED: &str = "\x1b[1;31m";
const RESET: &str = "\x1b[0m";

/// 服务器命令使用的布局：`PASSMANAGER_HOME`（测试）时为用户模式，否则系统模式。
pub fn layout() -> Layout {
    if std::env::var_os("PASSMANAGER_HOME").is_some() { Layout::user() } else { Layout::system() }
}

fn need_root(l: &Layout) -> Result<(), String> {
    if l.mode == Mode::System && !pm_platform::process::is_elevated() {
        return Err("需要 root 权限（在服务器上以 root 运行，例如经 SSH 密钥登录后执行）。".into());
    }
    Ok(())
}

fn run(cmd: &str, args: &[&str]) -> Result<String, String> {
    let out = Command::new(cmd).args(args).output().map_err(|e| format!("{cmd}: {e}"))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into())
    } else {
        Err(format!("{cmd} {}: {}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim()))
    }
}

fn chown_mode(p: &Path, uid: u32, gid: u32, mode: u32) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    nix::unistd::chown(p, Some(nix::unistd::Uid::from_raw(uid)), Some(nix::unistd::Gid::from_raw(gid)))
        .map_err(|e| format!("chown {}: {e}", p.display()))?;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).map_err(|e| format!("chmod {}: {e}", p.display()))
}

fn service_ids() -> Option<(u32, u32)> {
    nix::unistd::User::from_name(SVC).ok().flatten().map(|u| (u.uid.as_raw(), u.gid.as_raw()))
}

/// 把服务账户读写的文件交还给服务账户（root 创建或修改之后）。
fn give_back(l: &Layout) -> Result<(), String> {
    if l.mode != Mode::System {
        return Ok(());
    }
    let (uid, gid) = service_ids().ok_or("服务账户 passmanager 不存在")?;
    chown_mode(&l.data_dir, uid, gid, 0o700)?;
    for p in sf::owned_paths(l) {
        if p.is_dir() {
            chown_mode(&p, uid, gid, 0o700)?;
        } else if p.exists() {
            chown_mode(&p, uid, gid, 0o600)?;
        }
    }
    Ok(())
}

fn tss_group() -> Option<String> {
    nix::unistd::Group::from_name("tss").ok().flatten().map(|g| g.name)
}

// ---------------- init ----------------

pub use crate::server_opts::{InitOpts, merge_config};

/// 选择封存方式：沿用已有的；否则 TPM 可用时 L3（host+tpm2），有 systemd-creds 时 L2，都没有时 L1（文件）。
fn choose_sealer(l: &Layout, prev: Option<&InstallInfo>) -> (Box<dyn Sealer>, Option<String>) {
    if let Some(p) = prev
        && let Some(s) = seal::by_method(&p.seal_method, l)
        && s.is_provisioned()
    {
        return (s, None);
    }
    if l.mode == Mode::User {
        return (Box::new(seal::file::FileSealer::new(l)), Some("测试/用户模式：设备密钥只受文件权限保护。".into()));
    }
    seal::best_available(l)
}

pub fn init(o: InitOpts) -> ExitCode {
    match init_inner(&o) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => fail(e),
    }
}

fn init_inner(o: &InitOpts) -> Result<(), String> {
    let l = layout();
    need_root(&l)?;
    pm_crypto::selftest::run_all().map_err(|e| format!("密码学自检失败：{e}"))?;
    let prev = InstallInfo::load(&l).ok();
    let cfg = merge_config(prev.as_ref().and_then(|p| p.server.clone()), o);
    cfg.validate()?;
    sl::set_tpm_socket(cfg.tpm_socket.clone().map(Into::into));
    println!(
        "== 初始化 PassManager 服务器（{}，网页 {} / Agent {}，只允许 {}）==",
        cfg.domain,
        cfg.web_port,
        cfg.agent_port,
        cfg.lan.join(", ")
    );

    std::fs::create_dir_all(&l.data_dir).map_err(|e| e.to_string())?;
    if l.mode == Mode::System {
        if service_ids().is_none() {
            run(
                "useradd",
                &["--system", "--user-group", "--home-dir", "/nonexistent", "--no-create-home", "--shell", "/usr/sbin/nologin", SVC],
            )?;
        }
        let (uid, gid) = service_ids().ok_or("创建服务账户失败")?;
        chown_mode(&l.data_dir, uid, gid, 0o700)?;
        println!("  · 服务账户：{SVC}");
    }

    let (sealer, l1_reason) = choose_sealer(&l, prev.as_ref());
    if !sealer.is_provisioned() {
        let key = Zeroizing::new(pm_crypto::rng::random_array::<32>().map_err(|e| e.to_string())?);
        let mut rand = |b: &mut [u8]| pm_crypto::rng::fill(b).map_err(std::io::Error::other);
        sealer.seal(&key, &mut rand).map_err(|e| format!("封存设备密钥失败：{e}"))?;
    }
    if sealer.method() == seal::file::METHOD && l.mode == Mode::System {
        let (uid, gid) = service_ids().ok_or("服务账户不存在")?;
        chown_mode(&l.data_dir.join("device.key"), uid, gid, 0o600)?;
    }
    let dk = sealer.unseal().map_err(|e| format!("无法解封设备密钥：{e}"))?;
    println!("  · 设备密钥：{}（{}）", seal::level_label(sealer.level()), sealer.describe());
    if let Some(r) = &l1_reason {
        println!("  {RED}{}{RESET} {r}", seal::L1_WARNING);
    }

    let keys = sf::ensure_server_keys(&l, &dk)?;
    println!("  · 内层通道密钥（ML-KEM-1024 + Classic McEliece 6688128），指纹 {}", pm_net::enroll::fpr_text(&keys.fingerprint()));

    if o.cf_token_stdin {
        let mut line = Zeroizing::new(String::new());
        std::io::stdin().read_line(&mut line).map_err(|e| format!("读取 Cloudflare token 失败：{e}"))?;
        sf::store_cf_token(&l, &dk, &line)?;
        println!("  · Cloudflare token 已用设备密钥封存");
    }

    let vault = l.vault_path();
    if vault.exists() || pm_vault::store::backup_path(&vault).exists() {
        Vault::open_device_only(&vault, &dk, sealer.level()).map_err(|e| format!("已有的密码库无法以无口令模式打开：{e}"))?;
        println!("  · 密码库已存在（无口令模式），保持不变");
    } else {
        Vault::create_device_only(&vault, &dk, sealer.level()).map_err(|e| format!("创建密码库失败：{e}"))?;
        println!("  · 已创建无口令密码库（ML-KEM-1024 + McEliece 双层加密，IKM = 设备密钥）");
    }

    let info = InstallInfo {
        mode: l.mode,
        client_user: "root".into(),
        client_uid: Some(0),
        client_gid: None,
        client_sid: None,
        service_user: if l.mode == Mode::System {
            SVC.into()
        } else {
            prev.as_ref().map(|p| p.service_user.clone()).unwrap_or_else(|| "user".into())
        },
        seal_method: sealer.method().into(),
        seal_level: sealer.level(),
        binary: if l.mode == Mode::System {
            BIN.into()
        } else {
            std::env::current_exe().map(|p| p.display().to_string()).unwrap_or_default()
        },
        server: Some(cfg.clone()),
    };
    info.store(&l).map_err(|e| e.to_string())?;

    if !o.skip_acme && !cfg.acme_directory.is_empty() {
        println!("  · 申请 / 检查 TLS 证书（Let's Encrypt DNS-01）……");
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|e| e.to_string())?;
        let certs = pm_net::tls::CertStore::new();
        match rt.block_on(pm_service::online::renew_if_needed(&l, &cfg, &dk, &certs, false)) {
            Ok(true) => println!("    {GREEN}证书已签发{RESET}"),
            Ok(false) => println!("    证书仍在有效期内"),
            Err(e) => println!("    {YELLOW}证书申请失败（服务启动后会按退避自动重试）：{e}{RESET}"),
        }
    }
    give_back(&l)?;

    if l.mode == Mode::System && Path::new("/run/systemd/system").exists() {
        let mut out = std::fs::File::create(LINUX_TMPFILES_PATH).map_err(|e| e.to_string())?;
        std::io::Write::write_all(&mut out, linux_server_tmpfiles(&info, &l).as_bytes()).map_err(|e| e.to_string())?;
        std::fs::write(LINUX_UNIT_PATH, linux_server_unit(&info, &l, tss_group().as_deref())).map_err(|e| e.to_string())?;
        chown_mode(Path::new(LINUX_TMPFILES_PATH), 0, 0, 0o644)?;
        chown_mode(Path::new(LINUX_UNIT_PATH), 0, 0, 0o644)?;
        run("systemd-tmpfiles", &["--create", LINUX_TMPFILES_PATH])?;
        let _ = crate::install::run_harden(&l, &info, crate::install::HardenMode::Fix);
        run("systemctl", &["daemon-reload"])?;
        run("systemctl", &["enable", "passmanager.service"])?;
        if !o.no_start {
            run("systemctl", &["restart", "passmanager.service"])?;
            println!("  · 已启动 passmanager.service");
        }
    }
    println!("\n{GREEN}完成。{RESET}接下来：");
    println!("  passmanager login              # 输出网页的一次性登录链接（2 分钟有效）");
    println!("  passmanager token add <标签>    # 为一个 Agent 生成一次性注册码（10 分钟有效）");
    println!("  passmanager status             # 查看状态（封存等级、证书、令牌）");
    if sealer.level() < 3 {
        println!(
            "当前为 {}。有可用的 TPM（/dev/tpmrm0，或用 --tpm-socket 配置的 swtpm 套接字）后运行 passmanager reseal 升级到 L3。",
            seal::level_label(sealer.level())
        );
    }
    Ok(())
}

// ---------------- 与运行中服务的 root 会话 ----------------

fn root_client() -> Result<Client, pm_proto::ApiError> {
    let l = layout();
    if let Err(e) = need_root(&l) {
        return Err(pm_proto::ApiError::new("FORBIDDEN", e));
    }
    Client::connect_at(&pm_platform::Layout::detect_client().socket, &Hello::Root { v: PROTO_V })
}

fn root_call<T: serde::de::DeserializeOwned>(req: Request) -> Result<T, String> {
    let mut c = root_client().map_err(|e| e.message)?;
    c.call_as(&req).map_err(|e| format!("{}: {}", e.code, e.message))
}

pub fn login() -> ExitCode {
    match root_call::<String>(Request::LoginLink) {
        Ok(url) => {
            println!("{url}");
            eprintln!("（2 分钟内有效，只能使用一次；打开后点击\"登录\"。）");
            ExitCode::SUCCESS
        }
        Err(e) => fail(e),
    }
}

pub fn token_add(label: &str) -> ExitCode {
    match root_call::<EnrollView>(Request::EnrollCreate { label: label.into() }) {
        Ok(v) => {
            println!("{}", v.url);
            eprintln!(
                "一次性注册码（{} 分钟内有效，只能使用一次）。在 Agent 所在的机器上运行：\n  sudo ./install-agent.sh '{}'\n或（已安装 PassManager 时）：\n  passmanager enroll '{}'",
                v.expires_in_secs / 60,
                v.url,
                v.url
            );
            ExitCode::SUCCESS
        }
        Err(e) => fail(e),
    }
}

/// `passmanager import`：从标准输入导入密钥，经本地 root 会话交给运行中的服务。
pub fn import(o: crate::import::ImportOpts) -> ExitCode {
    use std::io::IsTerminal;
    let l = layout();
    if let Err(e) = need_root(&l) {
        return fail(e);
    }
    let data = if std::io::stdin().is_terminal() {
        if !o.interactive {
            return fail(
                "标准输入是终端：请用管道或重定向传入密钥（例如 passmanager import --name x < 文件），或加 --interactive 以不回显方式输入。",
            );
        }
        match crate::import::prompt_interactive(&o) {
            Ok(d) => d,
            Err(e) => return fail(e),
        }
    } else {
        match crate::import::read_limited(std::io::stdin().lock()) {
            Ok(d) => d,
            Err(e) => return fail(e),
        }
    };
    let (input, bytes) = match crate::import::build_entry(&o, &data) {
        Ok(x) => x,
        Err(e) => return fail(e),
    };
    drop(data);
    let k = input.domains.len();
    let name = input.name.clone();
    let mut c = match root_client() {
        Ok(c) => c,
        Err(e) => return fail(e.message),
    };
    let exists = match c.call_as::<Vec<pm_proto::EntryView>>(&Request::Entries) {
        Ok(list) => list.iter().any(|e| e.name == name),
        Err(e) => return fail(import_err(&e)),
    };
    if exists && !o.replace {
        return fail(format!("条目 {name} 已存在（要替换请加 --replace）"));
    }
    let req = if exists { Request::UpdateEntry { original: name.clone(), entry: input } } else { Request::AddEntry { entry: input } };
    match c.call(&req) {
        Ok(v) => {
            println!("已导入 {name}（{bytes} 字节，{k} 个域名）");
            if let Some(fp) = v.get("public_key").and_then(|x| x.as_str()) {
                println!("公钥指纹：{fp}");
            }
            if k == 0 {
                println!("提示：没有绑定域名，在网页里添加域名之前 Agent 无法使用这个条目。");
            }
            ExitCode::SUCCESS
        }
        Err(e) => fail(import_err(&e)),
    }
}

fn import_err(e: &pm_proto::ApiError) -> String {
    match e.code.as_str() {
        "LOCKED" => "密码库已锁定：先运行 passmanager unlock（或在网页解锁）".into(),
        "NOT_READY" => "安全检查未通过，密码库保持锁定：运行 passmanager status 查看".into(),
        "NOT_INITIALIZED" => "密码库尚未初始化：先运行 passmanager init".into(),
        _ => format!("{}: {}", e.code, e.message),
    }
}

pub fn token_list() -> ExitCode {
    let tokens: Result<Vec<TokenView>, _> = root_call(Request::Tokens);
    let pending: Result<Vec<PendingEnrollView>, _> = root_call(Request::Enrollments);
    match (tokens, pending) {
        (Ok(t), Ok(p)) => {
            println!("{:<10} {:<24} {:<20} 最后使用", "ID", "标签", "创建");
            for x in t {
                println!(
                    "{:<10} {:<24} {:<20} {}",
                    x.id,
                    x.label,
                    fmt_ts(x.created as i64),
                    x.last_used.map(|u| fmt_ts(u as i64)).unwrap_or_else(|| "从未".into())
                );
            }
            if !p.is_empty() {
                println!("\n未使用的注册码：");
                for x in p {
                    println!("{:<10} {:<24} 剩余 {} 秒", x.id, x.label, x.expires_in_secs);
                }
            }
            ExitCode::SUCCESS
        }
        (Err(e), _) | (_, Err(e)) => fail(e),
    }
}

pub fn token_revoke(id: &str) -> ExitCode {
    match root_call::<serde_json::Value>(Request::RevokeToken { id: id.into() })
        .or_else(|_| root_call(Request::EnrollCancel { id: id.into() }))
    {
        Ok(_) => {
            println!("已吊销 {id}（立即失效）");
            ExitCode::SUCCESS
        }
        Err(e) => fail(e),
    }
}

pub fn lock(unlock: bool) -> ExitCode {
    match root_call::<serde_json::Value>(if unlock { Request::Unlock } else { Request::Lock }) {
        Ok(_) => {
            println!(
                "{}",
                if unlock {
                    "已解锁"
                } else {
                    "已锁定（Agent 请求将得到 LOCKED，直到在网页或用 passmanager unlock 解锁）"
                }
            );
            ExitCode::SUCCESS
        }
        Err(e) => fail(e),
    }
}

/// 时间戳 → `YYYY-MM-DD HH:MM UTC`。
pub fn fmt_ts(ts: i64) -> String {
    let (y, m, d) = pm_web::civil(ts.div_euclid(86400));
    let s = ts.rem_euclid(86400);
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02} UTC", s / 3600, s % 3600 / 60)
}

pub fn status() -> ExitCode {
    let l = layout();
    let info = InstallInfo::load(&l).ok();
    if info.as_ref().and_then(|i| i.server.as_ref()).is_none() {
        // 不是服务器：Agent 端显示远程配置。
        return crate::remote::status();
    }
    match root_call::<ServerStatusView>(Request::ServerStatus) {
        Ok(s) => {
            print_status(&s);
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("{RED}无法连接服务：{e}{RESET}");
            eprintln!("查看日志：journalctl -u passmanager -n 50");
            ExitCode::from(1)
        }
    }
}

fn print_status(s: &ServerStatusView) {
    let yes = |b: bool, t: &str, f: &str| if b { format!("{GREEN}{t}{RESET}") } else { format!("{RED}{f}{RESET}") };
    println!("域名           {}（网页 :{}，Agent :{}）", s.domain, s.web_port, s.agent_port);
    println!("允许的网段     {}", s.lan.join(", "));
    println!(
        "密码库         {}，{}",
        if s.initialized { yes(!s.locked, "已解锁", "已锁定") } else { format!("{RED}未初始化{RESET}") },
        s.vault_mode
    );
    println!("设备密钥封存   {}（{}）", seal::level_label(s.level), s.seal_method);
    println!("TPM            {}；随机数源：{}", if s.tpm_device { "已发现" } else { "没有" }, s.tpm_rng);
    match s.cert_not_after {
        Some(t) => println!("TLS 证书       到期 {}", fmt_ts(t)),
        None => println!("TLS 证书       {RED}没有可用的证书{RESET}"),
    }
    if let Some(e) = &s.cert_error {
        println!("               {YELLOW}{e}{RESET}");
    }
    println!("Agent 令牌     {}（未使用的注册码 {}）", s.tokens, s.pending_enrollments);
    println!("内层公钥指纹   {}", s.server_key_fingerprint);
    println!("安全检查     {}", yes(s.ready, "全部通过", "未通过（库保持锁定，Agent 得到 NOT_READY）"));
    for i in &s.issues {
        println!("               {RED}✘{RESET} {i}");
    }
    if s.vault_recovered_from_backup {
        println!("{YELLOW}注意：主库文件损坏，已从 vault.pmv.bak 恢复（下次保存时修复）。{RESET}");
    }
}

// ---------------- reseal ----------------

/// L2 → L3：用 TPM（swtpm 套接字或 /dev/tpmrm0）+ 主机密钥重新封存设备密钥。
/// 步骤（每一步都可重复执行，断电后重新运行即可）：解密现有密文 → 用 host+tpm2 加密到 `.new` →
/// 检查文件头并解密比对 → 停止服务 → rename 替换 → 更新 install.json → 库文件头记为 L3 → 启动服务。
pub fn reseal() -> ExitCode {
    let l = layout();
    if let Err(e) = need_root(&l) {
        return fail(e);
    }
    let systemctl = |args: &[&str]| -> Result<(), String> {
        if l.mode == Mode::System && Path::new("/run/systemd/system").exists() { run("systemctl", args).map(|_| ()) } else { Ok(()) }
    };
    match reseal_with(&l, &systemctl) {
        Ok(msg) => {
            println!("{GREEN}{msg}{RESET}");
            ExitCode::SUCCESS
        }
        Err(e) => fail(e),
    }
}

pub fn reseal_with(l: &Layout, systemctl: &dyn Fn(&[&str]) -> Result<(), String>) -> Result<String, String> {
    let mut info = InstallInfo::load(l).map_err(|e| format!("读取安装信息失败：{e}"))?;
    if let Some(s) = &info.server {
        sl::set_tpm_socket(s.tpm_socket.clone().map(Into::into));
    }
    if info.seal_method != METHOD_HOST && info.seal_method != METHOD_TPM {
        return Err(format!("当前封存方式 {} 不支持 reseal（需要 systemd-creds）", info.seal_method));
    }
    let cred = l.data_dir.join("device-key.cred");
    let kind = sl::cred_file_kind(&cred).map_err(|e| format!("读取 {} 失败：{e}", cred.display()))?;
    if info.seal_method == METHOD_TPM && kind == CredKind::HostTpm2 {
        return Ok("已经是 L3（TPM + 主机密钥），无需操作。".into());
    }
    let Some(tpm) = sl::discover_tpm() else {
        return Err("没有发现 TPM：需要 /dev/tpmrm0，或用 passmanager init --tpm-socket <路径> 配置 swtpm 套接字。".into());
    };
    let dk = sl::decrypt_from(&cred).map_err(|e| format!("无法解开现有的设备密钥：{e}"))?;
    let mut new = cred.as_os_str().to_owned();
    new.push(".new");
    let new = PathBuf::from(new);
    sl::encrypt_to(&new, &dk, true).map_err(|e| format!("用 TPM 封存失败（{}）：{e}", tpm.describe()))?;
    let check = sl::decrypt_from(&new).map_err(|e| format!("新密文无法解开：{e}"))?;
    if sl::cred_file_kind(&new).ok() != Some(CredKind::HostTpm2) || *check != *dk {
        let _ = std::fs::remove_file(&new);
        return Err("新密文校验失败，未做任何修改。".into());
    }
    systemctl(&["stop", "passmanager.service"])?;
    std::fs::rename(&new, &cred).map_err(|e| e.to_string())?;
    info.seal_method = METHOD_TPM.into();
    info.seal_level = 3;
    info.store(l).map_err(|e| e.to_string())?;
    // 库文件头记为 L3：此后这个库在只有 L2 的环境里打不开（防降级）。
    let vault = l.vault_path();
    if vault.exists() {
        let mut v = Vault::open_device_only(&vault, &dk, 3).map_err(|e| format!("打开密码库失败：{e}"))?;
        v.upgrade_seal_level(3).map_err(|e| e.to_string())?;
        give_back(l)?;
    }
    systemctl(&["start", "passmanager.service"])?;
    Ok(format!(
        "已升级到 L3（{}）。注意：此后只有这块 TPM 能解开设备密钥；TPM 状态丢失或容器迁移到别的节点后库将永久无法打开。",
        tpm.describe()
    ))
}

// ---------------- service-prepare（服务器模式部分） ----------------

/// 以 root 在服务启动前运行：创建运行目录与密钥交接目录；L3 时有限次等待 TPM；
/// 解密设备密钥交给服务（服务账户 0400，读后即删）。
/// 返回 Err(退出码)：TPM 未出现、L3 解密失败按暂时性故障（75，systemd 重试）；
/// 主机密钥解密失败时不在这里失败，交给服务以 78 报告配置错误。
pub fn prepare(l: &Layout, info: &InstallInfo) -> Result<(), u8> {
    prepare_with(l, info, TPM_WAIT)
}

pub fn prepare_with(l: &Layout, info: &InstallInfo, tpm_wait: Duration) -> Result<(), u8> {
    let cfg = info.server.as_ref().ok_or(EXIT_CONFIG)?;
    sl::set_tpm_socket(cfg.tpm_socket.clone().map(Into::into));
    let ids = if l.mode == Mode::System { service_ids() } else { None };
    for (dir, mode) in [(&l.run_dir, 0o750), (&l.key_handoff_dir(), 0o700)] {
        let _ = std::fs::create_dir_all(dir);
        if let Some((uid, gid)) = ids {
            let _ = chown_mode(dir, uid, gid, mode);
        }
    }
    if !info.seal_method.starts_with("systemd-creds") {
        return Ok(());
    }
    let cred = l.data_dir.join("device-key.cred");
    let tpm = info.seal_method == METHOD_TPM;
    if tpm {
        match sl::wait_for_tpm(tpm_wait, Duration::from_millis(100)) {
            Some(t) => eprintln!("[PassManager] TPM: {}", t.describe()),
            None => {
                eprintln!("[PassManager] TPM 在 {} 秒内没有出现（swtpm 套接字或 /dev/tpmrm0），稍后重试", tpm_wait.as_secs());
                return Err(EXIT_TRANSIENT);
            }
        }
        // 防降级：install.json 说 L3，密文却只用主机密钥封存 → 不交出密钥（服务随后以 78 退出）。
        if sl::cred_file_kind(&cred).ok() != Some(CredKind::HostTpm2) {
            eprintln!("[PassManager] 设备密钥密文不是 host+tpm2 类型（可能被替换为较低等级），拒绝使用");
            return Ok(());
        }
    }
    match sl::decrypt_from(&cred) {
        Ok(k) => {
            let p = l.key_handoff_path();
            let tmp = p.with_extension("tmp");
            let r = pm_platform::paths::write_atomic(&tmp, k.as_ref(), 0o400).and_then(|_| {
                if let Some((uid, gid)) = ids {
                    nix::unistd::chown(&tmp, Some(nix::unistd::Uid::from_raw(uid)), Some(nix::unistd::Gid::from_raw(gid)))
                        .map_err(std::io::Error::from)?;
                }
                std::fs::rename(&tmp, &p)
            });
            if let Err(e) = r {
                eprintln!("[PassManager] 写入密钥交接文件失败：{e}");
                return Err(EXIT_TRANSIENT);
            }
            Ok(())
        }
        Err(e) if tpm => {
            eprintln!("[PassManager] 用 TPM 解封设备密钥失败（{e}），稍后重试");
            Err(EXIT_TRANSIENT)
        }
        Err(e) => {
            eprintln!("[PassManager] 解封设备密钥失败：{e}");
            Ok(())
        }
    }
}

/// 输出服务器模式的 systemd 单元 / tmpfiles.d（系统布局；有 install.json 时使用其中的配置）。
pub fn print_unit(tpm_group: Option<&str>, tmpfiles: bool) -> ExitCode {
    let l = Layout::system();
    let info = InstallInfo::load(&l).ok().filter(|i| i.server.is_some()).unwrap_or_else(|| InstallInfo {
        mode: Mode::System,
        client_user: "root".into(),
        client_uid: Some(0),
        client_gid: None,
        client_sid: None,
        service_user: SVC.into(),
        seal_method: METHOD_HOST.into(),
        seal_level: 2,
        binary: BIN.into(),
        server: Some(ServerConfig::default()),
    });
    print!("{}", if tmpfiles { linux_server_tmpfiles(&info, &l) } else { linux_server_unit(&info, &l, tpm_group) });
    ExitCode::SUCCESS
}

/// 导入证书（不使用 ACME 时，或测试）：私钥用设备密钥封存。
pub fn import_cert(chain: &Path, key: &Path) -> ExitCode {
    let l = layout();
    let r = (|| -> Result<(), String> {
        need_root(&l)?;
        let info = InstallInfo::load(&l).map_err(|e| e.to_string())?;
        let s = seal::by_method(&info.seal_method, &l).ok_or("未知的封存方式")?;
        let dk = s.unseal().map_err(|e| e.to_string())?;
        let c = std::fs::read_to_string(chain).map_err(|e| e.to_string())?;
        let k = Zeroizing::new(std::fs::read_to_string(key).map_err(|e| e.to_string())?);
        pm_net::tls::CertStore::new().set_pem(&c, &k)?;
        sf::store_cert(&l, &dk, &c, &k)?;
        give_back(&l)
    })();
    match r {
        Ok(()) => {
            println!("证书已导入（重启服务后生效：systemctl restart passmanager）");
            ExitCode::SUCCESS
        }
        Err(e) => fail(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pm_platform::seal::linux::SystemdCredsSealer;

    #[test]
    fn exit_codes_and_wait_bound() {
        assert_eq!(EXIT_CONFIG, 78);
        assert_ne!(EXIT_TRANSIENT, EXIT_CONFIG);
        assert!(TPM_WAIT <= Duration::from_secs(90), "开机等待必须有上限");
        assert_eq!(fmt_ts(0), "1970-01-01 00:00 UTC");
    }

    /// reseal 与 service-prepare：用假的 systemd-creds 与假的 swtpm 套接字走一遍
    /// L2 初始化 → 没有 TPM 时拒绝（不改任何东西）→ 有 TPM 时升级到 L3 → 库文件头升级、L2 下打不开 →
    /// service-prepare 交出密钥 → TPM 迟迟不出现时以 75 退出 → 密文被换成低等级时拒绝交出。
    #[test]
    fn reseal_and_prepare_with_fake_tpm() {
        let dir = tempfile::tempdir().unwrap();
        let fake = pm_platform::seal::linux::testing::fake_creds(dir.path());
        let sock = dir.path().join("tpm.sock");
        // SAFETY: 本测试独占这些环境变量（同一测试二进制里没有别的测试使用它们）。
        unsafe {
            std::env::set_var("PASSMANAGER_SYSTEMD_CREDS", &fake);
            std::env::set_var("PASSMANAGER_TPM_SOCKET", &sock);
            std::env::set_var("PASSMANAGER_TPM_DEVICE", dir.path().join("no-tpmrm0"));
        }
        let l = Layout {
            mode: Mode::User,
            data_dir: dir.path().join("data"),
            run_dir: dir.path().join("run"),
            socket: dir.path().join("run/s"),
        };
        std::fs::create_dir_all(&l.data_dir).unwrap();
        let sealer = SystemdCredsSealer::new(false, &l);
        let key = [9u8; 32];
        let mut rand = |b: &mut [u8]| {
            b.fill(1);
            Ok(())
        };
        sealer.seal(&key, &mut rand).unwrap();
        let mut v = Vault::create_device_only(&l.vault_path(), &key, 2).unwrap();
        v.payload.settings.auto_lock_hours = 5;
        v.save().unwrap();
        let info = InstallInfo {
            mode: Mode::User,
            client_user: "root".into(),
            client_uid: Some(0),
            client_gid: None,
            client_sid: None,
            service_user: "x".into(),
            seal_method: METHOD_HOST.into(),
            seal_level: 2,
            binary: "/x".into(),
            server: Some(ServerConfig { tpm_socket: Some(sock.display().to_string()), ..Default::default() }),
        };
        info.store(&l).unwrap();
        let calls = std::sync::Mutex::new(Vec::<String>::new());
        let sysctl = |a: &[&str]| -> Result<(), String> {
            calls.lock().unwrap().push(a.join(" "));
            Ok(())
        };
        // L2 时 service-prepare 交出密钥。
        prepare(&l, &info).unwrap();
        assert_eq!(std::fs::read(l.key_handoff_path()).unwrap(), key);
        std::fs::remove_file(l.key_handoff_path()).unwrap();

        // 没有 TPM：拒绝，什么都不改。
        let before = std::fs::read(l.data_dir.join("device-key.cred")).unwrap();
        assert!(reseal_with(&l, &sysctl).unwrap_err().contains("没有发现 TPM"));
        assert_eq!(std::fs::read(l.data_dir.join("device-key.cred")).unwrap(), before);
        assert!(calls.lock().unwrap().is_empty(), "失败时不停服务");

        // 出现 swtpm 套接字：升级。
        let _listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        unsafe { std::env::set_var("FAKE_EXPECT_TPM2_DEVICE", format!("swtpm:path={}", sock.display())) };
        let msg = reseal_with(&l, &sysctl).unwrap();
        assert!(msg.contains("L3"), "{msg}");
        assert_eq!(*calls.lock().unwrap(), vec!["stop passmanager.service".to_string(), "start passmanager.service".to_string()]);
        let info3 = InstallInfo::load(&l).unwrap();
        assert_eq!((info3.seal_method.as_str(), info3.seal_level), (METHOD_TPM, 3));
        assert_eq!(sl::cred_file_kind(&l.data_dir.join("device-key.cred")).unwrap(), CredKind::HostTpm2);
        assert!(!l.data_dir.join("device-key.cred.new").exists());
        assert_eq!(Vault::read_header(&l.vault_path()).unwrap().seal_level, 3);
        assert!(Vault::open_device_only(&l.vault_path(), &key, 2).is_err(), "L3 的库在 L2 环境里打不开");
        assert_eq!(Vault::open_device_only(&l.vault_path(), &key, 3).unwrap().payload.settings.auto_lock_hours, 5);
        // 再次运行：已经是 L3。
        assert!(reseal_with(&l, &sysctl).unwrap().contains("无需操作"));

        // L3 时 service-prepare 带着 SYSTEMD_TPM2_DEVICE 解密并交出密钥。
        prepare(&l, &info3).unwrap();
        assert_eq!(std::fs::read(l.key_handoff_path()).unwrap(), key);
        std::fs::remove_file(l.key_handoff_path()).unwrap();

        // 密文被换成只用主机密钥封存的版本（降级）：不交出密钥。
        sl::encrypt_to(&l.data_dir.join("device-key.cred"), &key, false).unwrap();
        prepare(&l, &info3).unwrap();
        assert!(!l.key_handoff_path().exists());
        sl::encrypt_to(&l.data_dir.join("device-key.cred"), &key, true).unwrap();

        // TPM 解密失败（例如 swtpm 未就绪）：暂时性故障。
        unsafe { std::env::set_var("FAKE_FAIL_TPM", "1") };
        assert_eq!(prepare(&l, &info3), Err(EXIT_TRANSIENT));
        unsafe { std::env::remove_var("FAKE_FAIL_TPM") };
        drop(_listener);
        std::fs::remove_file(&sock).unwrap();
        // TPM 迟迟不出现（宿主机的 swtpm 还没就绪）：等待有上限，以 75（暂时性故障，systemd 重试）退出，而不是 78。
        let t0 = std::time::Instant::now();
        assert_eq!(prepare_with(&l, &info3, Duration::from_millis(300)), Err(EXIT_TRANSIENT));
        assert!(t0.elapsed() >= Duration::from_millis(300) && t0.elapsed() < Duration::from_secs(5));
        assert!(!l.key_handoff_path().exists());
        unsafe {
            for k in ["PASSMANAGER_SYSTEMD_CREDS", "PASSMANAGER_TPM_SOCKET", "PASSMANAGER_TPM_DEVICE", "FAKE_EXPECT_TPM2_DEVICE"] {
                std::env::remove_var(k);
            }
        }
    }
}
