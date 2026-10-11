//! Linux：systemd-creds 封存。
//!
//! 有可用的 TPM2 时使用 `--with-key=host+tpm2`（L3），否则 `--with-key=host`（L2）。
//! 不绑定 PCR（`--tpm2-pcrs=`），固件或内核升级后仍能解开（LXC 没有自己的启动度量，PCR 反映的是宿主机）。
//!
//! 设备密钥交给服务的方式（按优先级）：
//! 1. 服务器模式：`ExecStartPre=+… service-prepare` 以 root 解密到 `/run/passmanager-key/device.key`
//!    （服务账户 0400），服务读取后立即删除。非特权 LXC 不支持 `LoadCredentialEncrypted=`，所以用这个等价方式；
//! 2. 单机模式：单元的 `LoadCredentialEncrypted=passmanager-device-key:<cred>`，明文只出现在
//!    服务专属的 `$CREDENTIALS_DIRECTORY`（内存文件系统）中；
//! 3. 兜底（仅 root，例如安装程序、`init`、`reseal`）：直接调用 `systemd-creds decrypt`。
//!
//! TPM 有两种形态：配置的 swtpm Unix 套接字（例如宿主机为容器提供的软件 TPM，`server.tpm_socket`
//! 或环境变量 `PASSMANAGER_TPM_SOCKET`；配置且存在时优先），或自动检测的内核设备 `/dev/tpmrm0`。套接字模式下每次调用 systemd-creds 都带上
//! `SYSTEMD_TPM2_DEVICE=swtpm:path=<套接字>`（需要 Debian 的 libtss2-tcti-swtpm，调用者属于 tss 组）。
//!
//! `PASSMANAGER_SYSTEMD_CREDS` 可指定 systemd-creds 程序路径（测试用替身）；
//! `PASSMANAGER_TPM_SOCKET` / `PASSMANAGER_TPM_DEVICE` 覆盖 TPM 路径。

use std::ffi::OsString;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use super::{RandFn, Sealer, key_from_bytes};
use crate::paths::Layout;

pub const METHOD_HOST: &str = "systemd-creds-host";
pub const METHOD_TPM: &str = "systemd-creds-host+tpm2";
pub const CRED_NAME: &str = "passmanager-device-key";
pub const TPM_DEVICE: &str = "/dev/tpmrm0";

/// 配置的 swtpm 套接字路径（install.json 的 `server.tpm_socket`，没有默认值）；环境变量 `PASSMANAGER_TPM_SOCKET` 优先。
static TPM_SOCKET: Mutex<Option<PathBuf>> = Mutex::new(None);

pub fn set_tpm_socket(p: Option<PathBuf>) {
    *TPM_SOCKET.lock().unwrap() = p;
}

pub struct SystemdCredsSealer {
    tpm: bool,
    cred_path: PathBuf,
    handoff: PathBuf,
}

fn creds_bin() -> OsString {
    std::env::var_os("PASSMANAGER_SYSTEMD_CREDS").filter(|v| !v.is_empty()).unwrap_or_else(|| "systemd-creds".into())
}

/// 可用的 TPM：swtpm 套接字（优先）或内核设备。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TpmPath {
    Socket(PathBuf),
    Device(PathBuf),
}

impl TpmPath {
    pub fn describe(&self) -> String {
        match self {
            TpmPath::Socket(p) => format!("swtpm 套接字 {}", p.display()),
            TpmPath::Device(p) => format!("设备 {}", p.display()),
        }
    }
}

fn socket_path() -> Option<PathBuf> {
    std::env::var_os("PASSMANAGER_TPM_SOCKET").filter(|v| !v.is_empty()).map(PathBuf::from).or_else(|| TPM_SOCKET.lock().unwrap().clone())
}

fn device_path() -> PathBuf {
    std::env::var_os("PASSMANAGER_TPM_DEVICE").filter(|v| !v.is_empty()).map(PathBuf::from).unwrap_or_else(|| TPM_DEVICE.into())
}

fn is_socket(p: &Path) -> bool {
    use std::os::unix::fs::FileTypeExt;
    fs::metadata(p).is_ok_and(|m| m.file_type().is_socket())
}

// ---------------- root 访问 TPM 所需的附加组 ----------------
//
// swtpm 套接字通常是 `srw-rw---- nobody:tss`，所在目录也只对 tss 组开放。非特权 LXC 里属主 nobody 是未映射的宿主机
// uid，容器内的 root 没有 DAC 豁免，只能靠组权限；而 systemd 以 `ExecStartPre=+` 启动的 root 进程没有任何附加组。
// 所以以 root 运行时，在访问套接字或设备之前把"目录与套接字的组"（以及 tss 组）加入本进程的附加组；
// 子进程（systemd-creds）随之继承。只加入组，从不修改任何文件的权限。

/// 加入附加组所需的系统调用（测试中替换为模拟实现）。
pub(crate) trait GroupOps {
    fn is_root(&self) -> bool;
    fn groups(&self) -> Vec<u32>;
    fn egid(&self) -> u32;
    fn set_groups(&mut self, g: &[u32]) -> io::Result<()>;
    /// (mode, gid)
    fn stat(&self, p: &Path) -> io::Result<(u32, u32)>;
    fn tss_gid(&self) -> Option<u32>;
}

struct RealOps;

impl GroupOps for RealOps {
    fn is_root(&self) -> bool {
        nix::unistd::geteuid().is_root()
    }
    fn groups(&self) -> Vec<u32> {
        nix::unistd::getgroups().map(|g| g.into_iter().map(|g| g.as_raw()).collect()).unwrap_or_default()
    }
    fn egid(&self) -> u32 {
        nix::unistd::getegid().as_raw()
    }
    fn set_groups(&mut self, g: &[u32]) -> io::Result<()> {
        // SAFETY: setgroups 系统调用；glibc 的包装会同步到进程内所有线程。
        if unsafe { libc::setgroups(g.len() as _, g.as_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    fn stat(&self, p: &Path) -> io::Result<(u32, u32)> {
        use std::os::unix::fs::MetadataExt;
        fs::metadata(p).map(|m| (m.mode(), m.gid()))
    }
    fn tss_gid(&self) -> Option<u32> {
        nix::unistd::Group::from_name("tss").ok().flatten().map(|g| g.gid.as_raw())
    }
}

/// 让 root 能访问 `path`（及其所在目录）所需加入的组：目录对其他人不可进入但对组可进入时加入目录的组；
/// 套接字 / 设备对其他人不可读写但对组可读写时加入它的组；另外总是加入 tss（存在时）。非 root 不做任何事。
/// 返回新加入的组。
pub(crate) fn join_groups_for(ops: &mut dyn GroupOps, path: &Path) -> io::Result<Vec<u32>> {
    if !ops.is_root() {
        return Ok(vec![]);
    }
    let mut added = Vec::new();
    let join = |ops: &mut dyn GroupOps, gid: u32, added: &mut Vec<u32>| -> io::Result<()> {
        let mut g = ops.groups();
        if gid == 0 || g.contains(&gid) || ops.egid() == gid {
            return Ok(());
        }
        g.push(gid);
        ops.set_groups(&g)?;
        added.push(gid);
        Ok(())
    };
    if let Some(t) = ops.tss_gid() {
        join(ops, t, &mut added)?;
    }
    // 先目录（否则连套接字本身都 stat 不到），再套接字。
    if let Some(parent) = path.parent()
        && let Ok((mode, gid)) = ops.stat(parent)
        && group_only(mode, true)
    {
        join(ops, gid, &mut added)?;
    }
    if let Ok((mode, gid)) = ops.stat(path)
        && group_only(mode, false)
    {
        join(ops, gid, &mut added)?;
    }
    Ok(added)
}

/// 目录或套接字只对组开放（对其他人不开放）时需要的组：目录看 x 位，套接字 / 设备看 rw 位。
fn group_only(mode: u32, dir: bool) -> bool {
    if dir { mode & 0o001 == 0 && mode & 0o010 != 0 } else { mode & 0o006 != 0o006 && mode & 0o060 == 0o060 }
}

/// 服务账户访问配置的 swtpm 套接字所需的附加组（写进 systemd 单元的 SupplementaryGroups）：
/// tss（存在时），以及套接字所在目录与套接字本身只对组开放时它们的组。只返回有名字的组，跳过 root 与 nogroup。
pub fn service_tpm_groups() -> Vec<String> {
    ensure_tpm_access();
    let mut gids: Vec<u32> = RealOps.tss_gid().into_iter().collect();
    if let Some(s) = socket_path() {
        for (p, dir) in [(s.parent().map(Path::to_path_buf), true), (Some(s.clone()), false)] {
            if let Some(p) = p
                && let Ok((mode, gid)) = RealOps.stat(&p)
                && group_only(mode, dir)
                && !gids.contains(&gid)
            {
                gids.push(gid);
            }
        }
    }
    gids.into_iter()
        .filter(|g| *g != 0)
        .filter_map(|g| nix::unistd::Group::from_gid(nix::unistd::Gid::from_raw(g)).ok().flatten().map(|g| g.name))
        .filter(|n| n != "nogroup" && n != "root")
        .collect()
}

static JOINED: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());

/// 以 root 运行时，为配置的 swtpm 套接字与 TPM 设备加入所需的附加组（每个路径只做一次；失败时记录原因，不中止）。
pub fn ensure_tpm_access() {
    if !nix::unistd::geteuid().is_root() {
        return;
    }
    let mut paths = vec![device_path()];
    if let Some(s) = socket_path() {
        paths.insert(0, s);
    }
    for p in paths {
        let mut done = JOINED.lock().unwrap();
        if done.contains(&p) {
            continue;
        }
        match join_groups_for(&mut RealOps, &p) {
            Ok(added) => {
                if !added.is_empty() {
                    eprintln!("[PassManager] 为访问 {} 加入附加组 {:?}", p.display(), added);
                }
                // 路径还不存在时（swtpm 尚未就绪）下次再试。
                if p.exists() {
                    done.push(p);
                }
            }
            Err(e) => eprintln!("[PassManager] 无法为访问 {} 加入附加组：{e}", p.display()),
        }
    }
}

/// 套接字的状态（用于等待与诊断）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SocketState {
    Ready,
    /// ENOENT：套接字（或所在目录）不存在。
    NotFound,
    /// EACCES / EPERM：没有权限（stat 或 connect）。
    PermissionDenied(String),
    /// ECONNREFUSED：文件在，但 swtpm 没有在监听。
    Refused,
    NotSocket,
    Other(String),
}

impl SocketState {
    pub fn describe(&self, p: &Path) -> String {
        match self {
            SocketState::Ready => format!("swtpm 套接字 {} 可用", p.display()),
            SocketState::NotFound => format!("swtpm 套接字 {} 不存在（ENOENT）", p.display()),
            SocketState::PermissionDenied(e) => {
                format!("没有权限访问 swtpm 套接字 {}（EACCES：{e}；需要所在目录与套接字的组权限，例如 tss）", p.display())
            }
            SocketState::Refused => format!("swtpm 套接字 {} 拒绝连接（ECONNREFUSED：swtpm 没有在监听）", p.display()),
            SocketState::NotSocket => format!("{} 不是 Unix 套接字", p.display()),
            SocketState::Other(e) => format!("访问 swtpm 套接字 {} 失败：{e}", p.display()),
        }
    }
}

fn classify(e: &io::Error, what: &str) -> SocketState {
    match e.raw_os_error() {
        Some(libc::ENOENT) | Some(libc::ENOTDIR) => SocketState::NotFound,
        Some(libc::EACCES) | Some(libc::EPERM) => SocketState::PermissionDenied(format!("{what}: {e}")),
        Some(libc::ECONNREFUSED) => SocketState::Refused,
        _ => SocketState::Other(format!("{what}: {e}")),
    }
}

/// 检查套接字：stat 后试连接一次（立即关闭）。
pub fn socket_state(p: &Path) -> SocketState {
    use std::os::unix::fs::FileTypeExt;
    match fs::metadata(p) {
        Err(e) => classify(&e, "stat"),
        Ok(m) if !m.file_type().is_socket() => SocketState::NotSocket,
        Ok(_) => match std::os::unix::net::UnixStream::connect(p) {
            Ok(_) => SocketState::Ready,
            Err(e) => classify(&e, "connect"),
        },
    }
}

/// 没有找到可用的 TPM 时的诊断信息。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TpmMissing {
    pub socket: Option<(PathBuf, SocketState)>,
    pub device: PathBuf,
}

impl TpmMissing {
    pub fn describe(&self) -> String {
        match &self.socket {
            Some((p, s)) => format!("{}；设备 {} 也不存在", s.describe(p), self.device.display()),
            None => format!("没有配置 swtpm 套接字，设备 {} 不存在", self.device.display()),
        }
    }

    pub fn permission_denied(&self) -> bool {
        matches!(self.socket, Some((_, SocketState::PermissionDenied(_))))
    }
}

/// 发现 TPM：配置的 swtpm 套接字存在时优先使用，否则内核设备 /dev/tpmrm0。
/// 以 root 运行时先加入访问所需的附加组。
pub fn discover_tpm() -> Option<TpmPath> {
    ensure_tpm_access();
    if let Some(s) = socket_path()
        && is_socket(&s)
    {
        return Some(TpmPath::Socket(s));
    }
    let d = device_path();
    d.exists().then_some(TpmPath::Device(d))
}

/// 传给每个 systemd-creds 调用的 `SYSTEMD_TPM2_DEVICE`（套接字模式：`swtpm:path=…`；设备模式不设置，用 systemd 的自动选择）。
pub fn tpm2_device_env() -> Option<String> {
    match discover_tpm()? {
        TpmPath::Socket(p) => Some(format!("swtpm:path={}", p.display())),
        TpmPath::Device(_) => None,
    }
}

fn creds_cmd() -> Command {
    let mut c = Command::new(creds_bin());
    if let Some(v) = tpm2_device_env() {
        c.env("SYSTEMD_TPM2_DEVICE", v);
        // discover_tpm 已经让本进程加入了访问套接字所需的组（子进程继承）；这里再保证 tss 组，作为兜底。
        if let Some(groups) = groups_with_tss() {
            use std::os::unix::process::CommandExt;
            // SAFETY: pre_exec 中只调用 setgroups（系统调用），参数在 fork 之前准备好。
            unsafe {
                c.pre_exec(move || {
                    if libc::setgroups(groups.len() as _, groups.as_ptr()) != 0 {
                        return Err(io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        }
    }
    c
}

/// 以 root 运行且存在 tss 组、当前还不在该组时：返回"当前附加组 + tss"。
fn groups_with_tss() -> Option<Vec<libc::gid_t>> {
    if !nix::unistd::geteuid().is_root() {
        return None;
    }
    let tss = nix::unistd::Group::from_name("tss").ok().flatten()?.gid.as_raw();
    let mut g: Vec<libc::gid_t> = nix::unistd::getgroups().ok()?.into_iter().map(|g| g.as_raw()).collect();
    if g.contains(&tss) || nix::unistd::getegid().as_raw() == tss {
        return None;
    }
    g.push(tss);
    Some(g)
}

/// 开机时有限次等待 TPM 可用（宿主机的 swtpm 可能比容器晚就绪）。先加入访问所需的附加组；
/// 配置了套接字时要能连接上才算可用。超时返回最后一次的诊断（ENOENT / EACCES / ECONNREFUSED 等）。
pub fn wait_for_tpm(timeout: Duration, interval: Duration) -> Result<TpmPath, TpmMissing> {
    let start = Instant::now();
    loop {
        ensure_tpm_access();
        let sock = socket_path().map(|p| {
            let s = socket_state(&p);
            (p, s)
        });
        if let Some((p, SocketState::Ready)) = &sock {
            return Ok(TpmPath::Socket(p.clone()));
        }
        let dev = device_path();
        if dev.exists() {
            return Ok(TpmPath::Device(dev));
        }
        if start.elapsed() >= timeout {
            return Err(TpmMissing { socket: sock, device: dev });
        }
        std::thread::sleep(interval);
    }
}

/// 解析 `systemd-creds --version` 的主版本号。
pub fn systemd_version() -> Option<u32> {
    let out = creds_cmd().arg("--version").output().ok()?;
    parse_version(&String::from_utf8_lossy(&out.stdout))
}

/// `systemd 257 (257.9-1~deb13u1)` → 257。
pub fn parse_version(s: &str) -> Option<u32> {
    s.split_whitespace().nth(1)?.parse().ok()
}

/// `--with-key=` 的取值。
pub fn with_key(tpm: bool) -> &'static str {
    if tpm { "host+tpm2" } else { "host" }
}

/// systemd 加密凭据的密钥类型（文件头前 16 字节的 ID，见 systemd `src/shared/creds-util.h`）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CredKind {
    Host,
    Tpm2,
    HostTpm2,
    Null,
    Other,
}

const ID_HOST: [u8; 16] = hexid("5a1c6a86df9d4096b1d5a65e0862f19a");
const ID_TPM2: [u8; 16] = hexid("0c7cc07b117645919c4b0bea08bc20fe");
const ID_TPM2_PK: [u8; 16] = hexid("faf7eb9341e3412ca1a436f95a29362f");
const ID_HOST_TPM2: [u8; 16] = hexid("93a894094874449090caf2fc93cab553");
const ID_HOST_TPM2_PK: [u8; 16] = hexid("af4950a849134eb1a73846304ff30c05");
const ID_NULL: [u8; 16] = hexid("058469daf6f54324800549da0f8ea2fb");

const fn hexid(s: &str) -> [u8; 16] {
    let b = s.as_bytes();
    let mut out = [0u8; 16];
    let mut i = 0;
    while i < 16 {
        out[i] = nib(b[2 * i]) << 4 | nib(b[2 * i + 1]);
        i += 1;
    }
    out
}

const fn nib(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        _ => c - b'a' + 10,
    }
}

/// 识别凭据文件的密钥类型。systemd-creds 默认输出 base64，也接受原始二进制。
pub fn cred_kind(data: &[u8]) -> CredKind {
    use base64::Engine;
    let text: Vec<u8> = data.iter().copied().filter(|b| !b.is_ascii_whitespace()).collect();
    let raw = base64::engine::general_purpose::STANDARD.decode(&text).unwrap_or_else(|_| data.to_vec());
    let Some(id) = raw.get(..16) else { return CredKind::Other };
    match <[u8; 16]>::try_from(id).unwrap() {
        ID_HOST => CredKind::Host,
        ID_TPM2 | ID_TPM2_PK => CredKind::Tpm2,
        ID_HOST_TPM2 | ID_HOST_TPM2_PK => CredKind::HostTpm2,
        ID_NULL => CredKind::Null,
        _ => CredKind::Other,
    }
}

pub fn cred_file_kind(p: &Path) -> io::Result<CredKind> {
    Ok(cred_kind(&fs::read(p)?))
}

/// 加密 32 字节密钥到 `out`（先写临时文件再 rename，断电不会留下半个密文）。
pub fn encrypt_to(out: &Path, key: &[u8; 32], tpm: bool) -> io::Result<()> {
    encrypt_named(out, key, tpm, CRED_NAME)
}

fn encrypt_named(out: &Path, key: &[u8], tpm: bool, name: &str) -> io::Result<()> {
    if let Some(d) = out.parent() {
        fs::create_dir_all(d)?;
    }
    let mut tmp = out.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    let _ = fs::remove_file(&tmp);
    let mut child = creds_cmd()
        .args(["encrypt", &format!("--name={name}"), &format!("--with-key={}", with_key(tpm)), "--tpm2-pcrs=", "-"])
        .arg(&tmp)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    child.stdin.take().expect("stdin").write_all(key)?;
    let out_ = child.wait_with_output()?;
    if !out_.status.success() {
        let _ = fs::remove_file(&tmp);
        return Err(io::Error::other(format!("systemd-creds encrypt failed: {}", String::from_utf8_lossy(&out_.stderr).trim())));
    }
    // 文件头必须是期望的密钥类型（防止 systemd 悄悄退回到别的方式）。
    let want = if tpm { CredKind::HostTpm2 } else { CredKind::Host };
    let got = cred_file_kind(&tmp)?;
    if got != want {
        let _ = fs::remove_file(&tmp);
        return Err(io::Error::other(format!("systemd-creds produced a {got:?} credential, expected {want:?}")));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))?;
    }
    fs::File::open(&tmp)?.sync_all()?;
    fs::rename(&tmp, out)?;
    if let Some(d) = out.parent()
        && let Ok(f) = fs::File::open(d)
    {
        let _ = f.sync_all();
    }
    Ok(())
}

/// 解密（需要 root：主机密钥 `/var/lib/systemd/credential.secret` 只有 root 可读；L3 还需要 TPM）。
pub fn decrypt_from(cred: &Path) -> io::Result<Zeroizing<[u8; 32]>> {
    let out = decrypt_named(cred, CRED_NAME)?;
    key_from_bytes(&out)
}

fn decrypt_named(cred: &Path, name: &str) -> io::Result<Zeroizing<Vec<u8>>> {
    let out = creds_cmd().args(["decrypt", &format!("--name={name}")]).arg(cred).arg("-").stderr(Stdio::piped()).output()?;
    if !out.status.success() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("无法解封设备密钥：{}", String::from_utf8_lossy(&out.stderr).trim()),
        ));
    }
    Ok(Zeroizing::new(out.stdout))
}

/// 是否发现了 TPM（套接字或设备）。
pub fn tpm_device_present() -> bool {
    discover_tpm().is_some()
}

/// TPM 是否真的可用于封存：发现了 TPM，用 `host+tpm2` 试加密一段随机数据，文件头是 host+tpm2 类型，
/// 且解密能得到原文。`systemd-creds has-tpm2` 只检查内核设备（套接字模式下返回 11），所以不用它判断。
pub fn tpm_usable(rand: RandFn) -> bool {
    if discover_tpm().is_none() {
        return false;
    }
    let mut probe = Zeroizing::new([0u8; 32]);
    if rand(probe.as_mut()).is_err() {
        return false;
    }
    let dir = std::env::temp_dir().join(format!("pm-tpm-probe-{}", std::process::id()));
    let path = dir.join("probe.cred");
    let ok = encrypt_named(&path, probe.as_ref(), true, "passmanager-tpm-probe")
        .and_then(|_| decrypt_named(&path, "passmanager-tpm-probe"))
        .is_ok_and(|back| back.as_slice() == probe.as_slice());
    let _ = fs::remove_dir_all(&dir);
    ok
}

impl SystemdCredsSealer {
    /// 检测是否可用；不可用时返回原因（用于 L1 警告）。
    pub fn probe(layout: &Layout) -> Result<Self, String> {
        if !Path::new("/run/systemd/system").exists() {
            return Err("未检测到以 systemd 启动的系统（可能是容器或使用其他 init 系统）。".into());
        }
        match systemd_version() {
            Some(v) if v >= 250 => {}
            Some(v) => return Err(format!("systemd 版本为 {v}，需要 ≥ 250 才支持 systemd-creds 封存。")),
            None => return Err("未找到 systemd-creds 命令。".into()),
        }
        let mut rand = |b: &mut [u8]| {
            let mut f = fs::File::open("/dev/urandom")?;
            f.read_exact(b)
        };
        Ok(Self::new(tpm_usable(&mut rand), layout))
    }

    pub fn new(tpm: bool, layout: &Layout) -> Self {
        Self { tpm, cred_path: layout.data_dir.join("device-key.cred"), handoff: layout.key_handoff_path() }
    }

    pub fn from_method(method: &str, layout: &Layout) -> Self {
        Self::new(method == METHOD_TPM, layout)
    }

    pub fn cred_path(&self) -> &PathBuf {
        &self.cred_path
    }

    pub fn uses_tpm(&self) -> bool {
        self.tpm
    }
}

impl Sealer for SystemdCredsSealer {
    fn method(&self) -> &'static str {
        if self.tpm { METHOD_TPM } else { METHOD_HOST }
    }

    fn level(&self) -> u8 {
        if self.tpm { 3 } else { 2 }
    }

    fn describe(&self) -> String {
        if self.tpm {
            "systemd-creds：TPM2 + 主机密钥双重封存（不绑定 PCR）".into()
        } else {
            "systemd-creds：主机密钥封存（/var/lib/systemd/credential.secret，仅 root 可读）".into()
        }
    }

    fn is_provisioned(&self) -> bool {
        self.cred_path.exists()
    }

    fn seal(&self, key: &[u8; 32], _rand: RandFn) -> io::Result<()> {
        encrypt_to(&self.cred_path, key, self.tpm)
    }

    fn unseal(&self) -> io::Result<Zeroizing<[u8; 32]>> {
        // 服务器模式：service-prepare 交来的明文，读后立即删除。
        if let Ok(mut f) = fs::File::open(&self.handoff) {
            let mut data = Zeroizing::new(Vec::with_capacity(32));
            f.read_to_end(&mut data)?;
            let _ = fs::remove_file(&self.handoff);
            return key_from_bytes(&data);
        }
        // 单机模式：由 systemd 通过 LoadCredentialEncrypted= 解密后提供。
        if let Some(dir) = std::env::var_os("CREDENTIALS_DIRECTORY") {
            let p = PathBuf::from(dir).join(CRED_NAME);
            if p.exists() {
                let data = Zeroizing::new(fs::read(p)?);
                return key_from_bytes(&data);
            }
        }
        // 兜底（仅 root）。
        decrypt_from(&self.cred_path)
    }

    fn remove(&self) -> io::Result<()> {
        match fs::remove_file(&self.cred_path) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            r => r,
        }
    }
}

/// 测试替身（其他 crate 的测试通过 `test-hooks` 特性使用）。
#[cfg(any(test, feature = "test-hooks"))]
pub mod testing {
    use std::path::{Path, PathBuf};

    /// 在 `path` 创建一个"没有人监听"的 Unix 套接字文件（ECONNREFUSED）。由一个短命的子进程绑定后退出，
    /// 本进程从不持有监听的文件描述符——否则并发测试 fork 出的子进程在 exec 之前会短暂持有它，
    /// 使套接字在本进程关闭之后仍然接受连接（测试因此不稳定）。
    pub fn stale_socket(path: &Path) {
        let _ = std::fs::remove_file(path);
        let st = std::process::Command::new("python3")
            .args(["-I", "-c", "import socket,sys; s=socket.socket(socket.AF_UNIX); s.bind(sys.argv[1]); s.close()"])
            .arg(path)
            .status()
            .expect("python3");
        assert!(st.success(), "创建套接字文件失败");
    }

    /// 写一个假的 systemd-creds（Python）：
    /// - encrypt：输出 base64(凭据类型 ID ‖ 明文)，ID 与真实 systemd 相同；
    /// - 涉及 TPM（host+tpm2 加密，或解密 host+tpm2 凭据）时：`FAKE_FAIL_TPM=1` 模拟没有 TPM；
    ///   设置了 `FAKE_EXPECT_TPM2_DEVICE` 时，`SYSTEMD_TPM2_DEVICE` 必须等于它（模拟 swtpm：不带环境变量就解不开）；
    /// - `FAKE_WRONG_KIND=1`：不管要求什么都输出 host 凭据（模拟悄悄退回）；
    /// - `FAKE_LOG`：每次调用追加一行 `<命令> <SYSTEMD_TPM2_DEVICE 或 ->`；
    /// - has-tpm2 返回 11（与套接字模式下的真实行为一致）。
    pub fn fake_creds(dir: &Path) -> PathBuf {
        let p = dir.join("fake-systemd-creds");
        std::fs::write(
            &p,
            r#"#!/usr/bin/python3 -I
import base64, os, sys
ID_HOST = bytes.fromhex("5a1c6a86df9d4096b1d5a65e0862f19a")
ID_HOST_TPM2 = bytes.fromhex("93a894094874449090caf2fc93cab553")
args = sys.argv[1:]
cmd = args[0] if args else ""
log = os.environ.get("FAKE_LOG")
if log:
    with open(log, "a") as f:
        f.write("%s %s\n" % (cmd, os.environ.get("SYSTEMD_TPM2_DEVICE", "-")))
def tpm_ok():
    if os.environ.get("FAKE_FAIL_TPM") == "1":
        sys.stderr.write("No TPM2 device found\n"); return False
    exp = os.environ.get("FAKE_EXPECT_TPM2_DEVICE")
    if exp is not None and os.environ.get("SYSTEMD_TPM2_DEVICE") != exp:
        sys.stderr.write("TPM2 device not accessible\n"); return False
    return True
if cmd == "--version":
    print("systemd 257 (257.9-1~deb13u1)"); sys.exit(0)
if cmd == "has-tpm2":
    sys.exit(11)
pos = [a for a in args[1:] if not a.startswith("--") and a != "-"]
if cmd == "encrypt":
    key = [a.split("=", 1)[1] for a in args if a.startswith("--with-key=")][0]
    data = sys.stdin.buffer.read()
    tpm = "tpm2" in key
    if tpm and not tpm_ok():
        sys.exit(1)
    ident = ID_HOST_TPM2 if tpm and os.environ.get("FAKE_WRONG_KIND") != "1" else ID_HOST
    with open(pos[-1], "wb") as f:
        f.write(base64.b64encode(ident + data) + b"\n")
    sys.exit(0)
if cmd == "decrypt":
    try:
        raw = base64.b64decode(open(pos[0], "rb").read())
    except Exception:
        sys.stderr.write("Failed to decrypt\n"); sys.exit(1)
    if raw[:16] == ID_HOST_TPM2:
        if not tpm_ok():
            sys.exit(1)
    elif raw[:16] != ID_HOST:
        sys.stderr.write("Failed to decrypt\n"); sys.exit(1)
    sys.stdout.buffer.write(raw[16:]); sys.exit(0)
sys.exit(2)
"#,
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 只有 root 才会给 systemd-creds 补 tss 组（普通用户无权 setgroups，也不需要）。
    #[test]
    fn tss_group_only_added_for_root() {
        if !nix::unistd::geteuid().is_root() {
            assert!(groups_with_tss().is_none());
        } else if let Some(g) = groups_with_tss() {
            let tss = nix::unistd::Group::from_name("tss").unwrap().unwrap().gid.as_raw();
            assert!(g.contains(&tss));
        }
    }

    #[test]
    fn version_and_credential_kinds() {
        assert_eq!(parse_version("systemd 257 (257.9-1~deb13u1)\n+PAM +AUDIT"), Some(257));
        assert_eq!(parse_version("systemd 252 (252.39-1~deb12u1)"), Some(252));
        assert_eq!(parse_version("garbage"), None);
        assert_eq!((with_key(true), with_key(false)), ("host+tpm2", "host"));
        use base64::Engine;
        let b64 = |id: [u8; 16]| {
            let mut v = id.to_vec();
            v.extend_from_slice(&[1u8; 40]);
            base64::engine::general_purpose::STANDARD.encode(v)
        };
        assert_eq!(cred_kind(b64(ID_HOST).as_bytes()), CredKind::Host);
        assert_eq!(cred_kind(b64(ID_HOST_TPM2).as_bytes()), CredKind::HostTpm2);
        assert_eq!(cred_kind(b64(ID_HOST_TPM2_PK).as_bytes()), CredKind::HostTpm2);
        assert_eq!(cred_kind(b64(ID_TPM2).as_bytes()), CredKind::Tpm2);
        assert_eq!(cred_kind(b64(ID_NULL).as_bytes()), CredKind::Null);
        // 换行折行的 base64 与原始二进制都能识别。
        let wrapped: String =
            b64(ID_HOST_TPM2).chars().enumerate().flat_map(|(i, c)| if i % 20 == 19 { vec![c, '\n'] } else { vec![c] }).collect();
        assert_eq!(cred_kind(wrapped.as_bytes()), CredKind::HostTpm2);
        let mut raw = ID_HOST.to_vec();
        raw.extend_from_slice(&[0xffu8; 10]);
        assert_eq!(cred_kind(&raw), CredKind::Host);
        assert_eq!(cred_kind(b""), CredKind::Other);
        assert_eq!(cred_kind(b"junk"), CredKind::Other);
        assert_eq!(cred_kind(&[0u8; 32]), CredKind::Other);
    }

    /// 环境变量是进程级的，所以依赖它们的步骤都放在这一个测试里顺序执行：
    /// TPM 发现的优先级、开机等待（超时与稍后出现）、封存/解封/交接文件、
    /// 套接字模式下每次调用都带 SYSTEMD_TPM2_DEVICE、文件头检查。
    #[test]
    fn discovery_wait_seal_and_swtpm_env_with_fake_systemd_creds() {
        let dir = tempfile::tempdir().unwrap();
        let fake = testing::fake_creds(dir.path());
        let sock = dir.path().join("swtpm/tpm.sock");
        let dev = dir.path().join("tpmrm0");
        let log = dir.path().join("calls.log");
        // SAFETY: 测试进程内设置环境变量（只有本测试使用这些变量）。
        unsafe {
            std::env::set_var("PASSMANAGER_SYSTEMD_CREDS", &fake);
            std::env::set_var("PASSMANAGER_TPM_SOCKET", &sock);
            std::env::set_var("PASSMANAGER_TPM_DEVICE", &dev);
            std::env::set_var("FAKE_LOG", &log);
        }
        // ---- 发现与等待 ----
        assert_eq!(discover_tpm(), None);
        assert!(tpm2_device_env().is_none());
        let t0 = Instant::now();
        let missing = wait_for_tpm(Duration::from_millis(300), Duration::from_millis(50)).unwrap_err();
        assert_eq!(missing.socket.as_ref().map(|s| &s.1), Some(&SocketState::NotFound), "超时返回诊断");
        assert!(missing.describe().contains("ENOENT"));
        assert!(t0.elapsed() >= Duration::from_millis(300) && t0.elapsed() < Duration::from_secs(5));
        std::fs::write(&dev, b"").unwrap();
        assert_eq!(discover_tpm(), Some(TpmPath::Device(dev.clone())));
        assert!(tpm2_device_env().is_none(), "设备模式不设置 SYSTEMD_TPM2_DEVICE");
        // 套接字稍后才出现：等待期间发现，并且优先于设备。
        std::fs::create_dir_all(sock.parent().unwrap()).unwrap();
        let s2 = sock.clone();
        let binder = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(200));
            std::os::unix::net::UnixListener::bind(&s2).unwrap()
        });
        std::fs::remove_file(&dev).unwrap();
        let found = wait_for_tpm(Duration::from_secs(5), Duration::from_millis(20));
        let _listener = binder.join().unwrap();
        assert_eq!(found, Ok(TpmPath::Socket(sock.clone())));
        std::fs::write(&dev, b"").unwrap();
        assert_eq!(discover_tpm(), Some(TpmPath::Socket(sock.clone())), "套接字优先于设备");
        let env = format!("swtpm:path={}", sock.display());
        assert_eq!(tpm2_device_env().as_deref(), Some(env.as_str()));
        // 普通文件冒充套接字：不算。
        let fake_sock = dir.path().join("not-a-socket");
        std::fs::write(&fake_sock, b"").unwrap();
        unsafe { std::env::set_var("PASSMANAGER_TPM_SOCKET", &fake_sock) };
        assert_eq!(discover_tpm(), Some(TpmPath::Device(dev.clone())));
        // 配置的路径（install.json）在没有环境变量时生效；都没有配置时只检测设备。
        unsafe { std::env::remove_var("PASSMANAGER_TPM_SOCKET") };
        set_tpm_socket(None);
        assert_eq!(discover_tpm(), Some(TpmPath::Device(dev.clone())), "没有配置套接字时不猜测路径");
        set_tpm_socket(Some(sock.clone()));
        assert_eq!(discover_tpm(), Some(TpmPath::Socket(sock.clone())));
        unsafe { std::env::set_var("PASSMANAGER_TPM_SOCKET", &sock) };
        set_tpm_socket(None);

        // ---- 封存（套接字模式：模拟 swtpm，不带正确的环境变量就无法使用 TPM）----
        unsafe { std::env::set_var("FAKE_EXPECT_TPM2_DEVICE", &env) };
        let layout = Layout {
            mode: crate::Mode::User,
            data_dir: dir.path().join("data"),
            run_dir: dir.path().join("run"),
            socket: dir.path().join("run/s"),
        };
        let mut rand = |b: &mut [u8]| {
            b.fill(7);
            Ok(())
        };
        assert!(tpm_usable(&mut rand), "套接字模式下试加解密成功");
        let t = SystemdCredsSealer::new(true, &layout);
        assert_eq!((t.method(), t.level()), (METHOD_TPM, 3));
        let key = [0x41u8; 32];
        t.seal(&key, &mut rand).unwrap();
        assert_eq!(cred_file_kind(t.cred_path()).unwrap(), CredKind::HostTpm2);
        assert!(!dir.path().join("data/device-key.cred.tmp").exists());
        assert_eq!(*t.unseal().unwrap(), key);
        let calls = std::fs::read_to_string(&log).unwrap();
        assert!(
            calls.lines().filter(|l| l.starts_with("encrypt") || l.starts_with("decrypt")).all(|l| l.ends_with(&env)),
            "每次调用都带 SYSTEMD_TPM2_DEVICE：\n{calls}"
        );
        // 套接字消失：解密 host+tpm2 凭据失败（与真实 swtpm 环境里不带环境变量时的表现一致）。
        drop(_listener);
        std::fs::remove_file(&sock).unwrap();
        std::fs::remove_file(&dev).unwrap();
        assert!(t.unseal().is_err());
        assert!(!tpm_usable(&mut rand));
        // L2（host）不依赖 TPM。
        let h = SystemdCredsSealer::new(false, &layout);
        assert_eq!((h.method(), h.level()), (METHOD_HOST, 2));
        h.seal(&key, &mut rand).unwrap();
        assert_eq!(cred_file_kind(h.cred_path()).unwrap(), CredKind::Host);
        assert_eq!(*h.unseal().unwrap(), key);
        // 交接文件：优先使用，读后删除；长度不对时报错。
        std::fs::create_dir_all(layout.key_handoff_dir()).unwrap();
        std::fs::write(layout.key_handoff_path(), [0x42u8; 32]).unwrap();
        assert_eq!(*h.unseal().unwrap(), [0x42u8; 32]);
        assert!(!layout.key_handoff_path().exists());
        assert_eq!(*h.unseal().unwrap(), key, "交接文件已删除，回到兜底解密");
        std::fs::write(layout.key_handoff_path(), [1u8; 5]).unwrap();
        assert!(h.unseal().is_err());
        // 文件头检查：要求 host+tpm2 却得到 host 凭据（悄悄退回）→ 拒绝，原文件不变。
        std::fs::write(&dev, b"").unwrap();
        unsafe {
            std::env::remove_var("FAKE_EXPECT_TPM2_DEVICE");
            std::env::set_var("FAKE_WRONG_KIND", "1");
        }
        let before = std::fs::read(h.cred_path()).unwrap();
        assert!(encrypt_to(h.cred_path(), &key, true).is_err());
        assert_eq!(std::fs::read(h.cred_path()).unwrap(), before);
        assert!(!tpm_usable(&mut rand));
        unsafe { std::env::remove_var("FAKE_WRONG_KIND") };
        // 密文损坏：解密失败。
        std::fs::write(h.cred_path(), b"junk").unwrap();
        assert!(h.unseal().is_err());
        unsafe {
            for k in ["PASSMANAGER_SYSTEMD_CREDS", "PASSMANAGER_TPM_SOCKET", "PASSMANAGER_TPM_DEVICE", "FAKE_LOG"] {
                std::env::remove_var(k);
            }
        }
    }

    /// 模拟：root、没有附加组（ExecStartPre=+），套接字 nobody:tss 0660，目录 nobody:tss 0750。
    struct FakeOps {
        root: bool,
        groups: Vec<u32>,
        log: Vec<String>,
        tss: Option<u32>,
    }

    const TSS: u32 = 107;
    const SOCK_DIR: &str = "/run/swtpm-test";
    const SOCK: &str = "/run/swtpm-test/tpm.sock";

    impl GroupOps for FakeOps {
        fn is_root(&self) -> bool {
            self.root
        }
        fn groups(&self) -> Vec<u32> {
            self.groups.clone()
        }
        fn egid(&self) -> u32 {
            0
        }
        fn set_groups(&mut self, g: &[u32]) -> io::Result<()> {
            self.log.push(format!("setgroups {g:?}"));
            self.groups = g.to_vec();
            Ok(())
        }
        fn stat(&self, p: &Path) -> io::Result<(u32, u32)> {
            self.log_stat(p)
        }
        fn tss_gid(&self) -> Option<u32> {
            self.tss
        }
    }

    impl FakeOps {
        fn log_stat(&self, p: &Path) -> io::Result<(u32, u32)> {
            // 目录只对 tss 组可进入：不在组里时连套接字都 stat 不到（EACCES）。
            if p == Path::new(SOCK_DIR) {
                return Ok((0o040750, TSS));
            }
            if p == Path::new(SOCK) {
                if !self.groups.contains(&TSS) {
                    return Err(io::Error::from_raw_os_error(libc::EACCES));
                }
                return Ok((0o140660, TSS));
            }
            Err(io::Error::from_raw_os_error(libc::ENOENT))
        }
    }

    #[test]
    fn group_only_permission_bits() {
        assert!(group_only(0o040750, true) && !group_only(0o040755, true) && !group_only(0o040700, true));
        assert!(group_only(0o140660, false) && group_only(0o140664, false) && !group_only(0o140666, false) && !group_only(0o140600, false));
    }

    /// 加入组发生在访问之前：没有附加组的 root 先加入目录与套接字的组，之后才能 stat 套接字；
    /// 已经在组里时不重复；非 root 不做任何事；对其他人开放的路径不需要加组。
    #[test]
    fn root_joins_socket_groups_before_access() {
        let mut ops = FakeOps { root: true, groups: vec![], log: vec![], tss: None };
        assert!(ops.stat(Path::new(SOCK)).is_err(), "加入组之前：EACCES");
        let added = join_groups_for(&mut ops, Path::new(SOCK)).unwrap();
        assert_eq!(added, vec![TSS]);
        assert_eq!(ops.groups, vec![TSS]);
        assert!(ops.stat(Path::new(SOCK)).is_ok(), "加入组之后可以访问");
        assert!(join_groups_for(&mut ops, Path::new(SOCK)).unwrap().is_empty(), "不重复加入");
        // tss 组存在时也加入（设备与兜底），保留原有附加组。
        let mut ops = FakeOps { root: true, groups: vec![4], log: vec![], tss: Some(TSS) };
        assert_eq!(join_groups_for(&mut ops, Path::new("/nonexistent/tpmrm0")).unwrap(), vec![TSS]);
        assert_eq!(ops.groups, vec![4, TSS]);
        // 非 root：不调用 setgroups。
        let mut ops = FakeOps { root: false, groups: vec![], log: vec![], tss: Some(TSS) };
        assert!(join_groups_for(&mut ops, Path::new(SOCK)).unwrap().is_empty());
        assert!(ops.log.is_empty());
    }

    /// 真实文件系统上的诊断：ENOENT、EACCES（目录不可进入 / 套接字不可写）、ECONNREFUSED、不是套接字、可用，
    /// 彼此区分（以非 root 运行；root 有 DAC 豁免时跳过权限部分）。
    #[test]
    fn socket_states_are_distinguished() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("tpm.sock");
        assert_eq!(socket_state(&p), SocketState::NotFound);
        assert!(SocketState::NotFound.describe(&p).contains("ENOENT"));
        let l = std::os::unix::net::UnixListener::bind(&p).unwrap();
        assert_eq!(socket_state(&p), SocketState::Ready);
        drop(l);
        // 换成从未在本进程中监听过的套接字文件（见 testing::stale_socket 的说明）。
        testing::stale_socket(&p);
        assert_eq!(socket_state(&p), SocketState::Refused, "文件还在但没有人监听");
        assert!(SocketState::Refused.describe(&p).contains("ECONNREFUSED"));
        let f = d.path().join("plain");
        std::fs::write(&f, b"").unwrap();
        assert_eq!(socket_state(&f), SocketState::NotSocket);
        if !nix::unistd::geteuid().is_root() {
            let sub = d.path().join("locked");
            std::fs::create_dir(&sub).unwrap();
            let s2 = sub.join("tpm.sock");
            let _l2 = std::os::unix::net::UnixListener::bind(&s2).unwrap();
            std::fs::set_permissions(&s2, std::fs::Permissions::from_mode(0o000)).unwrap();
            assert!(matches!(socket_state(&s2), SocketState::PermissionDenied(ref e) if e.starts_with("connect")), "套接字不可写");
            std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o000)).unwrap();
            let st = socket_state(&s2);
            assert!(matches!(st, SocketState::PermissionDenied(ref e) if e.starts_with("stat")), "目录不可进入：{st:?}");
            let msg = st.describe(&s2);
            assert!(msg.contains("EACCES") && msg.contains("没有权限") && !msg.contains("不存在"), "{msg}");
            let m = TpmMissing { socket: Some((s2.clone(), st)), device: "/nonexistent/tpmrm0".into() };
            assert!(m.permission_denied() && m.describe().contains("EACCES"));
            std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
    }
}
