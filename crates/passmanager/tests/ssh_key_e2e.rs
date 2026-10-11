//! SSH 私钥条目端到端（真实服务进程，Linux）：
//! - `import --kind ssh-key`（ECDSA P-384，ssh-keygen 生成的一次性测试密钥）只打印公钥指纹；
//! - 公钥认证：服务端只提供 mlkem768x25519-sha256 时成功；只提供 ecdh-sha2-nistp384（旧主机）时也成功；
//!   主机密钥、公钥认证都是 ecdsa-sha2-nistp384，加密 aes256-gcm@openssh.com，MAC hmac-sha2-512-etm；
//! - 私钥条目的 sudo 命令原样执行，口令条目仍然由服务注入 sudo 口令；错误的密钥被拒绝；主机密钥更换被拒绝；
//! - 输出与下载内容脱敏；scp 上传 / 下载；加密的私钥与非私钥内容在导入时被拒绝；
//! - 有系统 OpenSSH 时，用加固配置（AuthenticationMethods publickey 等）的真实 sshd 再验证一次。
#![cfg(target_os = "linux")]

mod common;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::*;

fn keygen(dir: &Path, name: &str, passphrase: &str) -> (PathBuf, String) {
    let p = dir.join(name);
    let o = Command::new("ssh-keygen")
        .args(["-q", "-t", "ecdsa", "-b", "384", "-N", passphrase, "-C", "pm-test", "-f"])
        .arg(&p)
        .output()
        .unwrap();
    assert!(o.status.success(), "ssh-keygen: {}", String::from_utf8_lossy(&o.stderr));
    let fp = String::from_utf8_lossy(&Command::new("ssh-keygen").arg("-lf").arg(&p).output().unwrap().stdout)
        .split_whitespace()
        .nth(1)
        .unwrap()
        .to_string();
    (p, fp)
}

fn have(cmd: &str) -> bool {
    Command::new("sh").args(["-c", &format!("command -v {cmd}")]).output().is_ok_and(|o| o.status.success())
}

mod sftpd {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use russh_sftp::protocol::{Attrs, Data, FileAttributes, Handle, OpenFlags, Status, StatusCode};

    pub type Files = Arc<Mutex<HashMap<String, Vec<u8>>>>;
    pub struct S(pub Files);

    fn ok(id: u32) -> Status {
        Status { id, status_code: StatusCode::Ok, error_message: "Ok".into(), language_tag: "en-US".into() }
    }

    impl russh_sftp::server::Handler for S {
        type Error = StatusCode;
        fn unimplemented(&self) -> Self::Error {
            StatusCode::OpUnsupported
        }
        async fn open(&mut self, id: u32, filename: String, pflags: OpenFlags, _a: FileAttributes) -> Result<Handle, Self::Error> {
            let mut f = self.0.lock().unwrap();
            if pflags.contains(OpenFlags::CREATE) && (pflags.contains(OpenFlags::TRUNCATE) || !f.contains_key(&filename)) {
                f.insert(filename.clone(), Vec::new());
            }
            if !f.contains_key(&filename) {
                return Err(StatusCode::NoSuchFile);
            }
            Ok(Handle { id, handle: filename })
        }
        async fn close(&mut self, id: u32, _h: String) -> Result<Status, Self::Error> {
            Ok(ok(id))
        }
        async fn read(&mut self, id: u32, handle: String, offset: u64, len: u32) -> Result<Data, Self::Error> {
            let f = self.0.lock().unwrap();
            let d = f.get(&handle).ok_or(StatusCode::NoSuchFile)?;
            let off = offset as usize;
            if off >= d.len() {
                return Err(StatusCode::Eof);
            }
            Ok(Data { id, data: d[off..(off + len as usize).min(d.len())].to_vec() })
        }
        async fn write(&mut self, id: u32, handle: String, offset: u64, data: Vec<u8>) -> Result<Status, Self::Error> {
            let mut f = self.0.lock().unwrap();
            let d = f.get_mut(&handle).ok_or(StatusCode::NoSuchFile)?;
            let off = offset as usize;
            if d.len() < off + data.len() {
                d.resize(off + data.len(), 0);
            }
            d[off..off + data.len()].copy_from_slice(&data);
            Ok(ok(id))
        }
        async fn stat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
            let f = self.0.lock().unwrap();
            let d = f.get(&path).ok_or(StatusCode::NoSuchFile)?;
            Ok(Attrs { id, attrs: FileAttributes { size: Some(d.len() as u64), ..Default::default() } })
        }
        async fn lstat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
            self.stat(id, path).await
        }
        async fn fstat(&mut self, id: u32, handle: String) -> Result<Attrs, Self::Error> {
            self.stat(id, handle).await
        }
    }
}

/// russh 测试服务器：加固配置（只允许指定的密钥交换、P-384 主机密钥、aes256-gcm、hmac-sha2-512-etm）。
struct H {
    files: sftpd::Files,
    channels: HashMap<russh::ChannelId, russh::Channel<russh::server::Msg>>,
    allowed: Option<russh::keys::PublicKey>,
    password: Option<String>,
    leak: String,
    /// 认证尝试的记录（方法名），用于检查先私钥、后口令的顺序。
    attempts: Arc<Mutex<Vec<String>>>,
}

impl russh::server::Handler for H {
    type Error = russh::Error;

    async fn auth_publickey_offered(&mut self, _u: &str, k: &russh::keys::PublicKey) -> Result<russh::server::Auth, Self::Error> {
        self.attempts.lock().unwrap().push("publickey".into());
        Ok(if self.allowed.as_ref().is_some_and(|a| a.key_data() == k.key_data()) {
            russh::server::Auth::Accept
        } else {
            russh::server::Auth::reject()
        })
    }
    async fn auth_publickey(&mut self, _u: &str, k: &russh::keys::PublicKey) -> Result<russh::server::Auth, Self::Error> {
        Ok(if self.allowed.as_ref().is_some_and(|a| a.key_data() == k.key_data()) {
            russh::server::Auth::Accept
        } else {
            russh::server::Auth::reject()
        })
    }
    async fn auth_password(&mut self, u: &str, p: &str) -> Result<russh::server::Auth, Self::Error> {
        self.attempts.lock().unwrap().push("password".into());
        Ok(if u == "deploy" && self.password.as_deref() == Some(p) { russh::server::Auth::Accept } else { russh::server::Auth::reject() })
    }
    async fn channel_open_session(
        &mut self,
        channel: russh::Channel<russh::server::Msg>,
        reply: russh::server::ChannelOpenHandle,
        _s: &mut russh::server::Session,
    ) -> Result<(), Self::Error> {
        self.channels.insert(channel.id(), channel);
        reply.accept().await;
        Ok(())
    }
    async fn subsystem_request(
        &mut self,
        channel: russh::ChannelId,
        name: &str,
        session: &mut russh::server::Session,
    ) -> Result<(), Self::Error> {
        if name == "sftp"
            && let Some(ch) = self.channels.remove(&channel)
        {
            session.channel_success(channel)?;
            tokio::spawn(russh_sftp::server::run(ch.into_stream(), sftpd::S(self.files.clone())));
            return Ok(());
        }
        session.channel_failure(channel)?;
        Ok(())
    }
    async fn exec_request(
        &mut self,
        channel: russh::ChannelId,
        data: &[u8],
        session: &mut russh::server::Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        let out = format!("ran: {}\nleak: {}\n", String::from_utf8_lossy(data), self.leak);
        session.data(channel, out.into_bytes())?;
        session.exit_status_request(channel, 3)?;
        session.eof(channel)?;
        session.close(channel)?;
        Ok(())
    }
}

struct Srv {
    port: u16,
    task: tokio::task::JoinHandle<()>,
}

fn serve(
    rt: &tokio::runtime::Runtime,
    port: u16,
    host_key: &Path,
    kex: Vec<russh::kex::Name>,
    mk: impl Fn() -> H + Send + Sync + 'static,
) -> Srv {
    serve_with(rt, port, host_key, kex, &[russh::MethodKind::PublicKey, russh::MethodKind::Password], mk)
}

fn serve_with(
    rt: &tokio::runtime::Runtime,
    port: u16,
    host_key: &Path,
    kex: Vec<russh::kex::Name>,
    methods: &[russh::MethodKind],
    mk: impl Fn() -> H + Send + Sync + 'static,
) -> Srv {
    use russh::keys::ssh_key::{Algorithm, EcdsaCurve};
    use std::borrow::Cow;
    let key = russh::keys::decode_secret_key(&std::fs::read_to_string(host_key).unwrap(), None).unwrap();
    let mut preferred = russh::Preferred::DEFAULT.clone();
    let mut k = kex;
    k.extend([russh::kex::EXTENSION_SUPPORT_AS_SERVER, russh::kex::EXTENSION_OPENSSH_STRICT_KEX_AS_SERVER]);
    preferred.kex = Cow::Owned(k);
    preferred.key = Cow::Owned(vec![Algorithm::Ecdsa { curve: EcdsaCurve::NistP384 }]);
    preferred.cipher = Cow::Owned(vec![russh::cipher::AES_256_GCM]);
    preferred.mac = Cow::Owned(vec![russh::mac::HMAC_SHA512_ETM]);
    let cfg = Arc::new(russh::server::Config {
        keys: vec![key],
        preferred,
        methods: russh::MethodSet::from(methods),
        auth_rejection_time: Duration::from_millis(10),
        auth_rejection_time_initial: Some(Duration::from_millis(0)),
        ..Default::default()
    });
    let l = rt.block_on(tokio::net::TcpListener::bind(("127.0.0.1", port))).unwrap();
    let port = l.local_addr().unwrap().port();
    let mk = Arc::new(mk);
    let task = rt.spawn(async move {
        loop {
            let Ok((s, _)) = l.accept().await else { break };
            let (cfg, mk) = (cfg.clone(), mk.clone());
            tokio::spawn(async move {
                if let Ok(r) = russh::server::run_stream(cfg, s, mk()).await {
                    let _ = r.await;
                }
            });
        }
    });
    Srv { port, task }
}

fn ssh(env: &Env, target: &str, cmd: &str) -> (bool, serde_json::Value, String) {
    let o = env.agent(&["ssh", target, cmd]);
    let out = stdout(&o);
    (o.status.success(), serde_json::from_str(&out).unwrap_or(serde_json::Value::Null), out + &stderr(&o))
}

#[test]
fn ssh_key_auth_end_to_end() {
    if !have("ssh-keygen") {
        eprintln!("跳过：没有 ssh-keygen");
        return;
    }
    let env = Env::setup("sshkey");
    let kd = env.base.join("keys");
    std::fs::create_dir_all(&kd).unwrap();
    let (host1, _) = keygen(&kd, "host1", "");
    let (host2, _) = keygen(&kd, "host2", "");
    let (good, good_fp) = keygen(&kd, "client", "");
    let (bad, _) = keygen(&kd, "other", "");
    let (enc, _) = keygen(&kd, "encrypted", "passphrase-123");
    let good_pem = std::fs::read_to_string(&good).unwrap();
    let key_line = good_pem.lines().nth(1).unwrap().to_string();
    let good_pub = russh::keys::decode_secret_key(&good_pem, None).unwrap().public_key().clone();
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
    let files: sftpd::Files = Default::default();
    files.lock().unwrap().insert("/etc/app.conf".into(), format!("key={key_line}\n").into_bytes());
    let mk = {
        let (files, good_pub, leak) = (files.clone(), good_pub.clone(), key_line.clone());
        move || H {
            files: files.clone(),
            channels: HashMap::new(),
            allowed: Some(good_pub.clone()),
            password: None,
            leak: leak.clone(),
            attempts: Default::default(),
        }
    };
    // A：只提供 mlkem768x25519-sha256；B：只提供 ecdh-sha2-nistp384（旧主机的回退）；C：口令认证。
    let a = serve(&rt, 0, &host1, vec![russh::kex::MLKEM768X25519_SHA256], mk.clone());
    let b = serve(&rt, 0, &host1, vec![russh::kex::ECDH_SHA2_NISTP384], mk.clone());
    let c = {
        let files = files.clone();
        serve(&rt, 0, &host1, vec![russh::kex::MLKEM768X25519_SHA256, russh::kex::ECDH_SHA2_NISTP384], move || H {
            files: files.clone(),
            channels: HashMap::new(),
            allowed: None,
            password: Some("PwEntry-123!".into()),
            leak: "PwEntry-123!".into(),
            attempts: Default::default(),
        })
    };
    let mut outputs = String::new();

    // ---- 导入：只打印公钥指纹 ----
    let (da, db, dc) = (format!("localhost:{}", a.port), format!("localhost:{}", b.port), format!("localhost:{}", c.port));
    let o = env.run_stdin(&["import", "--name", "adminkey", "--kind", "ssh-key", "--domain", &da, "--domain", &db], good_pem.as_bytes());
    assert!(o.status.success(), "{}", stderr(&o));
    assert!(stdout(&o).contains(&format!("公钥指纹：ecdsa-sha2-nistp384 {good_fp}")), "{}", stdout(&o));
    outputs += &(stdout(&o) + &stderr(&o));
    // 加密的私钥、不是私钥的内容：拒绝。
    let o = env.run_stdin(&["import", "--name", "enc", "--kind", "ssh-key", "--domain", &da], &std::fs::read(&enc).unwrap());
    assert!(!o.status.success() && stderr(&o).contains("加密"), "{}", stderr(&o));
    let o = env.run_stdin(&["import", "--name", "notkey", "--kind", "ssh-key", "--domain", &da], b"just-a-password\n");
    assert!(!o.status.success(), "{}", stdout(&o));

    // ---- 公钥认证：mlkem768x25519 与 nistp384 两种主机 ----
    for port in [a.port, b.port] {
        let (ok, v, out) = ssh(&env, &format!("deploy@localhost:{port}"), "uptime");
        assert!(ok, "{out}");
        assert_eq!(v["exit_code"], 3);
        assert!(v["stdout"].as_str().unwrap().contains("ran: uptime"));
        assert!(v["stdout"].as_str().unwrap().contains("leak: [REDACTED:adminkey]"), "{out}");
        outputs += &out;
    }
    // 私钥条目的 sudo：原样执行，不注入口令。
    let (ok, v, out) = ssh(&env, &format!("deploy@localhost:{}", a.port), "sudo systemctl restart x");
    assert!(ok && v["stdout"].as_str().unwrap().contains("ran: sudo systemctl restart x"), "{out}");
    outputs += &out;

    // ---- scp：上传、下载（下载内容脱敏） ----
    let local = env.base.join("upload.txt");
    std::fs::write(&local, b"uploaded-by-key").unwrap();
    let o = env.agent(&["scp", local.to_str().unwrap(), &format!("deploy@localhost:{}:/tmp/u.txt", a.port)]);
    assert!(o.status.success(), "{}", stdout(&o));
    assert_eq!(files.lock().unwrap().get("/tmp/u.txt").unwrap().as_slice(), b"uploaded-by-key");
    let dl = env.base.join("download.txt");
    let o = env.agent(&["scp", &format!("deploy@localhost:{}:/etc/app.conf", a.port), dl.to_str().unwrap()]);
    assert!(o.status.success(), "{}", stdout(&o));
    let content = std::fs::read_to_string(&dl).unwrap();
    assert!(content.contains("key=[REDACTED:adminkey]") && !content.contains(&key_line), "{content}");

    // ---- 口令条目：仍然可用，sudo 注入口令 ----
    let o = env.run_stdin(&["import", "--name", "pwentry", "--domain", &dc], b"PwEntry-123!\n");
    assert!(o.status.success(), "{}", stderr(&o));
    let (ok, v, out) = ssh(&env, &format!("deploy@localhost:{}", c.port), "sudo id");
    assert!(ok && v["stdout"].as_str().unwrap().contains("ran: sudo -k -S -p '' -- sh -c 'id'"), "{out}");
    assert!(v["stdout"].as_str().unwrap().contains("leak: [REDACTED:pwentry]"), "{out}");
    outputs += &out;

    // ---- 多字段条目：登录用 password 字段，命令里的 {{条目.字段}} / {{字段}} 代入，输出中每个字段都脱敏 ----
    let o = env.run_stdin(
        &["import", "--name", "fentry", "--fields", "username,password", "--domain", &dc, "--replace"],
        b"field-user-77\r\nPwEntry-123!\r\n",
    );
    assert!(o.status.success(), "{}", stderr(&o));
    // pwentry 与 fentry 都匹配 C：按引用名指定凭据。
    let (ok, v, out) = ssh(&env, &format!("fentry/deploy@localhost:{}", c.port), "login {{fentry.username}} {{password}}");
    assert!(ok, "{out}");
    let so = v["stdout"].as_str().unwrap();
    assert!(so.contains("ran: login [REDACTED:fentry.username] [REDACTED:"), "{so}");
    assert!(!so.contains("field-user-77") && !so.contains("PwEntry-123!"));
    let (ok, v, out) = ssh(&env, &format!("fentry/deploy@localhost:{}", c.port), "sudo id");
    assert!(ok && v["stdout"].as_str().unwrap().contains("ran: sudo -k -S -p '' -- sh -c 'id'"), "sudo 用 password 字段：{out}");
    let (ok, _, out) = ssh(&env, &format!("fentry/deploy@localhost:{}", c.port), "echo {{fentry.pin}}");
    assert!(!ok && out.contains("UNKNOWN_FIELD") && !out.contains("username"), "{out}");
    outputs += &out;

    // ---- 错误的密钥：拒绝 ----
    let o = env.run_stdin(
        &["import", "--name", "adminkey", "--kind", "ssh-key", "--domain", &da, "--domain", &db, "--replace"],
        &std::fs::read(&bad).unwrap(),
    );
    assert!(o.status.success());
    let (ok, _, out) = ssh(&env, &format!("deploy@localhost:{}", a.port), "uptime");
    assert!(!ok && out.contains("AUTH_REJECTED"), "{out}");
    let o = env.run_stdin(
        &["import", "--name", "adminkey", "--kind", "ssh-key", "--domain", &da, "--domain", &db, "--replace"],
        good_pem.as_bytes(),
    );
    assert!(o.status.success());

    // ---- 主机密钥更换：拒绝（不发送认证数据） ----
    a.task.abort();
    std::thread::sleep(Duration::from_millis(200));
    let a2 = serve(&rt, a.port, &host2, vec![russh::kex::MLKEM768X25519_SHA256], mk.clone());
    let (ok, _, out) = ssh(&env, &format!("deploy@localhost:{}", a2.port), "uptime");
    assert!(!ok && out.contains("HOST_KEY_CHANGED"), "{out}");

    outputs += &env.service_log();
    let bad_leaks = leaks(&outputs, &[&good_pem, "PwEntry-123!", "field-user-77"]);
    assert!(bad_leaks.is_empty(), "{bad_leaks:?}");
    drop((b, c, a2));
}

/// 同一主机同时匹配私钥条目与"初始口令"条目（通配符 / 网段绑定、只允许 ssh）：
/// 先用私钥；私钥被拒且服务器提供口令方式时回退到口令；服务器只允许公钥时不发送口令；
/// 只允许 ssh 的口令不能代入 HTTP 请求；sudo 使用口令条目的口令。
#[test]
fn key_first_then_password_fallback() {
    if !have("ssh-keygen") {
        eprintln!("跳过：没有 ssh-keygen");
        return;
    }
    let env = Env::setup("sshfallback");
    let kd = env.base.join("keys");
    std::fs::create_dir_all(&kd).unwrap();
    let (host1, _) = keygen(&kd, "host1", "");
    let (client, _) = keygen(&kd, "client", "");
    let (other, _) = keygen(&kd, "other", "");
    let client_pem = std::fs::read_to_string(&client).unwrap();
    let client_pub = russh::keys::decode_secret_key(&client_pem, None).unwrap().public_key().clone();
    let other_pub = russh::keys::decode_secret_key(&std::fs::read_to_string(&other).unwrap(), None).unwrap().public_key().clone();
    const INIT: &str = "Init-Pass-4711!";
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
    let kex = || vec![russh::kex::MLKEM768X25519_SHA256, russh::kex::ECDH_SHA2_NISTP384];
    let mk = |allowed: russh::keys::PublicKey, attempts: Arc<Mutex<Vec<String>>>| {
        move || H {
            files: Default::default(),
            channels: HashMap::new(),
            allowed: Some(allowed.clone()),
            password: Some(INIT.into()),
            leak: INIT.into(),
            attempts: attempts.clone(),
        }
    };
    let both = [russh::MethodKind::PublicKey, russh::MethodKind::Password];
    // A：已装好密钥；B：新主机（还没有这把公钥，只能用初始口令）；C：只允许公钥（AuthenticationMethods publickey）。
    let (att_a, att_b, att_c) = (Arc::new(Mutex::new(vec![])), Arc::new(Mutex::new(vec![])), Arc::new(Mutex::new(vec![])));
    let a = serve_with(&rt, 0, &host1, kex(), &both, mk(client_pub.clone(), att_a.clone()));
    let b = serve_with(&rt, 0, &host1, kex(), &both, mk(other_pub.clone(), att_b.clone()));
    let c = serve_with(&rt, 0, &host1, kex(), &[russh::MethodKind::PublicKey], mk(other_pub.clone(), att_c.clone()));

    // 私钥绑定到具体主机；初始口令绑定到网段（与通配符）并只允许 ssh。
    let o = env.run_stdin(&["import", "--name", "deploy-key", "--kind", "ssh-key", "--domain", "127.0.0.1"], client_pem.as_bytes());
    assert!(o.status.success(), "{}", stderr(&o));
    let o = env.run_stdin(
        &["import", "--name", "init-pw", "--domain", "127.0.0.0/8", "--domain", "*.example.com", "--ops", "ssh"],
        format!("{INIT}\n").as_bytes(),
    );
    assert!(o.status.success(), "{}", stderr(&o));
    let mut outputs = stdout(&o) + &stderr(&o);

    let (ok, v, out) = ssh(&env, &format!("deploy@127.0.0.1:{}", a.port), "uptime");
    assert!(ok && v["stdout"].as_str().unwrap().contains("ran: uptime"), "{out}");
    assert_eq!(*att_a.lock().unwrap(), vec!["publickey".to_string()], "私钥成功时不发送口令");
    outputs += &out;

    let (ok, v, out) = ssh(&env, &format!("deploy@127.0.0.1:{}", b.port), "sudo id");
    assert!(ok, "{out}");
    let so = v["stdout"].as_str().unwrap();
    assert!(so.contains("ran: sudo -k -S -p '' -- sh -c 'id'"), "sudo 使用口令条目的口令：{so}");
    assert!(so.contains("leak: [REDACTED:init-pw]"), "{so}");
    assert_eq!(*att_b.lock().unwrap(), vec!["publickey".to_string(), "password".to_string()], "先私钥、后口令");
    outputs += &out;

    let (ok, _, out) = ssh(&env, &format!("deploy@127.0.0.1:{}", c.port), "uptime");
    assert!(!ok && out.contains("AUTH_REJECTED"), "{out}");
    assert!(!att_c.lock().unwrap().contains(&"password".to_string()), "服务器只允许公钥时不发送口令");
    outputs += &out;

    // 指定引用名：只用该条目。
    att_a.lock().unwrap().clear();
    let (ok, _, out) = ssh(&env, &format!("init-pw/deploy@127.0.0.1:{}", a.port), "uptime");
    assert!(ok, "{out}");
    assert_eq!(*att_a.lock().unwrap(), vec!["password".to_string()]);

    // 只允许 ssh 的口令不能用于 HTTP。
    let o = env.agent(&["http", "https://127.0.0.1:9/?p={{init-pw}}"]);
    assert!(!o.status.success() && stdout(&o).contains("OP_NOT_ALLOWED"), "{}", stdout(&o));
    let o = env.agent(&["http", "https://www.example.com/?p={{secret}}"]);
    assert!(!o.status.success() && stdout(&o).contains("OP_NOT_ALLOWED"), "{}", stdout(&o));
    outputs += &(stdout(&o) + &stderr(&o));

    outputs += &env.service_log();
    let bad = leaks(&outputs, &[INIT, &client_pem]);
    assert!(bad.is_empty(), "{bad:?}");
    drop((a, b, c));
}

/// 系统自带的 OpenSSH sshd（以当前用户在高端口运行），加固配置：只允许公钥认证、ecdsa-sha2-nistp384 主机密钥与公钥、
/// aes256-gcm、hmac-sha2-512-etm；密钥交换用本机 OpenSSH 支持的后量子混合组（mlkem768x25519 或 sntrup761x25519）加 nistp384。
#[test]
fn hardened_openssh_server() {
    if !Path::new("/usr/sbin/sshd").exists() || !have("ssh-keygen") {
        eprintln!("跳过：没有 OpenSSH sshd");
        return;
    }
    let env = Env::setup("opensshd");
    let kd = env.base.join("sshd");
    std::fs::create_dir_all(&kd).unwrap();
    let (host, _) = keygen(&kd, "host_ecdsa", "");
    let (client, _) = keygen(&kd, "client", "");
    std::fs::copy(client.with_extension("pub"), kd.join("authorized_keys")).unwrap();
    let kex_supported = String::from_utf8_lossy(&Command::new("ssh").args(["-Q", "kex"]).output().unwrap().stdout).to_string();
    let pq = if kex_supported.lines().any(|l| l == "mlkem768x25519-sha256") {
        "mlkem768x25519-sha256"
    } else {
        "sntrup761x25519-sha512@openssh.com"
    };
    let port = free_port();
    let cfg = kd.join("sshd_config");
    std::fs::write(
        &cfg,
        format!(
            "ListenAddress 127.0.0.1:{port}\nHostKey {}\nPidFile none\nUsePAM no\nStrictModes no\nAuthorizedKeysFile {}\n\
             KexAlgorithms {pq},ecdh-sha2-nistp384\nHostKeyAlgorithms ecdsa-sha2-nistp384\nPubkeyAcceptedAlgorithms ecdsa-sha2-nistp384\n\
             Ciphers aes256-gcm@openssh.com\nMACs hmac-sha2-512-etm@openssh.com\nAuthenticationMethods publickey\nPasswordAuthentication no\n\
             KbdInteractiveAuthentication no\nMaxAuthTries 3\nLogLevel ERROR\n",
            host.display(),
            kd.join("authorized_keys").display()
        ),
    )
    .unwrap();
    let mut sshd: Child = Command::new("/usr/sbin/sshd").args(["-D", "-e", "-f"]).arg(&cfg).stderr(Stdio::piped()).spawn().unwrap();
    let t0 = Instant::now();
    while std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
        if t0.elapsed() > Duration::from_secs(10) || sshd.try_wait().unwrap().is_some() {
            let mut err = String::new();
            use std::io::Read;
            let _ = sshd.stderr.take().unwrap().read_to_string(&mut err);
            let _ = sshd.kill();
            panic!("sshd did not start: {err}");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let user = String::from_utf8_lossy(&Command::new("id").arg("-un").output().unwrap().stdout).trim().to_string();
    let o = env.run_stdin(
        &["import", "--name", "matrix", "--kind", "ssh-key", "--domain", &format!("localhost:{port}")],
        &std::fs::read(&client).unwrap(),
    );
    assert!(o.status.success(), "{}", stderr(&o));
    let (ok, v, out) = ssh(&env, &format!("{user}@localhost:{port}"), "echo pm-ok-$((40+2))");
    let _ = sshd.kill();
    let _ = sshd.wait();
    assert!(ok, "{out}");
    assert_eq!(v["exit_code"], 0, "{out}");
    assert!(v["stdout"].as_str().unwrap().contains("pm-ok-42"), "{out}");
}
