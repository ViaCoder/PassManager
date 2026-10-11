//! ssh-agent 桥端到端（Linux，真实 OpenSSH）：私钥在服务器上，`ssh` 经 agent 套接字由服务器签名。
//! 覆盖：套接字 0600、ssh-add -L 列出公钥、加固 sshd 登录成功、未绑定的主机被拒、转发会话被拒（本地与服务端）、
//! 添加 / 删除操作被拒、服务端审计日志（条目、公钥指纹、主机指纹，不含数据）、吊销令牌后立即无法签名。
#![cfg(target_os = "linux")]

mod common;

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::process::{Child, Stdio};
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use common::*;
use pm_proto::{AgentBinding, Client, Hello, PROTO_V, Request};
use russh::keys::signature::Signer;
use russh::keys::ssh_encoding::Encode;

struct Kill(Child);
impl Drop for Kill {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn s(v: &[u8]) -> Vec<u8> {
    let mut o = (v.len() as u32).to_be_bytes().to_vec();
    o.extend_from_slice(v);
    o
}

fn agent_call(sock: &std::path::Path, msg: &[u8]) -> Vec<u8> {
    let mut c = UnixStream::connect(sock).unwrap();
    agent_call_on(&mut c, msg)
}

fn agent_call_on(c: &mut UnixStream, msg: &[u8]) -> Vec<u8> {
    c.write_all(&s(msg)).unwrap();
    let mut len = [0u8; 4];
    c.read_exact(&mut len).unwrap();
    let mut r = vec![0u8; u32::from_be_bytes(len) as usize];
    c.read_exact(&mut r).unwrap();
    r
}

fn userauth(session: &[u8], key: &[u8]) -> Vec<u8> {
    let mut d = s(session);
    d.push(50);
    d.extend(s(b"deploy"));
    d.extend(s(b"ssh-connection"));
    d.extend(s(b"publickey"));
    d.push(1);
    d.extend(s(b"ecdsa-sha2-nistp384"));
    d.extend(s(key));
    d
}

#[test]
fn ssh_agent_bridge() {
    if !std::path::Path::new("/usr/sbin/sshd").exists() || !have("ssh") || !have("ssh-keygen") || !have("ssh-add") {
        eprintln!("跳过：需要 OpenSSH（sshd、ssh、ssh-keygen、ssh-add）");
        return;
    }
    let env = Env::setup("agent");
    let kd = env.base.join("keys");
    std::fs::create_dir_all(&kd).unwrap();
    let (client_key, client_fp) = keygen(&kd, "matrix", "");
    let sshd = start_sshd(&env.base.join("sshd1"), &client_key.with_extension("pub"));
    let other = start_sshd(&env.base.join("sshd2"), &client_key.with_extension("pub"));
    let host_pub = std::fs::read_to_string(sshd.host_key.with_extension("pub")).unwrap();
    let pem = std::fs::read_to_string(&client_key).unwrap();
    let user = String::from_utf8_lossy(&std::process::Command::new("id").arg("-un").output().unwrap().stdout).trim().to_string();

    // 导入私钥，只绑定第一台 sshd 的主机密钥。
    let o = env.run_stdin(&["import", "--name", "matrix", "--kind", "ssh-key", "--host-key", host_pub.trim()], pem.as_bytes());
    assert!(o.status.success(), "{}", stderr(&o));
    assert!(stdout(&o).contains(&client_fp));

    // 启动 agent 桥。
    let sock = env.base.join("agentdir/agent.sock");
    let agent = Kill(
        env.agent_cmd(&["ssh-agent", "--socket", sock.to_str().unwrap()]).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().unwrap(),
    );
    let t0 = Instant::now();
    while !sock.exists() {
        assert!(t0.elapsed() < Duration::from_secs(10), "agent socket not created");
        std::thread::sleep(Duration::from_millis(50));
    }
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(std::fs::metadata(&sock).unwrap().permissions().mode() & 0o777, 0o600);

    // ssh-add -L：列出服务器上的公钥（注释为条目名）。
    let o = std::process::Command::new("ssh-add").arg("-L").env("SSH_AUTH_SOCK", &sock).output().unwrap();
    let listed = stdout(&o);
    assert!(listed.starts_with("ecdsa-sha2-nistp384 ") && listed.trim_end().ends_with(" matrix"), "{listed}");
    assert_eq!(
        listed.split_whitespace().nth(1),
        std::fs::read_to_string(client_key.with_extension("pub")).unwrap().split_whitespace().nth(1)
    );
    // 添加 / 删除：拒绝。
    let o = std::process::Command::new("ssh-add").arg("-D").env("SSH_AUTH_SOCK", &sock).output().unwrap();
    assert!(!o.status.success());
    let o = std::process::Command::new("ssh-add")
        .arg(&client_key)
        .env("SSH_AUTH_SOCK", &sock)
        .env("HOME", env.base.join("h"))
        .output()
        .unwrap();
    assert!(!o.status.success());

    // 真实 ssh：绑定的主机登录成功。
    let home = env.base.join("sshhome");
    let o = real_ssh(&home, &sock, sshd.port, &user, "echo agent-ok-$((40+2))");
    assert!(o.status.success() && stdout(&o).contains("agent-ok-42"), "{}{}", stdout(&o), stderr(&o));
    // 没有绑定的主机：服务器拒绝签名，登录失败。
    let o = real_ssh(&home, &sock, other.port, &user, "echo should-not-run");
    assert!(!o.status.success() && !stdout(&o).contains("should-not-run"));

    // 转发会话：本地拒绝；直接向服务器请求也被拒绝。
    let host_sk = russh::keys::decode_secret_key(&std::fs::read_to_string(&sshd.host_key).unwrap(), None).unwrap();
    let session = b"fake-session-identifier-0123456789";
    let mut host_sig = Vec::new();
    Signer::<russh::keys::ssh_key::Signature>::try_sign(&host_sk, session).unwrap().encode(&mut host_sig).unwrap();
    let host_blob = host_sk.public_key().to_bytes().unwrap();
    let key_blob = russh::keys::decode_secret_key(&pem, None).unwrap().public_key().to_bytes().unwrap();
    let mut c = UnixStream::connect(&sock).unwrap();
    let mut bind = vec![27u8];
    bind.extend(s(b"session-bind@openssh.com"));
    bind.extend(s(&host_blob));
    bind.extend(s(session));
    bind.extend(s(&host_sig));
    bind.push(1);
    assert_eq!(agent_call_on(&mut c, &bind), vec![6]);
    let mut sign = vec![13u8];
    sign.extend(s(&key_blob));
    sign.extend(s(&userauth(session, &key_blob)));
    sign.extend(0u32.to_be_bytes());
    assert_eq!(agent_call_on(&mut c, &sign), vec![5], "转发会话不签名");
    // 没有绑定直接签名：拒绝。
    assert_eq!(agent_call(&sock, &sign), vec![5]);
    // 服务端同样执行这些检查（绕过本地 agent 直接发请求）。
    let mut remote = remote_client(&env);
    let b = |fwd: bool, sid: &[u8]| AgentBinding {
        host_key: STANDARD.encode(&host_blob),
        session_id: STANDARD.encode(sid),
        signature: STANDARD.encode(&host_sig),
        forwarding: fwd,
    };
    let req = |binding: Option<AgentBinding>, data: &[u8]| Request::AgentSign {
        key: STANDARD.encode(&key_blob),
        data: STANDARD.encode(data),
        flags: 0,
        binding,
    };
    assert_eq!(remote.call(&req(Some(b(true, session)), &userauth(session, &key_blob))).unwrap_err().code, "FORBIDDEN");
    assert_eq!(remote.call(&req(None, &userauth(session, &key_blob))).unwrap_err().code, "FORBIDDEN");
    assert_eq!(remote.call(&req(Some(b(false, session)), b"arbitrary data")).unwrap_err().code, "FORBIDDEN", "不签任意数据");
    assert_eq!(remote.call(&req(Some(b(false, session)), &userauth(b"other-session", &key_blob))).unwrap_err().code, "FORBIDDEN");
    assert_eq!(remote.call(&req(Some(b(false, b"wrong")), &userauth(b"wrong", &key_blob))).unwrap_err().code, "FORBIDDEN", "主机签名不对");
    // 合法的绑定（这台主机已绑定）：服务器签名，签名可被公钥验证。
    let sig: String = serde_json::from_value(remote.call(&req(Some(b(false, session)), &userauth(session, &key_blob))).unwrap()).unwrap();
    assert!(!sig.is_empty());

    // 审计日志：条目、公钥指纹、主机指纹；不含会话数据。
    let log = env.service_log();
    let host_fp = host_sk.public_key().fingerprint(russh::keys::HashAlg::Sha256).to_string();
    assert!(log.contains(&format!("ssh-agent sign: entry=matrix key=ecdsa-sha2-nistp384 {client_fp} host={host_fp}")), "{log}");
    assert!(log.contains("ssh-agent sign refused"), "未绑定主机的拒绝也有记录");
    assert!(!log.contains("fake-session-identifier") && leaks(&log, &[&pem]).is_empty());

    // 吊销令牌：立即无法签名。
    let o = env.run(&["token", "list"]);
    let id = stdout(&o).lines().find(|l| l.contains("agent")).unwrap().split_whitespace().next().unwrap().to_string();
    assert!(env.run(&["token", "revoke", &id]).status.success());
    let o = real_ssh(&home, &sock, sshd.port, &user, "echo after-revoke");
    assert!(!o.status.success() && !stdout(&o).contains("after-revoke"));
    drop(agent);
}

/// 用 Agent 的远程配置直接连接服务器（双层加密通道）。
fn remote_client(env: &Env) -> Client {
    let d = &env.agent_dir;
    let token = std::fs::read_to_string(d.join("token")).unwrap();
    let bundle = std::fs::read(d.join("server-keys.bin")).unwrap();
    let public = pm_net::inner::ServerPublic::from_bundle(&bundle, &pm_net::inner::fingerprint(&bundle)).unwrap();
    let target = pm_net::client::Target {
        host: "pm.test".into(),
        port: env.agent,
        connect_addr: Some(addr(env.agent)),
        extra_ca_pem: Some(std::fs::read_to_string(&env.ca).unwrap()),
    };
    let stream = pm_net::client::connect(&target, &public).unwrap();
    Client::connect_stream(stream, &Hello::Token { v: PROTO_V, token }).unwrap()
}
