#![cfg(target_os = "linux")]
//! `lookup tang`：Agent 只能访问 PassManager 服务器，也能拿到本服务器 Tang 的完整用法（地址与当前签名密钥指纹）。
//! 没配置 tangd 时是 NO_TANG；tangd 停了是 UPSTREAM_ERROR。

mod common;

use std::io::{Read, Write};
use std::net::TcpListener;
use std::time::Duration;

use base64::Engine;
use common::{Env, stdout};
use serde_json::json;

/// 替身 tangd：每个连接读到 EOF（与真的 tangd 一样），回答一份广告（一个签名密钥、一个交换密钥）。
fn fake_tangd(sign: serde_json::Value) -> (TcpListener, String) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap().to_string();
    let keys = json!({"keys": [sign, {"kty": "EC", "crv": "P-521", "x": "eA", "y": "eQ", "key_ops": ["deriveKey"]}]});
    let p = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(keys.to_string());
    let body = json!({"payload": p, "protected": "e30", "signature": "AA"}).to_string();
    let reply = format!("HTTP/1.1 200 OK\r\nContent-Type: application/jose+json\r\nContent-Length: {}\r\n\r\n{body}", body.len());
    let l2 = l.try_clone().unwrap();
    std::thread::spawn(move || {
        for c in l2.incoming() {
            let Ok(mut c) = c else { break };
            let _ = c.set_read_timeout(Some(Duration::from_secs(5)));
            let mut buf = Vec::new();
            let _ = c.read_to_end(&mut buf);
            let _ = c.write_all(reply.as_bytes());
        }
    });
    (l, addr)
}

/// 停止服务、用 `init` 改配置（与已有配置合并）、再启动。
fn reinit(env: &mut Env, args: &[&str]) {
    if let Some(mut c) = env.child.take() {
        let _ = c.kill();
        let _ = c.wait();
    }
    let _ = std::fs::remove_file(env.home.join("run/passmanager.sock"));
    let mut a = vec!["init", "--skip-acme", "--no-start", "--acme-directory", ""];
    a.extend_from_slice(args);
    let o = env.run(&a);
    assert!(o.status.success(), "init: {}{}", stdout(&o), common::stderr(&o));
    env.start();
}

#[test]
fn lookup_tang_gives_this_servers_pin() {
    let mut env = Env::setup("tang");

    // 没有配置 tangd：NO_TANG，不涉及任何凭据。
    let o = env.agent_cmd(&["lookup", "tang"]).output().unwrap();
    assert!(!o.status.success() && stdout(&o).contains("NO_TANG"), "{}", stdout(&o));

    // 配置 tangd 后：pin 是本服务器的 /tang 地址和签名密钥的指纹（与 tang-show-keys 相同的算法）。
    let sign = json!({"kty": "EC", "crv": "P-521", "x": "c2lnbng", "y": "c2lnbnk", "key_ops": ["verify"]});
    let thp = pm_web::tang::jwk_thumbprint(&sign).unwrap();
    let (_tangd, addr) = fake_tangd(sign);
    reinit(&mut env, &["--tang", &addr]);
    let origin = format!("https://pm.test:{}/tang", env.web);
    for target in ["tang", origin.as_str()] {
        let o = env.agent_cmd(&["lookup", target]).output().unwrap();
        let out = stdout(&o);
        assert!(o.status.success(), "{target}: {out}");
        assert!(out.contains(&thp) && out.contains(&origin) && out.contains("clevis encrypt tang"), "{target}: {out}");
        assert!(out.contains("1. Install") && out.contains("5. Switch") && !out.contains("<thp>"), "{out}");
    }

    // tangd 停了：UPSTREAM_ERROR（服务器端的 Tang 坏了，Agent 只需告诉用户）。
    reinit(&mut env, &["--tang", &format!("127.0.0.1:{}", common::free_port())]);
    let o = env.agent_cmd(&["lookup", "tang"]).output().unwrap();
    assert!(!o.status.success() && stdout(&o).contains("UPSTREAM_ERROR"), "{}", stdout(&o));
}
