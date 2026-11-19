//! 托管证书端到端：Pebble 签发（DNS-01 经 challtestsrv）→ 服务端经 SSH（本机 sshd，库里的 ECDSA 密钥）把证书与私钥
//! 以 0600 放到远端目录 → 执行安装命令 → 删掉临时文件；`cert list` / `status` 显示已投递；`cert remove` 清理。
//! 需要本机有 Pebble（~/.local/opt/pebble）、/usr/sbin/sshd 与 ssh-keygen，否则跳过。只在 Unix 上编译（sshd、文件权限）。
#![cfg(unix)]

mod common;

use common::*;

fn whoami() -> String {
    String::from_utf8_lossy(&std::process::Command::new("whoami").output().unwrap().stdout).trim().to_string()
}

#[test]
fn managed_cert_issue_deliver_and_remove() {
    if !have("ssh-keygen") || !std::path::Path::new("/usr/sbin/sshd").exists() {
        eprintln!("跳过：没有 ssh-keygen 或 sshd");
        return;
    }
    let rt = tokio::runtime::Runtime::new().unwrap();
    let Some(pb) = rt.block_on(pm_net::acme::testing::Pebble::start()) else {
        eprintln!("跳过：没有 pebble");
        return;
    };
    let env = Env::setup_acme("managedcert", &pb.directory, &pb.root_pem, &pb.challtest);

    // ---- 远端：本机 sshd，只认测试生成的 ECDSA 公钥；库里导入对应私钥并绑定 127.0.0.1 ----
    let kd = env.base.join("keys");
    std::fs::create_dir_all(&kd).unwrap();
    let (client, _) = keygen(&kd, "client", "");
    let sshd = start_sshd(&env.base.join("sshd"), &kd.join("client.pub"));
    let pem = std::fs::read_to_string(&client).unwrap();
    let o = env.run_stdin(&["import", "--ops", "ssh", "--name", "labkey", "--kind", "ssh-key", "--domain", "127.0.0.1"], pem.as_bytes());
    assert!(o.status.success(), "{}", stderr(&o));
    let target = format!("{}@127.0.0.1:{}", whoami(), sshd.port);

    // ---- 配置校验：域名、没有凭据的目标都被拒绝 ----
    let dom = "lab.passmanager.test";
    let deliver = env.base.join("deliver");
    let out = env.base.join("out");
    std::fs::create_dir_all(&out).unwrap();
    let (dl, ol) = (deliver.display().to_string(), out.display().to_string());
    let after = format!("cp {dl}/{dom}.pem {ol}/cert.pem && cp {dl}/{dom}.key {ol}/key.pem && stat -c %a {dl}/{dom}.key > {ol}/mode");
    let o = env.run(&["cert", "add", "--domain", "localhost", "--target", &target, "--dir", &dl, "--after", &after]);
    assert!(!o.status.success() && stderr(&o).contains("域名无效"), "{}{}", stdout(&o), stderr(&o));
    let o = env.run(&["cert", "add", "--domain", dom, "--target", "root@203.0.113.9", "--dir", &dl, "--after", &after]);
    assert!(!o.status.success(), "没有凭据的目标应被拒绝：{}", stdout(&o));
    let o = env.run(&["cert", "list"]);
    assert!(o.status.success() && stdout(&o).contains("共 0 张"), "{}", stdout(&o));

    // ---- 新增：保存后服务立即签发并投递；renew --wait 等到结束 ----
    let o = env.run(&["cert", "add", "--domain", dom, "--target", &target, "--dir", &dl, "--after", &after]);
    assert!(o.status.success(), "{}{}", stdout(&o), stderr(&o));
    assert!(stdout(&o).contains("已保存"), "{}", stdout(&o));
    let o = env.run(&["cert", "renew", dom, "--wait"]);
    assert!(o.status.success(), "renew: {}{}\n--- service log ---\n{}", stdout(&o), stderr(&o), env.service_log());
    let text = stdout(&o);
    assert!(text.contains("已投递") && !text.contains("签发失败") && !text.contains("投递失败"), "{text}");

    // ---- 远端结果：证书是 Pebble 签给该域名的，私钥 0600，临时文件已删 ----
    let cert = std::fs::read_to_string(out.join("cert.pem")).unwrap();
    assert!(cert.contains("BEGIN CERTIFICATE"));
    assert!(pm_net::tls::cert_not_after(&cert).is_some(), "证书可解析");
    let key = std::fs::read_to_string(out.join("key.pem")).unwrap();
    assert!(key.contains("PRIVATE KEY"));
    assert_eq!(std::fs::read_to_string(out.join("mode")).unwrap().trim(), "600");
    pm_net::tls::CertStore::new().set_pem(&cert, &key).expect("证书与私钥配对");
    assert!(!deliver.join(format!("{dom}.pem")).exists() && !deliver.join(format!("{dom}.key")).exists(), "临时文件应已删除");
    // 服务器上：证书链明文、私钥封存（文件里没有 PEM 私钥）
    let managed = env.home.join("data/tls/managed").join(dom);
    assert!(managed.join("cert.pem").exists());
    assert!(!std::fs::read(managed.join("key.sealed")).unwrap().windows(11).any(|w| w == b"PRIVATE KEY"));
    // 状态：list 与 status 都显示已投递；日志有签发与投递两行
    let o = env.run(&["cert", "list"]);
    assert!(stdout(&o).contains("共 1 张") && stdout(&o).contains("已投递"), "{}", stdout(&o));
    let o = env.run(&["status"]);
    assert!(stdout(&o).contains("托管证书") && stdout(&o).contains(dom) && stdout(&o).contains("已投递"), "{}", stdout(&o));
    let log = env.service_log();
    assert!(log.contains(&format!("managed cert {dom} issued")) && log.contains(&format!("managed cert {dom} delivered")), "{log}");
    // 私钥的任何一行都不在命令输出或日志里
    for line in key.lines().filter(|l| !l.starts_with("-----")) {
        assert!(!log.contains(line) && !text.contains(line), "输出里出现了私钥内容");
    }

    // ---- 再签一次（续期）：新证书再次投递，远端 cert.pem 被更新 ----
    let before = std::fs::read_to_string(out.join("cert.pem")).unwrap();
    let o = env.run(&["cert", "renew", dom, "--wait"]);
    assert!(o.status.success(), "{}{}", stdout(&o), stderr(&o));
    assert_ne!(std::fs::read_to_string(out.join("cert.pem")).unwrap(), before, "续期后应是新证书");

    // ---- 删除：配置与服务器上的文件都没了 ----
    let o = env.run(&["cert", "remove", dom]);
    assert!(o.status.success(), "{}", stderr(&o));
    assert!(!managed.exists(), "服务器上的证书目录应被删除");
    let o = env.run(&["cert", "list"]);
    assert!(stdout(&o).contains("共 0 张"), "{}", stdout(&o));
    let o = env.run(&["cert", "renew", dom]);
    assert!(!o.status.success(), "删除后 renew 应失败");
    drop(sshd);
}
