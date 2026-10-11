#!/usr/bin/env python3
"""发布前扫描（白名单式）：只输出 路径:行号 + 类型/长度，从不输出匹配到的内容。

三层检查，任何未被允许的发现都会使退出码为 1：
  1. 文件白名单：每个受跟踪的文件（以及历史中出现过的每个文件路径）必须匹配 ALLOWED_FILES；
  2. 高熵字符串：长度 ≥ 20、由 base64/base64url/十六进制字符组成且香农熵超过阈值的片段，以及任何 PEM 块，
     都必须被允许清单（scripts/release-scan-allow.txt）里的条目覆盖；
  3. 私有 IPv4 字面量：只允许文档地址段（RFC 5737）与回环地址；其他私有地址（10/8、172.16/12、192.168/16、
     100.64/10、169.254/16）必须被允许清单覆盖。站点的真实值放在 git 忽略的本地配置里，不应出现在仓库中。

用法：
  python3 -I scripts/release_scan.py                 # 扫描工作区中受跟踪及未被忽略的文件
                                                     # （CI 的检出目录必须保持干净：下载与临时文件放到 RUNNER_TEMP）
  python3 -I scripts/release_scan.py --history       # 另外扫描所有引用可达的历史：每个 blob、提交信息与提交身份
  python3 -I scripts/release_scan.py --self-test     # 自检（在临时仓库里验证能发现问题且不泄露内容）

允许清单格式（每行，# 开头为注释）：
  <类型>  <路径 glob>  <指纹或 *>  <原因>
  类型：entropy | pem | ip ；指纹为匹配内容 SHA-256 的前 16 个十六进制字符（* 表示该文件内全部允许）。
"""
import fnmatch
import hashlib
import ipaddress
import math
import os
import re
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ALLOW_FILE = os.path.join(ROOT, "scripts", "release-scan-allow.txt")

ALLOWED_FILES = [
    "*.rs", "*.toml", "Cargo.lock", "*.md", "*.html", "*.css", "*.sh", "*.py", ".github/*.yml",
    ".github/**/*.yml", ".github/pull_request_template.md", ".gitignore", "LICENSE", "scripts/release-scan-allow.txt",
]

TOKEN_RE = re.compile(rb"[A-Za-z0-9+/=_-]{20,}")
PEM_RE = re.compile(rb"-----BEGIN [A-Z0-9 ]+-----")
IPV4_RE = re.compile(rb"(?<![0-9.])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?![0-9])")
PRIVATE = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16")]


def entropy(s: bytes) -> float:
    n = len(s)
    counts = {}
    for b in s:
        counts[b] = counts.get(b, 0) + 1
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def identifier_like(t: bytes) -> bool:
    """由多个"单词"组成的标识符（例如 Win32_System_Registry、server-unit-contains）：每段是字母，
    或字母后跟不超过 2 位数字。"""
    parts = [p for p in re.split(rb"[_\-./+=]", t) if p]
    return len(parts) >= 2 and all(re.fullmatch(rb"[A-Za-z]+[0-9]{0,2}|[0-9]{1,2}[A-Za-z]*", p) for p in parts)


def is_secret_like(tok: bytes) -> bool:
    t = tok.rstrip(b"=")
    if len(t) < 20 or identifier_like(t):
        return False
    if re.fullmatch(rb"[0-9a-fA-F]+", t):
        return len(t) >= 32 and entropy(t) >= 3.0
    has_upper = re.search(rb"[A-Z]", t) is not None
    has_lower = re.search(rb"[a-z]", t) is not None
    has_digit = re.search(rb"[0-9]", t) is not None
    if not (has_upper and has_lower and has_digit):
        return False
    return entropy(t) >= min(4.2, 0.85 * math.log2(len(t)))


def fp(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()[:16]


def load_allow():
    rules = []
    if not os.path.exists(ALLOW_FILE):
        return rules
    with open(ALLOW_FILE, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 3)
            if len(parts) < 4:
                raise SystemExit(f"bad allowlist line: {line[:40]}")
            rules.append(tuple(parts))
    return rules


def allowed(rules, kind, path, digest):
    for k, glob, f, _reason in rules:
        if k == kind and fnmatch.fnmatch(path, glob) and (f == "*" or f == digest):
            return True
    return False


def file_allowed(path):
    return any(fnmatch.fnmatch(path, g) or fnmatch.fnmatch(os.path.basename(path), g) for g in ALLOWED_FILES)


def scan_blob(path, data, rules, findings, where):
    if b"\0" in data[:8000]:
        findings.append(f"{where}{path}: binary content (not allowed)")
        return
    for no, line in enumerate(data.split(b"\n"), 1):
        for m in PEM_RE.finditer(line):
            if not allowed(rules, "pem", path, fp(m.group(0))):
                findings.append(f"{where}{path}:{no}: PEM block header")
        for m in TOKEN_RE.finditer(line):
            tok = m.group(0)
            if is_secret_like(tok) and not allowed(rules, "entropy", path, fp(tok)):
                findings.append(f"{where}{path}:{no}: high-entropy string, length {len(tok)}, id {fp(tok)}")
        for m in IPV4_RE.finditer(line):
            try:
                ip = ipaddress.ip_address(m.group(1).decode())
            except ValueError:
                continue
            if any(ip in n for n in PRIVATE) and not allowed(rules, "ip", path, fp(m.group(1))):
                findings.append(f"{where}{path}:{no}: private IPv4 literal, id {fp(m.group(1))}")


def git(*args, cwd=ROOT, input=None):
    return subprocess.run(["git", *args], cwd=cwd, input=input, capture_output=True, check=True).stdout


def scan_tree(rules, cwd=ROOT):
    findings = []
    # 受跟踪的文件，加上还没有加入但也没有被忽略的文件（提交前就能发现问题）。
    files = sorted({p for p in git("ls-files", "-z", "--cached", "--others", "--exclude-standard", cwd=cwd).decode().split("\0") if p})
    for p in files:
        if not file_allowed(p):
            findings.append(f"{p}: file type not in the whitelist")
            continue
        full = os.path.join(cwd, p)
        if os.path.islink(full) or not os.path.isfile(full):
            continue
        with open(full, "rb") as f:
            scan_blob(p, f.read(), rules, findings, "")
    return files, findings


def scan_history(rules, cwd=ROOT):
    findings = []
    objs = git("rev-list", "--objects", "--all", cwd=cwd).decode().splitlines()
    seen = {}
    for line in objs:
        sha, _, path = line.partition(" ")
        if path:
            seen.setdefault(sha, path)
    blobs = []
    for sha, path in seen.items():
        t = git("cat-file", "-t", sha, cwd=cwd).decode().strip()
        if t == "blob":
            blobs.append((sha, path))
    for sha, path in blobs:
        if not file_allowed(path):
            findings.append(f"history:{path}: file type not in the whitelist")
            continue
        scan_blob(path, git("cat-file", "blob", sha, cwd=cwd), rules, findings, "history:")
    authors = sorted(set(git("log", "--all", "--format=%an <%ae>%x00%cn <%ce>", cwd=cwd).decode().replace("\0", "\n").split("\n")) - {""})
    msgs = git("log", "--all", "--format=%B", cwd=cwd)
    scan_blob("<commit messages>", msgs, rules, findings, "history:")
    commits = len(git("rev-list", "--all", cwd=cwd).decode().split())
    return len(blobs), commits, authors, findings


def self_test():
    with tempfile.TemporaryDirectory() as d:
        run = lambda *a: subprocess.run(["git", *a], cwd=d, capture_output=True, check=True)
        run("init", "-q")
        import base64
        # 运行时生成测试用的随机样子的值（源码里不出现高熵字面量）。
        secret = "A1" + base64.b64encode(hashlib.sha256(b"release-scan-self-test").digest()).decode().rstrip("=")
        with open(os.path.join(d, "a.rs"), "w") as f:
            f.write(f'const K: &str = "{secret}";\nlet ip = "10.1.2.3"; let doc = "192.0.2.1"; let lo = "127.0.0.1";\n')
        with open(os.path.join(d, "notes.txt"), "w") as f:
            f.write("x\n")
        run("add", ".")
        run("-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-q", "-m", "x")
        _, fnd = scan_tree([], cwd=d)
        text = "\n".join(fnd)
        assert "notes.txt: file type not in the whitelist" in text, text
        assert "a.rs:1: high-entropy string" in text, text
        assert "a.rs:2: private IPv4 literal" in text, text
        assert text.count("private IPv4") == 1, "文档地址段与回环地址允许"
        assert secret not in text and "10.1.2.3" not in text, "不输出匹配内容"
        tok_id = fp(secret.encode())
        _, fnd2 = scan_tree([("entropy", "a.rs", tok_id, "test")], cwd=d)
        assert not any("high-entropy" in x for x in fnd2), fnd2
        nb, nc, authors, hist = scan_history([], cwd=d)
        assert nb >= 2 and nc == 1 and authors == ["t <t@example.com>"], (nb, nc, authors)
        assert any("history:a.rs:1: high-entropy" in x for x in hist)
        for word in ["server_config_defaults_and_validation", "PASSMANAGER_INSECURE_TEST_KDF", "ABCDEFGHIJKLMNOPQRSTUVWXYZ"]:
            assert not is_secret_like(word.encode()), word
    print("self-test ok")


def main():
    args = sys.argv[1:]
    if args == ["--self-test"]:
        return self_test()
    if any(a not in ("--history",) for a in args):
        raise SystemExit("usage: release_scan.py [--history | --self-test]")
    rules = load_allow()
    files, findings = scan_tree(rules)
    print(f"files (tracked + not ignored): {len(files)}")
    if "--history" in args:
        nb, nc, authors, hist = scan_history(rules)
        print(f"history: {nc} commits, {nb} distinct blobs")
        print("commit identities (check that these may be published):")
        for a in authors:
            print(f"  {a}")
        findings += hist
    for f in findings:
        print(f"FINDING {f}")
    print(f"findings: {len(findings)}")
    sys.exit(1 if findings else 0)


if __name__ == "__main__":
    main()
