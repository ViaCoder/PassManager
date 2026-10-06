"""在构建机上直接对发布包做功能冒烟测试（不需要单独的运行环境）。

步骤：以用户模式启动发布版服务（运行完整的启动自检）→ 用真实的 KDF 参数设置口令 →
调用 tests/system_probe.py 跑一遍 Agent 流程（建令牌、加条目、CLI list、经 httpbin.org 的 HTTPS 代填与脱敏）。

用法：
  python3 -I tests/release_smoke.py <PassManager 可执行文件> [--prefix "arch -x86_64"]
--prefix 用于在 Apple 芯片上通过 Rosetta 2 运行通用二进制中的 x86_64 部分。
"""
import argparse, json, os, shutil, socket, struct, subprocess, sys, tempfile, time
from pathlib import Path

# Windows 控制台默认编码（cp1252 等）输出不了中文。
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.stderr.reconfigure(encoding="utf-8", errors="replace")

ap = argparse.ArgumentParser()
ap.add_argument("bin")
ap.add_argument("--prefix", default="")
a = ap.parse_args()

BIN = str(Path(a.bin).resolve())
PREFIX = a.prefix.split()
PW = "Release-Smoke-Passw0rd!"
home = Path(tempfile.mkdtemp(prefix="pm-smoke-", dir=None if os.name == "nt" else "/tmp"))
env = dict(os.environ, PASSMANAGER_HOME=str(home))
for k in ("CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT", "PASSMANAGER_INSECURE_TEST_KDF"):
    env.pop(k, None)


def run(*args, **kw):
    return subprocess.run(PREFIX + [BIN, *args], env=env, capture_output=True, encoding="utf-8", errors="replace", **kw)


version = run("--version").stdout.strip()
print("版本：", version)
if a.prefix:
    print("运行前缀：", a.prefix)
sock = run("socket-path").stdout.strip()
print("本地地址：", sock)

svc = subprocess.Popen(PREFIX + [BIN, "service", "--user"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, encoding="utf-8", errors="replace")


def listening():
    if os.name == "nt":
        name = sock.rsplit("\\", 1)[-1].lower()
        return any(n.lower() == name for n in os.listdir("\\\\.\\pipe\\"))
    return os.path.exists(sock)


ok = False
try:
    deadline = time.time() + 120
    while not listening():
        if svc.poll() is not None:
            print("服务退出：", svc.stderr.read())
            sys.exit(1)
        if time.time() > deadline:
            print("服务未在 120 秒内启动")
            sys.exit(1)
        time.sleep(0.5)

    # 首次设置口令（真实 KDF：按本机校准 Argon2id，并生成 ML-KEM-1024 与 Classic McEliece 密钥）。
    t0 = time.time()
    if os.name == "nt":
        f = open(sock, "r+b", buffering=0)
    else:
        s = socket.socket(socket.AF_UNIX)
        s.connect(sock)
        f = s.makefile("rwb", buffering=0)
    hello = json.dumps({"auth": "setup", "v": 1, "password": PW}).encode()
    f.write(struct.pack(">I", len(hello)) + hello)
    ack = f.read(4)
    f.close()
    if len(ack) < 4:
        print("设置口令失败（握手被拒绝）")
        sys.exit(1)
    print(f"库已创建（{time.time() - t0:.1f} 秒）")

    probe = [sys.executable, "-I", str(Path(__file__).with_name("system_probe.py")), "--socket", sock, "--password", PW,
             "--expect-level", "1", "--expect-ready", "yes", "--agent-flow", "--bin", BIN]
    if a.prefix:
        probe += ["--bin-prefix", a.prefix]
    r = subprocess.run(probe, env=env)
    ok = r.returncode == 0
finally:
    svc.terminate()
    try:
        svc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        svc.kill()
    shutil.rmtree(home, ignore_errors=True)

print("发布包冒烟测试：", "通过" if ok else "失败")
sys.exit(0 if ok else 1)
