"""系统模式安装后的探测脚本（供 CI 使用）。

连接已安装的 PassManager 服务（口令握手），输出状态、封存等级、安全检查结果；
可选地在库已就绪时跑一遍 Agent 流程（新建令牌 → 新增条目 → 用 CLI 以令牌调用 list）。

用法：
  python3 -I tests/system_probe.py --password PW [--expect-level 2] [--expect-ready yes|no|any]
                                   [--agent-flow --bin /usr/local/bin/PassManager [--run-as USER]]
退出码：0 = 全部期望满足；1 = 不满足；2 = 无法连接。
"""
import argparse, json, os, struct, subprocess, sys, time

# Windows 控制台默认编码（cp1252 等）输出不了中文。
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.stderr.reconfigure(encoding="utf-8", errors="replace")

p = argparse.ArgumentParser()
p.add_argument("--password", required=True)
p.add_argument("--expect-level", type=int)
p.add_argument("--expect-ready", choices=["yes", "no", "any"], default="any")
p.add_argument("--agent-flow", action="store_true")
p.add_argument("--bin", default="PassManager")
p.add_argument("--bin-prefix", default="", help="运行 CLI 时的前缀命令，例如 'arch -x86_64'（macOS Rosetta）")
p.add_argument("--run-as", help="以该用户身份运行 CLI（Linux/macOS；脚本本身以 root 运行时使用。令牌会话不接受 root）")
p.add_argument("--timeout", type=float, default=60)
p.add_argument("--socket", help="覆盖默认的 socket / 管道地址（本地测试用）")
args = p.parse_args()

if os.name == "nt":
    ADDR = r"\\.\pipe\PassManager"
elif sys.platform == "darwin":
    ADDR = "/var/run/passmanager/passmanager.sock"
else:
    ADDR = "/run/passmanager/passmanager.sock"
if args.socket:
    ADDR = args.socket


class Conn:
    def __init__(self, hello):
        deadline = time.time() + args.timeout
        last = None
        while time.time() < deadline:
            try:
                if os.name == "nt":
                    self.f = open(ADDR, "r+b", buffering=0)
                else:
                    import socket
                    s = socket.socket(socket.AF_UNIX)
                    s.connect(ADDR)
                    self.f = s.makefile("rwb", buffering=0)
                break
            except OSError as e:
                last = e
                time.sleep(1)
        else:
            print(f"无法连接 {ADDR}: {last}")
            sys.exit(2)
        self.send(hello)
        ack = self.recv()
        if ack is None:
            print("握手被拒绝（口令错误或服务未就绪）")
            sys.exit(2)

    def send(self, obj):
        b = json.dumps(obj).encode()
        self.f.write(struct.pack(">I", len(b)) + b)
        self.f.flush()

    def recv(self):
        h = self.f.read(4)
        if not h or len(h) < 4:
            return None
        n = struct.unpack(">I", h)[0]
        d = b""
        while len(d) < n:
            c = self.f.read(n - len(d))
            if not c:
                return None
            d += c
        return json.loads(d)

    def call(self, req):
        self.send(req)
        return self.recv()


admin = Conn({"auth": "password", "v": 1, "password": args.password})
status = admin.call({"op": "status"})["data"]
security = admin.call({"op": "security"})["data"]
print(json.dumps({"status": status, "seal": {k: security[k] for k in ("level", "method", "description", "l1_reason", "runtime_issues")}}, ensure_ascii=False, indent=2))
print("安全检查：")
for f in security["report"]["findings"]:
    mark = "✔" if f["ok"] else ("⚠" if f.get("advisory") else "✘")
    print(f"  {mark} {f['id']}: {f['title']}")
    if not f["ok"]:
        for line in (f.get("detail", "") + "\n" + f.get("steps", "")).strip().splitlines():
            print(f"      {line}")

failures = []
if security["runtime_issues"]:
    failures.append(f"运行时问题：{security['runtime_issues']}")
if args.expect_level is not None and security["level"] != args.expect_level:
    failures.append(f"封存等级为 L{security['level']}，期望 L{args.expect_level}")
if args.expect_ready != "any" and status["ready"] != (args.expect_ready == "yes"):
    failures.append(f"ready={status['ready']}，期望 {args.expect_ready}")
if not status["initialized"]:
    failures.append("库尚未初始化")

if args.agent_flow and status["ready"]:
    tok = admin.call({"op": "create_token", "label": "ci-probe"})["data"]["token"]
    r = admin.call({"op": "add_entry", "entry": {"name": "ci", "secret": "ci-secret-value-123", "domains": ["httpbin.org"], "note": "ci"}})
    if not r["ok"] and "已存在" not in (r.get("message") or ""):
        failures.append(f"新增条目失败：{r}")
    env = dict(os.environ, PASSMANAGER_TOKEN=tok)
    prefix = args.bin_prefix.split()
    cmd = prefix + [args.bin, "list"]
    if args.run_as and os.name != "nt":
        cmd = ["sudo", "-u", args.run_as, "env", f"PASSMANAGER_TOKEN={tok}"] + cmd
    out = subprocess.run(cmd, env=env, capture_output=True, encoding="utf-8", errors="replace")
    print("CLI list:", out.stdout.strip())
    if out.returncode != 0 or '"ci"' not in out.stdout:
        failures.append(f"CLI list 失败：{out.stdout} {out.stderr}")
    # 真实 HTTPS 回显：密钥必须被脱敏（外部服务偶尔不可用，只记录不判失败）。
    cmd = prefix + [args.bin, "http", "GET", "https://httpbin.org/anything?k={{ci}}"]
    if args.run_as and os.name != "nt":
        cmd = ["sudo", "-u", args.run_as, "env", f"PASSMANAGER_TOKEN={tok}"] + cmd
    out = subprocess.run(cmd, env=env, capture_output=True, encoding="utf-8", errors="replace")
    echoed = "[REDACTED:ci]" in out.stdout and "ci-secret-value-123" not in out.stdout
    print("HTTPS 回显已脱敏：", echoed)
    if "ci-secret-value-123" in out.stdout:
        failures.append("HTTPS 回显中出现了明文密钥！")
elif args.agent_flow:
    print("库未就绪，跳过 Agent 流程。")

if failures:
    print("\n未满足：")
    for f in failures:
        print("  -", f)
    sys.exit(1)
print("\n全部期望满足。")
