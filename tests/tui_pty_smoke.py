"""在伪终端中驱动 PassManager TUI 做冒烟测试：登录、新增条目、键盘/鼠标切换标签、双击编辑、退出。

用法：python3 -I tests/tui_pty_smoke.py target/debug/PassManager "$(mktemp -d)"
（需要调试构建；脚本以用户模式启动服务，并使用测试用的低强度 KDF 参数）
"""
import os, pty, sys, time, select, subprocess, json, socket, struct, re
ANSI = re.compile(rb"\x1b\[[0-9;?]*[ -/]*[@-~]")
def text(b):
    return ANSI.sub(b"", b).decode("utf-8", "ignore").replace(" ", "")

BIN = sys.argv[1]
HOME = sys.argv[2]
env = dict(os.environ, PASSMANAGER_HOME=HOME, PASSMANAGER_INSECURE_TEST_KDF="1", TERM="xterm-256color")
for k in ["CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT"]:
    env.pop(k, None)

svc = subprocess.Popen([BIN, "service", "--user"], env=env, stderr=subprocess.DEVNULL)
sock = os.path.join(HOME, "run", "passmanager.sock")
for _ in range(100):
    if os.path.exists(sock):
        break
    time.sleep(0.1)

def call(hello, reqs):
    s = socket.socket(socket.AF_UNIX); s.connect(sock)
    def send(o):
        b = json.dumps(o).encode(); s.sendall(struct.pack(">I", len(b)) + b)
    def recv():
        n = struct.unpack(">I", s.recv(4))[0]; d = b""
        while len(d) < n: d += s.recv(n - len(d))
        return json.loads(d)
    send(hello); recv()
    out = []
    for r in reqs:
        send(r); out.append(recv())
    s.close(); return out

call({"auth": "setup", "v": 1, "password": "tui-password-1"}, [])

pid, fd = pty.fork()
if pid == 0:
    import fcntl, termios
    fcntl.ioctl(0, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 120, 0, 0))
    os.execve(BIN, [BIN], env)

screen = b""
def read(t=1.0):
    global screen
    end = time.time() + t
    while time.time() < end:
        r, _, _ = select.select([fd], [], [], 0.1)
        if r:
            try:
                screen += os.read(fd, 65536)
            except OSError:
                return
def send(b, t=0.6):
    os.write(fd, b); read(t)

read(1.5)
ok_login_box = "PassManager" in text(screen)

send(b"tui-password-1\r", 3)
txt = text(screen)
ok_unlocked = "已解锁" in txt
screen = b""
send(b"a", 1)  # 新增条目（字段：密钥 → 域名 → 说明；引用名自动生成）
send(b"ghp_from_tui_123456")
send(b"\t")
send(b"*.github.com")
send(b"\t")
send(b"ci token")
send(b"\x13", 2)  # Ctrl+S 保存
txt = text(screen)
ok_saved = "已保存" in txt
screen = b""
send(b"3", 1)  # Agent 接入页
ok_agents = "ClaudeCode" in text(screen)
screen = b""
send(b"4", 1)  # 诊断页
ok_doctor = "用户模式" in text(screen)
screen = b""
# 鼠标点击"5 设置"标签（第 3 行，第 46 列；SGR 编码，按下 + 释放）。
send(b"\x1b[<0;46;3M\x1b[<0;46;3m", 1)
ok_mouse_tab = "空闲自动锁定" in text(screen)
screen = b""
# 回到条目页，双击第一行打开编辑对话框。
send(b"1", 1)
send(b"\x1b[<0;5;6M\x1b[<0;5;6m", 0.2)
send(b"\x1b[<0;5;6M\x1b[<0;5;6m", 1)
ok_double_click = "编辑条目" in text(screen)
send(b"\x1b", 0.5)
send(b"q", 1)
os.waitpid(pid, 0)

# 通过协议确认条目已写入、密钥正确。
res = call({"auth": "password", "v": 1, "password": "tui-password-1"}, [{"op": "entries"}, {"op": "reveal", "name": "github.com", "password": "tui-password-1"}])
entries = res[0]["data"]
secret = res[1]["data"]
svc.terminate(); svc.wait()
result = {
    "login_box": ok_login_box, "unlocked": ok_unlocked, "saved": ok_saved, "agents_tab": ok_agents, "doctor_tab": ok_doctor, "mouse_tab": ok_mouse_tab, "double_click_edit": ok_double_click,
    "entries": [(e["name"], e["domains"], e["note"]) for e in entries], "secret_ok": secret == "ghp_from_tui_123456",
}
print(json.dumps(result, ensure_ascii=False))
checks = [v for k, v in result.items() if isinstance(v, bool)]
sys.exit(0 if all(checks) and result["entries"] else 1)
