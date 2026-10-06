"""把项目推送到 GitHub（必要时新建私有仓库），触发 Actions 并等待结果。

凭据从项目目录下的 `pri` 文件读取（GITHUB_TOKEN、GIT_AUTHOR_NAME、GIT_AUTHOR_EMAIL，
每行 `NAME=value`，可带 export 与引号）。本脚本：
- 绝不打印、记录凭据的值；
- 不把令牌放进命令行参数或 git 远程地址（git 通过凭据助手从环境变量读取）；
- 推送前确认 `pri` 未被提交，且暂存的文件中不含令牌；
- 下载日志时手动处理重定向，不把令牌发给 GitHub 以外的存储地址。

用法：
  python3 -I scripts/github_ci.py [--repo PassManager] [--message "提交说明"] [--release] [--no-wait]
  python3 -I scripts/github_ci.py --wait-only [--sha <commit>]     # 只等待并汇总某次提交的运行结果
  python3 -I scripts/github_ci.py --tag ...                        # 推送后打版本标签，正式发布
"""
import argparse, json, os, re, subprocess, sys, time, urllib.error, urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
API = "https://api.github.com"
TRAILER = ""


KEYS = ("GITHUB_TOKEN", "GIT_AUTHOR_NAME", "GIT_AUTHOR_EMAIL")


def load_credentials(path: Path, account: str = "") -> dict:
    """读取 pri；account 非空时使用带该后缀的一组变量（如 GITHUB_TOKEN1），映射为标准名称。"""
    creds = {}
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].strip()
        for sep in ("=", ":"):
            if sep in line:
                k, v = line.split(sep, 1)
                creds[k.strip()] = v.strip().strip('"').strip("'")
                break
    missing = [k + account for k in KEYS if not creds.get(k + account)]
    if missing:
        sys.exit(f"pri 中缺少：{', '.join(missing)}")
    return {k: creds[k + account] for k in KEYS}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **kw):
        return None


class GitHub:
    def __init__(self, token: str):
        self._token = token
        self._opener = urllib.request.build_opener(NoRedirect)

    def call(self, method, path, body=None, raw=False):
        url = path if path.startswith("http") else API + path
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Authorization", f"Bearer {self._token}")
        req.add_header("Accept", "application/vnd.github+json")
        req.add_header("X-GitHub-Api-Version", "2022-11-28")
        req.add_header("User-Agent", "PassManager-ci-script")
        try:
            with self._opener.open(req, timeout=60) as r:
                payload = r.read()
                return r.status, dict(r.headers), (payload if raw else (json.loads(payload) if payload else None))
        except urllib.error.HTTPError as e:
            payload = e.read()
            try:
                parsed = json.loads(payload) if not raw else payload
            except ValueError:
                parsed = payload.decode("utf-8", "replace")
            return e.code, dict(e.headers), parsed

    def job_log(self, owner, repo, job_id) -> str:
        status, headers, _ = self.call("GET", f"/repos/{owner}/{repo}/actions/jobs/{job_id}/logs", raw=True)
        loc = headers.get("Location") or headers.get("location")
        if status in (301, 302, 303, 307, 308) and loc:
            # 重定向到存储地址：不带令牌下载。
            with urllib.request.urlopen(urllib.request.Request(loc, headers={"User-Agent": "PassManager-ci-script"}), timeout=120) as r:
                return r.read().decode("utf-8", "replace")
        return f"(无法获取日志：HTTP {status})"


def git(*args, env=None, check=True, capture=False):
    r = subprocess.run(["git", *args], cwd=ROOT, env=env, text=True, capture_output=capture)
    if check and r.returncode != 0:
        sys.exit(f"git {' '.join(args)} 失败：{(r.stderr or '').strip()}")
    return r


def git_env(creds, author=None):
    env = dict(os.environ)
    name, email = author if author else (creds["GIT_AUTHOR_NAME"], creds["GIT_AUTHOR_EMAIL"])
    env["GIT_AUTHOR_NAME"] = env["GIT_COMMITTER_NAME"] = name
    env["GIT_AUTHOR_EMAIL"] = env["GIT_COMMITTER_EMAIL"] = email
    env["GITHUB_TOKEN"] = creds["GITHUB_TOKEN"]
    env["GIT_TERMINAL_PROMPT"] = "0"
    return env


def ensure_repo(gh, name, public=False):
    st, headers, user = gh.call("GET", "/user")
    if st != 200:
        sys.exit(f"令牌无效或权限不足（GET /user → HTTP {st}）")
    owner = user["login"]
    scopes = headers.get("X-OAuth-Scopes") or headers.get("x-oauth-scopes")
    print(f"GitHub 账户：{owner}" + (f"；令牌权限：{scopes}" if scopes is not None else "（细粒度令牌）"))
    st, _, repo = gh.call("GET", f"/repos/{owner}/{name}")
    if st == 404:
        st, _, repo = gh.call("POST", "/user/repos", {
            "name": name,
            "private": not public,
            "description": "PassManager: a post-quantum password manager for AI agents",
            "has_wiki": False,
        })
        if st != 201:
            sys.exit(f"创建仓库失败：HTTP {st} {repo.get('message') if isinstance(repo, dict) else ''}")
        print(f"已创建{'公开' if public else '私有'}仓库 {repo['full_name']}")
    elif st == 200:
        print(f"使用已有仓库 {repo['full_name']}（{'私有' if repo['private'] else '公开'}）")
    else:
        sys.exit(f"查询仓库失败：HTTP {st}")
    return owner, repo


def commit_and_push(creds, owner, repo_name, message, author=None, single=False):
    env = git_env(creds, author)
    token = creds["GITHUB_TOKEN"]
    if not (ROOT / ".git").exists():
        git("init", "-q")
    git("add", "-A", env=env)
    staged = git("diff", "--cached", "--name-only", capture=True).stdout.split()
    if "pri" in staged or git("ls-files", "--error-unmatch", "pri", check=False, capture=True).returncode == 0:
        sys.exit("拒绝推送：pri 被加入了 git，请检查 .gitignore")
    for f in staged:
        p = ROOT / f
        if p.is_file() and token.encode() in p.read_bytes():
            sys.exit(f"拒绝推送：{f} 中包含令牌")
    has_head = git("rev-parse", "--verify", "HEAD", check=False, capture=True).returncode == 0
    if single:
        # 整个历史只保留一个初始提交：用孤立分支重新提交当前工作树，替换 main。
        git("branch", "-D", "pm-single", check=False, capture=True)
        git("checkout", "-q", "--orphan", "pm-single", env=env)
        git("add", "-A", env=env)
        git("commit", "-q", "-m", message + TRAILER, env=env)
        git("branch", "-D", "main", check=False, capture=True)
        git("branch", "-m", "main")
        print(f"已生成唯一的初始提交：{message}")
    elif staged or not has_head:
        git("commit", "-q", "-m", message + TRAILER, env=env)
        print(f"已提交：{message}")
    git("branch", "-M", "main")
    url = f"https://github.com/{owner}/{repo_name}.git"
    if git("remote", "get-url", "origin", check=False, capture=True).returncode == 0:
        git("remote", "set-url", "origin", url)
    else:
        git("remote", "add", "origin", url)
    helper = '!f() { echo username=x-access-token; echo "password=$GITHUB_TOKEN"; }; f'
    push = ["push", "-u", "origin", "main"] + (["--force"] if single else [])
    r = git("-c", "credential.helper=", "-c", f"credential.helper={helper}", *push, env=env, check=False, capture=True)
    if r.returncode != 0:
        err = r.stderr.replace(token, "***")
        hint = "（推送 .github/workflows 需要令牌具有 workflow 权限）" if "workflow" in err else ""
        sys.exit(f"推送失败{hint}：{err.strip()}")
    sha = git("rev-parse", "HEAD", capture=True).stdout.strip()
    print(f"已推送 {sha[:12]} → {url}")
    return sha


def push_tag(creds, author=None):
    """按 Cargo.toml 的版本给 HEAD 打附注标签 vX.Y.Z 并推送（触发 release.yml 正式发布）。"""
    env = git_env(creds, author)
    m = re.search(r'^version = "([^"]+)"', (ROOT / "Cargo.toml").read_text(), re.M)
    if not m:
        sys.exit("Cargo.toml 中找不到 version")
    tag = f"v{m.group(1)}"
    if f"## [{m.group(1)}]" not in (ROOT / "CHANGELOG.md").read_text():
        sys.exit(f"CHANGELOG.md 中缺少 [{m.group(1)}] 一节")
    git("tag", "-f", "-a", tag, "-m", f"PassManager {m.group(1)}", env=env, capture=True)
    helper = '!f() { echo username=x-access-token; echo "password=$GITHUB_TOKEN"; }; f'
    r = git("-c", "credential.helper=", "-c", f"credential.helper={helper}", "push", "--force", "origin", f"refs/tags/{tag}",
            env=env, check=False, capture=True)
    if r.returncode != 0:
        sys.exit(f"推送标签失败：{r.stderr.replace(creds['GITHUB_TOKEN'], '***').strip()}")
    print(f"已推送标签 {tag}（Release 工作流将构建、测试并发布）")
    return tag


def dispatch_release(gh, owner, repo):
    st, _, body = gh.call("POST", f"/repos/{owner}/{repo}/actions/workflows/release.yml/dispatches", {"ref": "main"})
    print("已触发 Release 构建（workflow_dispatch）" if st == 204 else f"触发 Release 失败：HTTP {st} {body}")


def wait_runs(gh, owner, repo, sha, timeout_min, expect_release):
    print(f"等待 {sha[:12]} 的 Actions 运行（最长 {timeout_min} 分钟）……", flush=True)
    deadline = time.time() + timeout_min * 60
    runs = []
    while time.time() < deadline:
        st, _, body = gh.call("GET", f"/repos/{owner}/{repo}/actions/runs?head_sha={sha}&per_page=50")
        runs = body.get("workflow_runs", []) if st == 200 else []
        names = {r["name"] for r in runs}
        expected = {"CI"} | ({"Release"} if expect_release else set())
        done = runs and expected <= names and all(r["status"] == "completed" for r in runs)
        summary = ", ".join(f"{r['name']}:{r['status']}/{r['conclusion'] or '-'}" for r in runs) or "尚未开始"
        print(f"  [{time.strftime('%H:%M:%S')}] {summary}", flush=True)
        if done:
            break
        time.sleep(60)
    logs_dir = ROOT / "ci-logs"
    logs_dir.mkdir(exist_ok=True)
    all_ok = True
    for r in runs:
        print(f"\n== {r['name']}：{r['conclusion'] or r['status']}  {r['html_url']}")
        st, _, jobs = gh.call("GET", f"/repos/{owner}/{repo}/actions/runs/{r['id']}/jobs?per_page=100")
        for j in jobs.get("jobs", []):
            mark = {"success": "✔", "failure": "✘", "cancelled": "■", "skipped": "-"}.get(j["conclusion"], "?")
            print(f"  {mark} {j['name']}: {j['conclusion'] or j['status']}")
            if j["conclusion"] == "failure":
                failed_steps = [s["name"] for s in j.get("steps", []) if s.get("conclusion") == "failure"]
                print(f"      失败步骤：{', '.join(failed_steps) or '?'}")
                log = gh.job_log(owner, repo, j["id"])
                safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in j["name"])
                (logs_dir / f"{safe}.log").write_text(log)
                print(f"      日志已保存：ci-logs/{safe}.log")
        if r["conclusion"] != "success":
            all_ok = False
    return all_ok


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default="PassManager")
    ap.add_argument("--message", default="Update PassManager")
    ap.add_argument("--release", action="store_true", help="同时触发 Release 构建（只构建和测试，不发布）")
    ap.add_argument("--tag", action="store_true", help="推送后按 Cargo.toml 版本打标签 vX.Y.Z 并推送，正式发布")
    ap.add_argument("--no-wait", action="store_true")
    ap.add_argument("--wait-only", action="store_true")
    ap.add_argument("--sha")
    ap.add_argument("--timeout", type=int, default=120, help="等待分钟数")
    ap.add_argument("--pri", default=str(ROOT / "pri"))
    ap.add_argument("--account", default="", metavar="SUFFIX", help="使用 pri 中带该后缀的一组凭据（如 1 → GITHUB_TOKEN1）")
    ap.add_argument("--public", action="store_true", help="新建仓库时设为公开（公开仓库的 Actions 不限分钟）")
    ap.add_argument("--single-commit", action="store_true", help="历史只保留一个初始提交（强制推送）")
    ap.add_argument("--author", help="提交作者，格式 'Name <email>'（默认取 pri 中的 GIT_AUTHOR_*）")
    ap.add_argument("--make-public", action="store_true", help="把仓库改为公开（公开仓库的 Actions 不限分钟）")
    ap.add_argument("--job-log", type=int, metavar="JOB_ID", help="下载某个任务的日志到 ci-logs/ 后退出")
    a = ap.parse_args()

    creds = load_credentials(Path(a.pri), a.account)
    gh = GitHub(creds["GITHUB_TOKEN"])
    owner, repo = ensure_repo(gh, a.repo, a.public)
    name = repo["name"]
    if a.make_public:
        st, _, body = gh.call("PATCH", f"/repos/{owner}/{name}", {"visibility": "public"})
        print("仓库已改为公开" if st == 200 else f"修改可见性失败：HTTP {st} {body.get('message') if isinstance(body, dict) else body}")
        return
    if a.job_log:
        (ROOT / "ci-logs").mkdir(exist_ok=True)
        out = ROOT / "ci-logs" / f"job-{a.job_log}.log"
        out.write_text(gh.job_log(owner, name, a.job_log))
        print(f"日志已保存：{out.relative_to(ROOT)}")
        return
    if a.wait_only:
        sha = a.sha or git("rev-parse", "HEAD", capture=True).stdout.strip()
    else:
        author = None
        if a.author:
            n, _, e = a.author.partition("<")
            author = (n.strip(), e.rstrip(">").strip())
        sha = commit_and_push(creds, owner, name, a.message, author, a.single_commit)
        if a.tag:
            push_tag(creds, author)
        elif a.release:
            time.sleep(5)
            dispatch_release(gh, owner, name)
    if a.no_wait:
        return
    ok = wait_runs(gh, owner, name, sha, a.timeout, a.release)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
