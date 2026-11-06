#!/usr/bin/env python3
"""按漏洞库把受影响的依赖升级到已修复的版本（只改 Cargo.lock，不改 Cargo.toml）。

用法：python3 -I scripts/advisory_fix.py [--db 漏洞库目录] [--summary 输出文件]

做的事：
  1. cargo audit --json 列出公告（含 warnings 里的 unsound 等），跳过 deny.toml 已接受的；
  2. 从 crates.io 索引取未撤回的版本，选满足全部公告的修复范围、且与当前版本语义兼容的**最小**版本
     （每次升级都引入新代码，所以只升到够用为止）；
  3. cargo update -p <包>@<当前版本> --precise <新版本>，再审计一次，最多 3 轮；
  4. 写出摘要。退出码：0 没有未解决的公告；1 还有（没有修复版本、或依赖约束不允许）。

不合并、不发布：这个脚本只改本地的 Cargo.lock，由 CI 或维护者决定之后怎么做。
"""
import argparse
import json
import pathlib
import re
import subprocess
import sys
import tomllib
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
INDEX = "https://index.crates.io"
ROUNDS = 3


def version_key(v):
    """语义化版本的排序键：预发布版排在同号正式版之前，数字标识排在字母标识之前。"""
    core, _, pre = v.split("+")[0].partition("-")
    nums = [int(x) for x in core.split(".")]
    nums += [0] * (3 - len(nums))
    ids = [(0, int(p), "") if p.isdigit() else (1, 0, p) for p in pre.split(".")] if pre else []
    return (nums[0], nums[1], nums[2], 0 if pre else 1, ids)


def compatible(cur, new):
    """new 能否替换 cur 而不违反 ^ 约束：最左边的非零位相同；正式版不换成预发布版。"""
    a, b = version_key(cur), version_key(new)
    if a[3] == 1 and b[3] == 0:
        return False
    if a[0] != 0:
        return a[0] == b[0]
    if a[1] != 0:
        return (a[0], a[1]) == (b[0], b[1])
    return a[:3] == b[:3]


def comparator_ok(v, comp):
    """v 是否满足一个比较式（>=、>、<=、<、=、^、~；不写运算符等同 ^）。"""
    m = re.fullmatch(r"\s*(>=|<=|>|<|=|\^|~)?\s*([0-9][0-9A-Za-z.+-]*)\s*", comp)
    if not m:
        raise ValueError(f"unsupported version requirement: {comp!r}")
    op, base = m.group(1) or "^", m.group(2)
    kv, kb = version_key(v), version_key(base)
    if op == ">=":
        return kv >= kb
    if op == ">":
        return kv > kb
    if op == "<=":
        return kv <= kb
    if op == "<":
        return kv < kb
    if op == "=":
        return kv == kb
    if op == "~":
        return kv >= kb and kv[:2] == kb[:2]
    return kv >= kb and compatible(base, v)


def req_ok(v, req):
    """v 是否满足一条要求（逗号分隔的比较式同时成立）。"""
    return all(comparator_ok(v, c) for c in req.split(","))


def fixed_by(v, versions):
    """v 是否落在公告的 patched 或 unaffected 范围内。"""
    return any(req_ok(v, r) for r in versions.get("patched", []) + versions.get("unaffected", []))


def ignored_ids(text):
    """deny.toml 的 [advisories].ignore 里已接受的公告 ID。"""
    items = tomllib.loads(text).get("advisories", {}).get("ignore", [])
    return {i if isinstance(i, str) else i["id"] for i in items}


def findings(audit, ignored):
    """审计结果里需要处理的公告：(包, 当前版本) -> [{id, versions}]。"""
    entries = list(audit.get("vulnerabilities", {}).get("list", []))
    for group in audit.get("warnings", {}).values():
        entries.extend(group)
    out = {}
    for e in entries:
        adv = e.get("advisory")
        # yanked 等警告没有公告；已撤销的公告不算。
        if not adv or adv.get("withdrawn") or adv["id"] in ignored:
            continue
        key = (e["package"]["name"], e["package"]["version"])
        out.setdefault(key, []).append({"id": adv["id"], "versions": e.get("versions") or {}})
    return out


def pick(cur, advisories, available):
    """满足全部公告的最小可用版本；没有时 None。"""
    ok = [
        v
        for v in available
        if version_key(v) > version_key(cur) and compatible(cur, v) and all(fixed_by(v, a["versions"]) for a in advisories)
    ]
    return min(ok, key=version_key) if ok else None


def index_path(name):
    """crates.io 稀疏索引里这个包的路径。"""
    n = name.lower()
    if len(n) <= 2:
        return f"{len(n)}/{n}"
    if len(n) == 3:
        return f"3/{n[0]}/{n}"
    return f"{n[:2]}/{n[2:4]}/{n}"


def parse_index(text):
    """索引内容（每行一个 JSON）里未撤回的版本。"""
    rows = (json.loads(line) for line in text.splitlines() if line.strip())
    return [r["vers"] for r in rows if not r.get("yanked")]


def fetch_versions(name):
    """向 crates.io 查询这个包未撤回的版本。"""
    with urllib.request.urlopen(f"{INDEX}/{index_path(name)}", timeout=30) as r:
        return parse_index(r.read().decode("utf-8"))


def audit(db):
    """运行 cargo audit（发现公告时退出码非 0，结果仍在 stdout）。"""
    cmd = ["cargo", "audit", "--json"] + (["--no-fetch", "--db", db] if db else [])
    p = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
    if not p.stdout.strip():
        raise SystemExit(f"cargo audit gave no result: {p.stderr[-500:]}")
    return json.loads(p.stdout)


def update(name, cur, new):
    """把锁文件里的 name@cur 换成 new；依赖约束不允许时返回 False。"""
    cmd = ["cargo", "update", "-p", f"{name}@{cur}", "--precise", new]
    return subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True).returncode == 0


def fix(run_audit, versions_of, apply, ignored):
    """审计、选版本、升级，重复到没有进展。返回 (已升级, 未解决)。"""
    done, failed = [], set()
    for _ in range(ROUNDS):
        todo = findings(run_audit(), ignored)
        progress = False
        for (name, cur), advs in sorted(todo.items()):
            new = pick(cur, advs, versions_of(name))
            if new and (name, cur, new) not in failed:
                if apply(name, cur, new):
                    done.append({"name": name, "from": cur, "to": new, "ids": [a["id"] for a in advs]})
                    progress = True
                else:
                    failed.add((name, cur, new))
        if not progress:
            break
    left = []
    for (name, cur), advs in sorted(findings(run_audit(), ignored).items()):
        why = "a compatible fix exists but dependency constraints refuse it" if pick(cur, advs, versions_of(name)) else "no compatible fixed version"
        left.append({"name": name, "version": cur, "ids": [a["id"] for a in advs], "why": why})
    return done, left


def summary(done, left):
    """Markdown 摘要（PR 正文与运行摘要）。"""
    lines = ["## Dependency advisories", ""]
    for d in done:
        lines.append(f"- `{d['name']}` {d['from']} → {d['to']} ({', '.join(d['ids'])})")
    if not done:
        lines.append("- nothing was updated")
    if left:
        lines += ["", "### Still open", ""]
        lines += [f"- `{x['name']}` {x['version']} ({', '.join(x['ids'])}): {x['why']}" for x in left]
    return "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser(description="update dependencies to versions fixed according to the advisory database")
    ap.add_argument("--db", help="local advisory database (no fetch)")
    ap.add_argument("--summary", help="write a Markdown summary to this file")
    args = ap.parse_args()
    ignored = ignored_ids((ROOT / "deny.toml").read_text(encoding="utf-8"))
    done, left = fix(lambda: audit(args.db), fetch_versions, update, ignored)
    text = summary(done, left)
    print(text)
    if args.summary:
        pathlib.Path(args.summary).write_text(text, encoding="utf-8")
    return 1 if left else 0


if __name__ == "__main__":
    sys.exit(main())
