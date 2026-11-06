#!/usr/bin/env python3
"""advisory_fix.py 的单元测试（不联网、不运行 cargo）。运行：python3 -I scripts/advisory_fix_test.py"""
import importlib.util
import pathlib
import sys
import unittest

_spec = importlib.util.spec_from_file_location("advisory_fix", pathlib.Path(__file__).resolve().parent / "advisory_fix.py")
af = importlib.util.module_from_spec(_spec)
sys.modules["advisory_fix"] = af
_spec.loader.exec_module(af)


def adv(i, patched=(), unaffected=(), **kw):
    return {"advisory": {"id": i, **kw}, "versions": {"patched": list(patched), "unaffected": list(unaffected)}}


def entry(i, name, version, patched=(), **kw):
    return {**adv(i, patched, **kw), "package": {"name": name, "version": version}}


class Versions(unittest.TestCase):
    def test_version_key(self):
        order = ["0.9.0", "0.10.0-rc.2", "0.10.0-rc.18", "0.10.0", "1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-beta", "1.0.0"]
        self.assertEqual(sorted(reversed(order), key=af.version_key), order)
        self.assertEqual(af.version_key("1.2.3+build"), af.version_key("1.2.3"))

    def test_compatible(self):
        self.assertTrue(af.compatible("1.53.2", "1.54.1"))
        self.assertTrue(af.compatible("0.7.5", "0.7.10"))
        self.assertTrue(af.compatible("0.0.3", "0.0.3"))
        self.assertFalse(af.compatible("1.53.2", "2.0.0"))
        self.assertFalse(af.compatible("0.7.5", "0.8.0"))
        self.assertFalse(af.compatible("0.0.3", "0.0.4"))
        self.assertFalse(af.compatible("0.103.15", "0.103.16-alpha.1"), "正式版不换成预发布版")
        self.assertTrue(af.compatible("0.10.0-rc.18", "0.10.0-rc.19"), "预发布版可以换成预发布版")

    def test_comparator_ok(self):
        for v, c, want in [
            ("1.53.3", ">= 1.53.3", True),
            ("1.53.2", ">=1.53.3", False),
            ("1.2.0", "> 1.2.0", False),
            ("1.2.0", "<= 1.2.0", True),
            ("1.2.0", "< 1.2.0", False),
            ("1.2.0", "= 1.2.0", True),
            ("1.2.9", "~1.2.3", True),
            ("1.3.0", "~1.2.3", False),
            ("1.9.0", "^1.2.3", True),
            ("2.0.0", "^1.2.3", False),
            ("1.9.0", "1.2.3", True),
            ("0.104.0-alpha.1", "< 0.104.0-alpha.1", False),
        ]:
            self.assertEqual(af.comparator_ok(v, c), want, (v, c))
        with self.assertRaises(ValueError):
            af.comparator_ok("1.0.0", "!= 1.0.0")

    def test_req_ok(self):
        r = ">= 0.103.16, < 0.104.0-alpha.1"
        self.assertTrue(af.req_ok("0.103.16", r))
        self.assertFalse(af.req_ok("0.103.15", r))
        self.assertFalse(af.req_ok("0.104.0-alpha.2", r))

    def test_fixed_by(self):
        v = {"patched": [">= 1.51.6, < 1.52.0", ">= 1.53.3"], "unaffected": ["< 0.3.2"]}
        self.assertTrue(af.fixed_by("1.53.3", v) and af.fixed_by("1.51.7", v) and af.fixed_by("0.3.1", v))
        self.assertFalse(af.fixed_by("1.52.0", v) or af.fixed_by("1.53.2", v))
        self.assertFalse(af.fixed_by("9.0.0", {"patched": [], "unaffected": []}), "没有修复版本时什么都不算修复")


class Selection(unittest.TestCase):
    def test_pick_smallest_fixed_compatible(self):
        a = [{"id": "A", "versions": {"patched": [">= 0.103.16, < 0.104.0-alpha.1", ">= 0.104.0-alpha.8"]}}]
        self.assertEqual(af.pick("0.103.15", a, ["0.103.14", "0.103.17", "0.103.16", "0.104.0-alpha.8"]), "0.103.16")
        self.assertIsNone(af.pick("1.0.0", [{"id": "A", "versions": {"patched": [">= 2.0.0"]}}], ["2.0.0"]), "大版本不自动升")
        self.assertIsNone(af.pick("1.0.0", [{"id": "A", "versions": {}}], ["1.0.1"]), "无修复版本")
        # 同一个包的多条公告：取同时满足的版本。
        two = [{"id": "A", "versions": {"patched": [">= 1.0.1"]}}, {"id": "B", "versions": {"patched": [">= 1.0.3"]}}]
        self.assertEqual(af.pick("1.0.0", two, ["1.0.1", "1.0.2", "1.0.3", "1.0.4"]), "1.0.3")

    def test_ignored_ids(self):
        t = '[advisories]\nignore = [\n  { id = "RUSTSEC-1", reason = "x" },\n  "RUSTSEC-2",\n]\n'
        self.assertEqual(af.ignored_ids(t), {"RUSTSEC-1", "RUSTSEC-2"})
        self.assertEqual(af.ignored_ids("[bans]\n"), set())

    def test_findings(self):
        a = {
            "vulnerabilities": {"list": [entry("A", "x", "1.0.0"), entry("IGN", "y", "1.0.0"), entry("W", "w", "1.0.0", withdrawn="2026-01-01")]},
            "warnings": {"unsound": [entry("B", "x", "1.0.0")], "yanked": [{"advisory": None, "package": {"name": "z", "version": "1.0.0"}}]},
        }
        f = af.findings(a, {"IGN"})
        self.assertEqual(list(f), [("x", "1.0.0")], "跳过已接受、已撤销和没有公告的")
        self.assertEqual([i["id"] for i in f[("x", "1.0.0")]], ["A", "B"], "两处的公告合并到同一个包")

    def test_index_path(self):
        self.assertEqual(af.index_path("a"), "1/a")
        self.assertEqual(af.index_path("ab"), "2/ab")
        self.assertEqual(af.index_path("abc"), "3/a/abc")
        self.assertEqual(af.index_path("Tokio"), "to/ki/tokio")

    def test_parse_index(self):
        t = '{"vers":"1.0.0"}\n\n{"vers":"1.0.1","yanked":true}\n{"vers":"1.0.2","yanked":false}\n'
        self.assertEqual(af.parse_index(t), ["1.0.0", "1.0.2"])


class Fix(unittest.TestCase):
    def run_fix(self, lock, refuse=()):
        """用内存里的锁文件代替 cargo：x 有修复，n 没有，r 的修复被依赖约束拒绝。"""
        table = {"x": ([">= 1.0.2"], ["1.0.1", "1.0.2"]), "n": ([], ["1.0.1"]), "r": ([">= 1.0.1"], ["1.0.1"])}

        def run_audit():
            rows = [entry("ID-" + n, n, v, table[n][0]) for n, v in lock.items() if not (table[n][0] and af.fixed_by(v, {"patched": table[n][0]}))]
            return {"vulnerabilities": {"list": rows}, "warnings": {}}

        def apply(name, cur, new):
            if name in refuse:
                return False
            lock[name] = new
            return True

        return af.fix(run_audit, lambda n: table[n][1], apply, set())

    def test_updates_and_reports_rest(self):
        lock = {"x": "1.0.0", "n": "1.0.0", "r": "1.0.0"}
        done, left = self.run_fix(lock, refuse={"r"})
        self.assertEqual(done, [{"name": "x", "from": "1.0.0", "to": "1.0.2", "ids": ["ID-x"]}])
        self.assertEqual(lock["x"], "1.0.2")
        self.assertEqual({x["name"]: x["why"] for x in left}, {"n": "no compatible fixed version", "r": "a compatible fix exists but dependency constraints refuse it"})

    def test_clean(self):
        self.assertEqual(self.run_fix({"x": "1.0.2"}), ([], []))

    def test_summary(self):
        s = af.summary([{"name": "x", "from": "1.0.0", "to": "1.0.2", "ids": ["A", "B"]}], [{"name": "n", "version": "1.0.0", "ids": ["C"], "why": "no compatible fixed version"}])
        self.assertIn("`x` 1.0.0 → 1.0.2 (A, B)", s)
        self.assertIn("### Still open", s)
        self.assertIn("nothing was updated", af.summary([], []))
        self.assertNotIn("Still open", af.summary([], []))


if __name__ == "__main__":
    unittest.main(verbosity=1)
