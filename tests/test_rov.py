"""ROA / IRR 校验的单元测试（全部离线，不发起任何网络请求）。

    python3 -m unittest discover -s tests
"""

import ipaddress
import sys
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from ipmlib import roa as roa_mod
from ipmlib.irr import IrrRoute, _parse
from ipmlib.roa import INVALID, NOTFOUND, VALID, Vrp, covering, validate
from ipmlib.rov import (IRR_MATCH, NOT_ANNOUNCED, NO_AUTH, QUERY_FAILED,
                        ROA_INVALID, ROA_MATCH, evaluate, load_list)


def net(s):
    return ipaddress.ip_network(s)


def vrp(prefix, asn, maxlen, expires=0, valid_to=0):
    return Vrp(net(prefix), asn, maxlen, expires, "test", valid_to)


class TestRoaValidation(unittest.TestCase):
    """RFC 6811 语义。"""

    VRPS = [
        vrp("218.30.0.0/15", 4134, 15),      # 覆盖但 maxLength 只到 /15
        vrp("218.30.33.0/24", 4134, 24),
        vrp("218.30.39.0/24", 23764, 24),
        vrp("66.102.240.0/21", 4134, 24),    # 覆盖式，maxLength 放到 /24
    ]

    def test_exact_vrp_match_is_valid(self):
        self.assertEqual(validate(net("218.30.33.0/24"), 4134, self.VRPS)[0], VALID)

    def test_covering_vrp_with_maxlength_is_valid(self):
        # /21 的 VRP maxLength 24，能授权其下的 /24
        self.assertEqual(validate(net("66.102.245.0/24"), 4134, self.VRPS)[0], VALID)

    def test_maxlength_too_short_is_invalid(self):
        # /15 的 VRP maxLength 15，授权不了 /24；且没有别的 VRP 匹配
        state, matched, cover = validate(net("218.30.37.0/24"), 4134, self.VRPS)
        self.assertEqual(state, INVALID)
        self.assertEqual(matched, [])
        self.assertTrue(cover)

    def test_wrong_origin_is_invalid(self):
        self.assertEqual(validate(net("218.30.33.0/24"), 9999, self.VRPS)[0], INVALID)

    def test_uncovered_prefix_is_notfound(self):
        state, _, cover = validate(net("203.0.113.0/24"), 4134, self.VRPS)
        self.assertEqual(state, NOTFOUND)
        self.assertEqual(cover, [])

    def test_multiple_vrps_any_match_wins(self):
        vrps = self.VRPS + [vrp("218.30.39.0/24", 4809, 24)]
        self.assertEqual(validate(net("218.30.39.0/24"), 23764, vrps)[0], VALID)
        self.assertEqual(validate(net("218.30.39.0/24"), 4809, vrps)[0], VALID)
        self.assertEqual(validate(net("218.30.39.0/24"), 4134, vrps)[0], INVALID)

    def test_covering_lists_all_levels(self):
        cover = covering(net("218.30.33.0/24"), self.VRPS)
        self.assertEqual([str(v.network) for v in cover],
                         ["218.30.0.0/15", "218.30.33.0/24"])

    def test_v4_and_v6_do_not_cross_match(self):
        vrps = [vrp("2001:db8::/32", 4134, 48)]
        self.assertEqual(validate(net("218.30.33.0/24"), 4134, vrps)[0], NOTFOUND)


WHOIS_SAMPLE = """route:          218.30.0.0/15
origin:         AS4134
descr:          China Telecom Network
source:         RADB

route:          218.30.0.0/15
descr:          RPKI ROA for 218.30.0.0/15 / AS4134
max-length:     15
origin:         AS4134
source:         RPKI  # Trust Anchor: apnic

route:          218.30.33.0/24
descr:          CMI  (Customer Route)
                second line of descr
origin:         AS4134
mnt-by:         MAINT-AS58453
source:         RADB

route:          218.30.33.0/24
origin:         AS4134
source:         NTTCOM
"""


class TestIrrParsing(unittest.TestCase):
    def setUp(self):
        self.routes = _parse(WHOIS_SAMPLE, net("218.30.33.0/24"), {"RPKI"})

    def test_less_specific_objects_filtered_out(self):
        # -T route 会把覆盖对象一并返回，必须只留精确前缀
        self.assertTrue(all(r.network == net("218.30.33.0/24")
                            for r in self.routes))

    def test_rpki_pseudo_source_excluded(self):
        # RADB 镜像的 source: RPKI 是 ROA 自动转换的，算进 IRR 会变成循环论证
        self.assertNotIn("RPKI", {r.source for r in self.routes})

    def test_both_real_sources_kept(self):
        self.assertEqual({r.source for r in self.routes}, {"RADB", "NTTCOM"})
        self.assertEqual({r.origin for r in self.routes}, {4134})

    def test_continuation_line_merged_into_descr(self):
        radb = next(r for r in self.routes if r.source == "RADB")
        self.assertIn("second line of descr", radb.descr)
        self.assertEqual(radb.mnt_by, "MAINT-AS58453")

    def test_less_specific_query_returns_its_own_object(self):
        routes = _parse(WHOIS_SAMPLE, net("218.30.0.0/15"), {"RPKI"})
        self.assertEqual([r.source for r in routes], ["RADB"])


class TestLoadList(unittest.TestCase):
    def _write(self, text):
        path = Path(self.tmp) / "l.list"
        path.write_text(text, encoding="utf-8")
        return path

    def setUp(self):
        import tempfile
        self._dir = tempfile.TemporaryDirectory()
        self.tmp = self._dir.name

    def tearDown(self):
        self._dir.cleanup()

    def test_parses_asn_and_no(self):
        rows = load_list(self._write(
            "218.30.33.0/24\t4134\n218.30.32.0/24\tNO\n# 注释\n\n"
            "66.102.240.0/21\tAS4809\n"))
        self.assertEqual([(str(n), o) for n, o in rows],
                         [("218.30.33.0/24", 4134), ("218.30.32.0/24", None),
                          ("66.102.240.0/21", 4809)])

    def test_bad_prefix_raises_with_line_number(self):
        with self.assertRaises(ValueError) as cm:
            load_list(self._write("not-a-prefix\t4134\n"))
        self.assertIn(":1", str(cm.exception))

    def test_missing_second_column_raises(self):
        with self.assertRaises(ValueError):
            load_list(self._write("218.30.33.0/24\n"))


class TestEvaluate(unittest.TestCase):
    VRPS = [vrp("218.30.33.0/24", 4134, 24),
            vrp("218.30.0.0/15", 4134, 15)]

    def _one(self, prefix, origin, irr=None, err=None):
        rows = [(net(prefix), origin)]
        results = evaluate(rows, self.VRPS,
                           {net(prefix): irr or []},
                           {net(prefix): err} if err else {})
        return results[0]

    def test_roa_match(self):
        self.assertEqual(self._one("218.30.33.0/24", 4134).verdict, ROA_MATCH)

    def test_roa_invalid_not_rescued_by_irr(self):
        """RPKI invalid 会被上游直接丢弃，IRR 里登记了也救不回来。"""
        irr = [IrrRoute(net("218.30.33.0/24"), 9999, "RADB")]
        res = self._one("218.30.33.0/24", 9999, irr)
        self.assertEqual(res.verdict, ROA_INVALID)
        self.assertFalse(res.matched)

    def test_irr_match_only_when_no_roa_coverage(self):
        irr = [IrrRoute(net("203.0.113.0/24"), 65000, "RADB")]
        res = self._one("203.0.113.0/24", 65000, irr)
        self.assertEqual(res.verdict, IRR_MATCH)
        self.assertTrue(res.matched)

    def test_irr_origin_must_match(self):
        irr = [IrrRoute(net("203.0.113.0/24"), 65001, "RADB")]
        self.assertEqual(self._one("203.0.113.0/24", 65000, irr).verdict, NO_AUTH)

    def test_no_auth_when_nothing_found(self):
        self.assertEqual(self._one("203.0.113.0/24", 65000).verdict, NO_AUTH)

    def test_query_failure_is_not_judged_as_no_auth(self):
        # IRR 查不到和 IRR 查询失败必须区分，否则会误报成无授权
        res = self._one("203.0.113.0/24", 65000, err="超时")
        self.assertEqual(res.verdict, QUERY_FAILED)
        self.assertFalse(res.matched)

    def test_unannounced_classified_separately(self):
        res = self._one("218.30.37.0/24", None)
        self.assertEqual(res.verdict, NOT_ANNOUNCED)
        self.assertFalse(res.announced)

    def test_roa_usable_respects_maxlength(self):
        # /15≤15 覆盖了地址空间，却授权不了这条 /24 上线
        res = self._one("218.30.37.0/24", None)
        self.assertTrue(res.roa_covering)
        self.assertEqual(res.roa_usable, [])

    def test_roa_usable_when_maxlength_allows(self):
        res = self._one("218.30.33.0/24", None)
        self.assertEqual(len(res.roa_usable), 1)


class TestRoaExpiry(unittest.TestCase):
    """到期时间有两种口径，混用会得出完全相反的结论。"""

    def test_cert_validto_preferred_over_chain_expiry(self):
        # rpki.json 的 expires 是验证链有效期（几天），validTo 才是 ROA 证书有效期
        v = vrp("10.0.0.0/24", 65000, 24, expires=1000, valid_to=9000)
        self.assertEqual(v.expiry, 9000)
        self.assertEqual(v.expiry_kind, roa_mod.EXPIRY_CERT)

    def test_falls_back_to_chain_expiry(self):
        v = vrp("10.0.0.0/24", 65000, 24, expires=1000)
        self.assertEqual(v.expiry, 1000)
        self.assertEqual(v.expiry_kind, roa_mod.EXPIRY_CHAIN)

    def test_no_expiry_at_all(self):
        self.assertIsNone(vrp("10.0.0.0/24", 65000, 24).expiry)

    def test_roundtrip_through_cache_keeps_validto(self):
        v = vrp("10.0.0.0/24", 65000, 24, expires=1000, valid_to=9000)
        back = roa_mod._vrp_from(v.as_dict())
        self.assertEqual(back.valid_to, 9000)
        self.assertEqual(back.expiry, 9000)

    def test_attach_validity_survives_api_failure(self):
        """GraphQL 挂了不能让整个校验失败，退回链路有效期并标明口径。"""
        vrps = [vrp("10.0.0.0/24", 65000, 24, expires=1000)]
        meta = {}
        out = roa_mod.attach_validity(vrps, [net("10.0.0.0/24")], meta,
                                      url="http://127.0.0.1:1/none")
        self.assertEqual(out, vrps)
        self.assertEqual(meta["expiry_kind"], roa_mod.EXPIRY_CHAIN)
        self.assertIn("GraphQL 不可用", meta["expiry_source"])

    def test_aggregate_collapses_parents(self):
        parents = [net("218.30.32.0/24"), net("218.30.33.0/24"),
                   net("10.0.0.0/24")]
        self.assertEqual([str(x) for x in roa_mod._aggregate(parents)],
                         ["10.0.0.0/24", "218.30.32.0/23"])

    def test_days_until_rounds_up(self):
        from ipmlib.rov_report import days_until
        # 3 天后到期必须显示「剩 3 天」，向下取整会少算一天
        self.assertEqual(days_until(_soon(3)), 3)
        self.assertEqual(days_until(_soon(0.5)), 1)
        self.assertEqual(days_until(_soon(-2)), -2)

    def test_expiry_warning_uses_effective_vrp(self):
        from ipmlib.rov_report import _min_days
        soon = vrp("10.0.0.0/24", 65000, 24, valid_to=_soon(5))
        later = vrp("10.0.0.0/23", 65000, 24, valid_to=_soon(300))
        rows = evaluate([(net("10.0.0.0/24"), 65000)], [soon, later], {}, {})
        self.assertEqual(rows[0].verdict, ROA_MATCH)
        self.assertLess(_min_days(rows[0].roa_matched), 14)


def _soon(days):
    import datetime
    return int(datetime.datetime.now(datetime.timezone.utc).timestamp()
               + days * 86400)


class TestFreshness(unittest.TestCase):
    """校验必须基于当下的 RPKI 状态，数据新鲜度要能被看见。"""

    def test_default_never_reuses_cache(self):
        # 拿几小时前的快照判 valid/invalid 可能与现网相反，默认必须重新下载
        self.assertEqual(roa_mod.CACHE_MAX_AGE, 0)

    def test_cache_skipped_when_max_age_zero(self):
        import json as _json
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            cache = Path(d) / "vrps.json"
            cache.write_text(_json.dumps(
                {"meta": {"schema": roa_mod.CACHE_SCHEMA}, "vrps": []}),
                encoding="utf-8")
            calls = []
            orig = roa_mod._download
            roa_mod._download = lambda url, parents: (calls.append(1), ([], {}))[1]
            try:
                roa_mod.fetch_vrps([net("10.0.0.0/24")], cache, max_age=0)
            finally:
                roa_mod._download = orig
            self.assertEqual(len(calls), 1, "max_age=0 时不该走缓存")

    def test_cache_used_when_explicitly_allowed(self):
        import json as _json
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            cache = Path(d) / "vrps.json"
            cache.write_text(_json.dumps(
                {"meta": {"schema": roa_mod.CACHE_SCHEMA, "buildtime": "x"},
                 "vrps": []}), encoding="utf-8")
            calls = []
            orig = roa_mod._download
            roa_mod._download = lambda url, parents: (calls.append(1), ([], {}))[1]
            try:
                _, meta = roa_mod.fetch_vrps([net("10.0.0.0/24")], cache,
                                             max_age=3600)
            finally:
                roa_mod._download = orig
            self.assertEqual(calls, [])
            self.assertTrue(meta["from_cache"])

    def test_buildtime_age_parsed(self):
        import datetime
        now = datetime.datetime.now(datetime.timezone.utc)
        stamp = (now - datetime.timedelta(hours=3)).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.assertAlmostEqual(roa_mod.buildtime_age({"buildtime": stamp}),
                               3 * 3600, delta=120)
        self.assertIsNone(roa_mod.buildtime_age({}))
        self.assertIsNone(roa_mod.buildtime_age({"buildtime": "garbage"}))

    def test_report_flags_reused_cache(self):
        from ipmlib.rov_report import render
        text = render([], {"buildtime": "2026-09-12T01:27:57Z",
                           "from_cache": True, "cache_age_sec": 563 * 60},
                      "whois.test")
        self.assertIn("复用了 563 分钟前的本地缓存", text)
        self.assertIn("⚠", text)

    def test_report_flags_stale_source(self):
        from ipmlib.rov_report import render
        text = render([], {"buildtime": "2020-01-01T00:00:00Z",
                           "from_cache": False}, "whois.test")
        self.assertIn("数据源偏旧", text)

    def test_report_says_freshly_downloaded(self):
        import datetime
        from ipmlib.rov_report import render
        now = datetime.datetime.now(datetime.timezone.utc)
        stamp = (now - datetime.timedelta(minutes=12)).strftime("%Y-%m-%dT%H:%M:%SZ")
        text = render([], {"buildtime": stamp, "from_cache": False}, "whois.test")
        self.assertIn("本次重新下载", text)
        self.assertIn("12 分钟前", text)
        self.assertNotIn("数据源偏旧", text)


class TestRovReport(unittest.TestCase):
    def test_renders_all_sections(self):
        from ipmlib.rov_report import render
        rows = [(net("218.30.33.0/24"), 4134), (net("203.0.113.0/24"), 65000),
                (net("218.30.37.0/24"), None)]
        vrps = [vrp("218.30.33.0/24", 4134, 24), vrp("218.30.0.0/15", 4134, 15)]
        text = render(evaluate(rows, vrps, {}, {}), {"buildtime": "x"}, "whois.test")
        for token in ("ROA / IRR 授权校验", "ROA-MATCH", "NO-AUTH", "NOT-ANNOUNCED",
                      "ROA 到期"):
            self.assertIn(token, text)

    def _render(self, *pairs):
        """pairs: (前缀, 剩余天数[, origin]) —— origin 传 None 表示未广播。"""
        from ipmlib.rov_report import render
        vrps, rows = [], []
        for item in pairs:
            prefix, days = item[0], item[1]
            origin = item[2] if len(item) > 2 else 65000
            vrps.append(vrp(prefix, 65000, int(prefix.split("/")[1]),
                            valid_to=_soon(days)))
            rows.append((net(prefix), origin))
        return render(evaluate(rows, vrps, {}, {}),
                      {"buildtime": "x", "expiry_kind": "cert"}, "whois.test")

    def test_expiry_warning_section_appears(self):
        text = self._render(("10.0.0.0/24", 3))
        self.assertIn("剩3天", text)      # 向上取整，不能显示成「剩2天」

    def test_critical_block_comes_before_summary(self):
        """14 天内的必须单独成块，且排在总体结果前面。"""
        text = self._render(("10.0.0.0/24", 5), ("10.0.1.0/24", 200))
        self.assertIn("紧急", text)
        self.assertLess(text.index("紧急"), text.index("一、总体结果"))
        self.assertIn("10.0.0.0/24", text.split("一、总体结果")[0])

    def test_critical_and_warn_tiers_separated(self):
        text = self._render(("10.0.0.0/24", 5), ("10.0.1.0/24", 22))
        head, rest = text.split("ROA 到期预警（14~30 天）")
        self.assertIn("10.0.0.0/24", head)      # 5 天 -> 紧急块
        self.assertNotIn("10.0.1.0/24", head)   # 22 天 -> 次级预警
        self.assertIn("10.0.1.0/24", rest)

    def test_expired_counted_and_labelled(self):
        text = self._render(("10.0.0.0/24", -3))
        self.assertIn("已过期", text)
        self.assertIn("其中 1 条已过期", text)
        self.assertIn("已过期 3 天", text)      # 不能写成「-3 天后到期」

    def test_no_alert_block_when_all_far_out(self):
        text = self._render(("10.0.0.0/24", 200))
        self.assertNotIn("紧急", text)
        self.assertNotIn("ROA 到期预警", text)

    def test_unannounced_prefix_never_alerts(self):
        """未广播前缀的 ROA 过期不影响现网，不能挤占告警位。"""
        text = self._render(("10.0.0.0/24", 3, None))
        self.assertNotIn("紧急", text)
        self.assertNotIn("ROA 到期预警", text)
        self.assertIn("不计入上面的告警", text)

    def test_announced_alerts_while_unannounced_only_noted(self):
        text = self._render(("10.0.0.0/24", 3), ("10.0.1.0/24", 2, None))
        head = text.split("一、总体结果")[0]
        self.assertIn("10.0.0.0/24", head)       # 已广播 -> 进紧急块
        self.assertNotIn("10.0.1.0/24", head)    # 未广播 -> 不进
        self.assertIn("另有 1 条未广播前缀", text)

    def test_overview_counts_announced_only(self):
        text = self._render(("10.0.0.0/24", 100), ("10.0.1.0/24", 5, None))
        self.assertIn("已广播且有 ROA 覆盖的 1 条", text)
        self.assertIn("最早到期：100 天后", text)   # 不能被未广播的 5 天带偏

    def test_subject_calls_out_critical_tier(self):
        from ipmlib.rov_report import subject_line
        vrps = [vrp("10.0.0.0/24", 65000, 24, valid_to=_soon(5)),
                vrp("10.0.1.0/24", 65000, 24, valid_to=_soon(22))]
        rows = [(net("10.0.0.0/24"), 65000), (net("10.0.1.0/24"), 65000)]
        subj = subject_line(evaluate(rows, vrps, {}, {}))
        self.assertIn("1 条 ROA 14 天内到期", subj)
        self.assertIn("1 条 ROA 30 天内到期", subj)

    def test_subject_ignores_unannounced_expiry(self):
        from ipmlib.rov_report import subject_line
        vrps = [vrp("10.0.0.0/24", 65000, 24, valid_to=_soon(2))]
        subj = subject_line(evaluate([(net("10.0.0.0/24"), None)], vrps, {}, {}))
        self.assertNotIn("⚠", subj)
        self.assertIn("正常", subj)

    def test_subject_says_expired_when_all_critical_are_expired(self):
        from ipmlib.rov_report import subject_line
        vrps = [vrp("10.0.0.0/24", 65000, 24, valid_to=_soon(-1))]
        subj = subject_line(evaluate([(net("10.0.0.0/24"), 65000)], vrps, {}, {}))
        self.assertIn("已过期", subj)

    def test_chain_expiry_caveat_shown(self):
        from ipmlib.rov_report import render
        text = render(evaluate([(net("10.0.0.0/24"), 65000)], [], {}, {}),
                      {"buildtime": "x", "expiry_kind": "chain"}, "whois.test")
        self.assertIn("不代表 ROA 真的快过期", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
