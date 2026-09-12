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


def vrp(prefix, asn, maxlen):
    return Vrp(net(prefix), asn, maxlen, 0, "test")


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


class TestRovReport(unittest.TestCase):
    def test_renders_all_sections(self):
        from ipmlib.rov_report import render
        rows = [(net("218.30.33.0/24"), 4134), (net("203.0.113.0/24"), 65000),
                (net("218.30.37.0/24"), None)]
        vrps = [vrp("218.30.33.0/24", 4134, 24), vrp("218.30.0.0/15", 4134, 15)]
        text = render(evaluate(rows, vrps, {}, {}), {"buildtime": "x"}, "whois.test")
        for token in ("ROA / IRR 授权校验", "ROA-MATCH", "NO-AUTH", "NOT-ANNOUNCED"):
            self.assertIn(token, text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
