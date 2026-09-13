"""在用地址扫描的单元测试（不真的调用 nmap，用假 runner 注入输出）。"""

import ipaddress
import sys
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from ipmlib import scan as scan_mod
from ipmlib.scan import BlockScan, build_args, parse_alive, scan, split_blocks
from ipmlib.scan_report import render, subject_line


def net(s):
    return ipaddress.ip_network(s)


GREPABLE = """# Nmap 7.92 scan initiated
Host: 10.0.0.5 ()\tStatus: Up
Host: 10.0.0.9 ()\tStatus: Down
Host: 10.0.1.7 (host.example)\tStatus: Up
Host: 10.0.1.8 ()\tStatus: Up
# Nmap done at ...
"""


class TestParse(unittest.TestCase):
    def test_only_up_hosts_kept(self):
        self.assertEqual([str(x) for x in parse_alive(GREPABLE)],
                         ["10.0.0.5", "10.0.1.7", "10.0.1.8"])

    def test_empty_output(self):
        self.assertEqual(parse_alive(""), [])

    def test_garbage_addresses_skipped(self):
        self.assertEqual(parse_alive("Host: not-an-ip ()\tStatus: Up"), [])


class TestSplitBlocks(unittest.TestCase):
    def test_prefix_split_into_24s(self):
        self.assertEqual(len(split_blocks(net("10.0.0.0/20"))), 16)

    def test_prefix_more_specific_than_block_kept_whole(self):
        self.assertEqual([str(b) for b in split_blocks(net("10.0.0.0/28"))],
                         ["10.0.0.0/28"])

    def test_custom_block_len(self):
        self.assertEqual(len(split_blocks(net("10.0.0.0/24"), 26)), 4)


class TestScan(unittest.TestCase):
    def _runner(self, output="", raises=None):
        calls = []

        def runner(target, args, timeout):
            calls.append((target, args, timeout))
            if raises:
                raise raises
            return output
        runner.calls = calls
        return runner

    def test_alive_bucketed_into_right_blocks(self):
        runner = self._runner(GREPABLE)
        res = scan([net("10.0.0.0/23")], runner=runner)
        by = {str(b.block): b for b in res.blocks}
        self.assertEqual([str(x) for x in by["10.0.0.0/24"].alive], ["10.0.0.5"])
        self.assertEqual([str(x) for x in by["10.0.1.0/24"].alive],
                         ["10.0.1.7", "10.0.1.8"])
        self.assertEqual(res.alive_count, 3)
        self.assertEqual(res.total, 512)

    def test_empty_blocks_still_reported(self):
        """没有在用的 /24 也必须出现在结果里，否则「未探测到在用地址」的段会凭空消失。"""
        res = scan([net("10.0.0.0/22")], runner=self._runner(GREPABLE))
        self.assertEqual(len(res.blocks), 4)
        self.assertEqual(sum(1 for b in res.blocks if not b.alive), 2)

    def test_one_nmap_call_per_prefix(self):
        # 一次扫整条前缀，而不是逐个 /24 起进程
        runner = self._runner(GREPABLE)
        scan([net("10.0.0.0/22"), net("10.9.0.0/24")], runner=runner)
        self.assertEqual([c[0] for c in runner.calls],
                         ["10.0.0.0/22", "10.9.0.0/24"])

    def test_tcp_probes_included_by_default(self):
        runner = self._runner()
        scan([net("10.0.0.0/24")], runner=runner)
        args = runner.calls[0][1]
        self.assertIn("-PS80,443,22", args)
        self.assertIn("-PE", args)

    def test_icmp_only_drops_tcp_probes(self):
        runner = self._runner()
        scan([net("10.0.0.0/24")], tcp=False, runner=runner)
        self.assertNotIn("-PS80,443,22", runner.calls[0][1])
        self.assertIn("-PE", runner.calls[0][1])

    def test_failure_recorded_not_raised(self):
        """一段扫描失败不该中断整轮，但必须显式记进 errors。"""
        res = scan([net("10.0.0.0/24")],
                   runner=self._runner(raises=RuntimeError("boom")))
        self.assertEqual(len(res.errors), 1)
        self.assertIn("boom", res.errors[0])
        self.assertEqual(res.alive_count, 0)
        self.assertEqual(len(res.blocks), 1)

    def test_timeout_recorded(self):
        import subprocess
        res = scan([net("10.0.0.0/24")], runner=self._runner(
            raises=subprocess.TimeoutExpired("nmap", 1)))
        self.assertIn("超时", res.errors[0])

    def test_ratio_math(self):
        b = BlockScan(net("10.0.0.0/24"), [ipaddress.ip_address("10.0.0.1")] * 8)
        self.assertEqual(b.total, 256)
        self.assertAlmostEqual(b.ratio, 8 / 256)


class TestScanReport(unittest.TestCase):
    def _result(self):
        return scan([net("10.0.0.0/23")],
                    runner=lambda t, a, o: GREPABLE)

    def test_report_sections(self):
        text = render(self._result())
        for token in ("IPv4 在用地址扫描", "一、总体结果", "二、按自有前缀汇总",
                      "有在用地址的 /24"):
            self.assertIn(token, text)

    def test_report_states_measurement_caveat(self):
        # 有响应即认定在用；但无响应不代表空闲，这条口径必须写在报表里
        text = render(self._result())
        self.assertIn("「在用」指该地址对探测有响应", text)
        self.assertIn("无响应不代表空闲", text)
        self.assertIn("下限", text)

    def test_empty_blocks_listed_compactly(self):
        res = scan([net("10.0.0.0/22")], runner=lambda t, a, o: GREPABLE)
        text = render(res)
        self.assertIn("未探测到在用地址的 /24（2 个）", text)
        self.assertIn("10.0.2.0/24", text)

    def test_errors_surface_in_report(self):
        res = scan([net("10.0.0.0/24")],
                   runner=lambda t, a, o: (_ for _ in ()).throw(
                       RuntimeError("nmap 挂了")))
        self.assertIn("⚠ 扫描异常", render(res))
        self.assertIn("nmap 挂了", render(res))

    def test_subject_has_counts(self):
        subj = subject_line(self._result())
        self.assertIn("在用 3/512", subj)
        self.assertNotIn("⚠", subj)

    def test_subject_flags_errors(self):
        res = scan([net("10.0.0.0/24")],
                   runner=lambda t, a, o: (_ for _ in ()).throw(
                       RuntimeError("x")))
        self.assertIn("⚠", subject_line(res))


if __name__ == "__main__":
    unittest.main(verbosity=2)
