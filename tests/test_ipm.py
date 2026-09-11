"""ipm 统计功能的单元测试：python3 -m unittest discover -s tests"""

import ipaddress
import sys
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from ipmlib.cleaner import clean_config, render_line
from ipmlib.parsers import DIALECTS, detect_platform, parse_blocks, parse_junos
from ipmlib.stats import (build_report, load_prefixes, split_prefix,
                          split_report, unregistered_blocks)


class TestCleaner(unittest.TestCase):
    @staticmethod
    def _xr_pager(payload):
        """还原 IOS XR 的分页序列：打出 " --More-- " 后用退格逐字符擦掉，再打正文。"""
        prompt = " --More-- "
        return prompt + "\x08 \x08" * len(prompt) + payload + "\r"

    def test_more_prompt_with_backspaces(self):
        self.assertEqual(render_line(self._xr_pager("!")), "!")

    def test_more_prompt_preserves_indent(self):
        # 还原后必须保留块内缩进，否则 IOS XR 的层级会被破坏
        line = render_line(self._xr_pager(" description foo"))
        self.assertEqual(line, " description foo")

    def test_junos_more_with_cr_overwrite(self):
        raw = "---(more 2%)---\r        \rset interfaces xe-0/0/0 unit 0\r"
        self.assertEqual(render_line(raw), "set interfaces xe-0/0/0 unit 0")

    def test_huawei_csi_cursor_back(self):
        # 华为 VRP 用 ESC[16D 把光标退回行首，再用空格盖掉分页提示
        prompt = "  ---- More ----"
        raw = prompt + "\x1b[%dD" % len(prompt) + " " * len(prompt) \
            + "\x1b[%dD" % len(prompt) + " ip address 1.1.1.1 255.255.255.0\r"
        self.assertEqual(render_line(raw), " ip address 1.1.1.1 255.255.255.0")

    def test_csi_color_codes_stripped(self):
        self.assertEqual(render_line("\x1b[1;32mhello\x1b[0m"), "hello")

    def test_plain_lines_untouched(self):
        self.assertEqual(clean_config("a\n b\n"), ["a", " b", ""])


XR_SAMPLE = """!! IOS XR Configuration 7.11.2
hostname RTR-A
interface Loopback0
 description IP=10.0.0.1/32 For Global Routing
 ipv4 address 10.0.0.1 255.255.255.255
 ipv6 address 2001:db8::1/128
!
interface TenGigE0/0/0/1
 description [TRANSIT] DEST=peer
 vrf CN2-GIA
 ipv4 address 10.1.1.1 255.255.255.252
 shutdown
!
interface preconfigure TenGigE0/9/9/9
 ipv4 address 10.2.2.1 255.255.255.254
!
interface MgmtEth0/RSP0/CPU0/0
 ipv4 address dhcp
!
group Inband
 control-plane
  management-plane
   inband
    interface 'TenGigE.*'
     allow SSH peer
      address ipv4 192.0.2.0/24
     !
    !
   !
  !
 !
end-group
"""


class TestIosXrParser(unittest.TestCase):
    def setUp(self):
        _, self.entries = parse_blocks(XR_SAMPLE.split("\n"), "rtr-a.log",
                                       DIALECTS["iosxr"])

    def test_hostname_and_count(self):
        self.assertEqual({e.device for e in self.entries}, {"RTR-A"})
        # 4 条真实地址：lo0 v4+v6、TenGig v4、preconfigure v4；dhcp 不算
        self.assertEqual(len(self.entries), 4)

    def test_mask_converted_to_network(self):
        lo = next(e for e in self.entries if e.address == "10.0.0.1")
        self.assertEqual(lo.network, ipaddress.ip_network("10.0.0.1/32"))
        te = next(e for e in self.entries if e.address == "10.1.1.1")
        self.assertEqual(te.network, ipaddress.ip_network("10.1.1.0/30"))

    def test_vrf_description_and_shutdown(self):
        te = next(e for e in self.entries if e.address == "10.1.1.1")
        self.assertEqual(te.vrf, "CN2-GIA")
        self.assertTrue(te.shutdown)
        self.assertIn("[TRANSIT]", te.description)

    def test_preconfigure_interface_counted(self):
        pre = next(e for e in self.entries if e.address == "10.2.2.1")
        self.assertTrue(pre.preconfigure)
        self.assertEqual(pre.interface, "TenGigE0/9/9/9")

    def test_nested_group_block_not_parsed_as_interface(self):
        # group 里的 `address ipv4 192.0.2.0/24` 是 ACL 白名单，不是接口地址
        self.assertNotIn("192.0.2.0", [e.address for e in self.entries])

    def test_dhcp_address_skipped(self):
        self.assertNotIn("dhcp", [e.address for e in self.entries])


JUNOS_SAMPLE = """set version 23.4R2
set groups re0 system host-name RTR-B
set groups re0 interfaces fxp0 unit 0 family inet address 172.16.0.1/24
set groups re9 interfaces fxp1 unit 0 family inet address 172.31.0.1/24
set apply-groups re0
set system host-name RTR-B
set interfaces xe-0/0/0 unit 0 description "[BB] DEST=RTR-A IP=10.1.1.2/30"
set interfaces xe-0/0/0 unit 0 family inet address 10.1.1.2/30
set interfaces xe-0/0/0 unit 0 family inet6 address 2001:db8:1::2/127
set interfaces xe-0/0/1 disable
set interfaces xe-0/0/1 unit 0 family inet address 10.3.3.1/31
set routing-instances mgmt interface xe-0/0/0.0
"""


class TestJunosParser(unittest.TestCase):
    def setUp(self):
        _, self.entries = parse_junos(JUNOS_SAMPLE.split("\n"), "rtr-b.log")

    def test_hostname(self):
        self.assertEqual({e.device for e in self.entries}, {"RTR-B"})

    def test_unapplied_group_excluded(self):
        addrs = {e.address for e in self.entries}
        self.assertIn("172.16.0.1", addrs)      # re0 已 apply
        self.assertNotIn("172.31.0.1", addrs)   # re9 未 apply，地址未生效

    def test_description_and_unit_key(self):
        e = next(e for e in self.entries if e.address == "10.1.1.2")
        self.assertEqual(e.interface, "xe-0/0/0.0")
        self.assertIn("[BB]", e.description)
        self.assertEqual(e.network, ipaddress.ip_network("10.1.1.0/30"))

    def test_routing_instance_as_vrf(self):
        e = next(e for e in self.entries if e.address == "10.1.1.2")
        self.assertEqual(e.vrf, "mgmt")

    def test_disabled_interface_flagged(self):
        e = next(e for e in self.entries if e.address == "10.3.3.1")
        self.assertTrue(e.shutdown)

    def test_inet6_family(self):
        e = next(e for e in self.entries if e.family == "ipv6")
        self.assertEqual(e.network, ipaddress.ip_network("2001:db8:1::2/127"))


IOS_SAMPLE = """hostname RTR-IOS
interface Loopback1
 description For Management_IPv6
 no ip address
 ipv6 address 2001:DB8::84/128
!
interface GigabitEthernet0/0/1
 description [BB] DEST=peer
 vrf forwarding Mgmt-intf
 ip address 10.5.5.1 255.255.255.252
 shutdown
!
interface GigabitEthernet0/0/2
 no ip address
 negotiation auto
!
"""

NXOS_SAMPLE = """hostname RTR-NX
vdc RTR-NX id 1
interface Vlan2
  description [MGMT] DEST=peer
  no shutdown
  ip address 69.163.120.217/31

interface Ethernet1/1

interface Ethernet1/2
  vrf member management
  ip address 10.9.9.1/24
"""

VRP_SAMPLE = """!Software Version V800R011C10SPC100
sysname RTR-HW
#
interface Eth-Trunk1.2321
 vlan-type dot1q 2321
 description To Level3-AS3549-T
 ipv6 enable
 ip address 64.215.114.134 255.255.255.252
 ipv6 address 2001:450:2002:236::F6/126
#
interface GigabitEthernet0/0/0
 ip binding vpn-instance CTVPN1-CTG
 ip address 10.7.7.1 255.255.255.0
 shutdown
#
"""


class TestOtherDialects(unittest.TestCase):
    def _parse(self, sample, dialect):
        return parse_blocks(sample.split("\n"), "x.log", DIALECTS[dialect])

    def test_ios_ip_address_with_mask(self):
        dev, entries = self._parse(IOS_SAMPLE, "ios")
        self.assertEqual(dev, "RTR-IOS")
        v4 = [e for e in entries if e.family == "ipv4"]
        self.assertEqual(len(v4), 1)
        self.assertEqual(v4[0].network, ipaddress.ip_network("10.5.5.0/30"))
        self.assertEqual(v4[0].vrf, "Mgmt-intf")
        self.assertTrue(v4[0].shutdown)

    def test_ios_no_ip_address_not_matched(self):
        # ` no ip address` 是「关掉地址」，不能当成一条地址
        _, entries = self._parse(IOS_SAMPLE, "ios")
        self.assertEqual([e.interface for e in entries if e.family == "ipv4"],
                         ["GigabitEthernet0/0/1"])

    def test_nxos_cidr_address(self):
        dev, entries = self._parse(NXOS_SAMPLE, "nxos")
        self.assertEqual(dev, "RTR-NX")
        nets = {str(e.network) for e in entries}
        self.assertEqual(nets, {"69.163.120.216/31", "10.9.9.0/24"})

    def test_nxos_vrf_member(self):
        _, entries = self._parse(NXOS_SAMPLE, "nxos")
        e = next(e for e in entries if e.address == "10.9.9.1")
        self.assertEqual(e.vrf, "management")

    def test_nxos_blank_line_separated_blocks(self):
        # NX-OS 用空行分隔接口块，Vlan2 的地址不能被算到 Ethernet1/2 上
        _, entries = self._parse(NXOS_SAMPLE, "nxos")
        e = next(e for e in entries if e.address == "69.163.120.217")
        self.assertEqual(e.interface, "Vlan2")

    def test_vrp_sysname_and_addresses(self):
        dev, entries = self._parse(VRP_SAMPLE, "vrp")
        self.assertEqual(dev, "RTR-HW")
        self.assertEqual({str(e.network) for e in entries},
                         {"64.215.114.132/30", "2001:450:2002:236::f4/126",
                          "10.7.7.0/24"})

    def test_vrp_vpn_instance_as_vrf(self):
        _, entries = self._parse(VRP_SAMPLE, "vrp")
        e = next(e for e in entries if e.address == "10.7.7.1")
        self.assertEqual(e.vrf, "CTVPN1-CTG")
        self.assertTrue(e.shutdown)

    def test_platform_detection(self):
        self.assertEqual(detect_platform(IOS_SAMPLE.split("\n")), "ios")
        self.assertEqual(detect_platform(NXOS_SAMPLE.split("\n")), "nxos")
        self.assertEqual(detect_platform(VRP_SAMPLE.split("\n")), "vrp")
        self.assertEqual(detect_platform(XR_SAMPLE.split("\n")), "iosxr")
        self.assertEqual(detect_platform(JUNOS_SAMPLE.split("\n")), "junos")


class TestStats(unittest.TestCase):
    def _report(self, prefixes, lines):
        _, entries = parse_blocks(lines.split("\n"), "x.log", DIALECTS["iosxr"])
        return build_report(entries, [ipaddress.ip_network(p) for p in prefixes])

    def test_empty_prefix_list_is_ok(self):
        cfg = "hostname R\ninterface Te0/0\n ipv4 address 10.0.0.1 255.255.255.252\n!\n"
        rep = self._report([], cfg)
        self.assertEqual(rep.prefix_stats, [])
        self.assertEqual(len(rep.outside), 1)

    def test_whole_subnet_counted_not_single_ip(self):
        cfg = "hostname R\ninterface Te0/0/0/0\n ipv4 address 10.0.0.1 255.255.255.252\n!\n"
        st = self._report(["10.0.0.0/24"], cfg).prefix_stats[0]
        self.assertEqual(st.used, 4)          # /30 整条算占用，而不是 1 个 IP
        self.assertEqual(st.capacity, 256)
        self.assertEqual(st.free, 252)

    def test_same_subnet_on_two_interfaces_counted_once(self):
        cfg = ("hostname R\ninterface Lo0\n ipv4 address 10.0.0.1 255.255.255.255\n!\n"
               "interface Lo1\n vrf V\n ipv4 address 10.0.0.1 255.255.255.255\n!\n")
        rep = self._report(["10.0.0.0/24"], cfg)
        st = rep.prefix_stats[0]
        self.assertEqual(st.used, 1)
        self.assertEqual(len(st.subnets), 1)
        self.assertEqual(len(st.subnets[0].entries), 2)   # 明细里两处都要留痕

    def test_nested_subnets_not_double_counted(self):
        cfg = ("hostname R\ninterface Te0/0\n ipv4 address 10.0.1.1 255.255.255.0\n!\n"
               "interface Lo0\n ipv4 address 10.0.1.9 255.255.255.255\n!\n")
        st = self._report(["10.0.0.0/16"], cfg).prefix_stats[0]
        self.assertEqual(st.used, 256)        # /32 落在 /24 内，折叠后只算 256

    def test_most_specific_prefix_wins(self):
        cfg = "hostname R\ninterface Te0/0\n ipv4 address 10.0.1.1 255.255.255.252\n!\n"
        rep = self._report(["10.0.0.0/8", "10.0.1.0/24"], cfg)
        by = {str(s.prefix): s for s in rep.prefix_stats}
        self.assertEqual(by["10.0.1.0/24"].used, 4)
        self.assertEqual(by["10.0.0.0/8"].used, 0)

    def test_address_outside_owned_prefixes(self):
        cfg = "hostname R\ninterface Te0/0\n ipv4 address 203.0.113.1 255.255.255.252\n!\n"
        rep = self._report(["10.0.0.0/8"], cfg)
        self.assertEqual(rep.prefix_stats[0].used, 0)
        self.assertEqual([str(u.network) for u in rep.outside], ["203.0.113.0/30"])

    def test_partial_overlap_flagged(self):
        # 接口子网反包含自有前缀，属于配置异常，要单独提示而不是静默计入
        cfg = "hostname R\ninterface Te0/0\n ipv4 address 10.0.0.1 255.255.0.0\n!\n"
        rep = self._report(["10.0.1.0/24"], cfg)
        self.assertEqual([str(u.network) for u in rep.overlapping], ["10.0.0.0/16"])
        self.assertEqual(rep.prefix_stats[0].used, 0)

    def test_ipv6_counted_in_48_blocks(self):
        # IPv6 以 /48 为统计单位：整条 /48 里配再多链路也只算 1 个单位
        cfg = ("hostname R\ninterface Te0/0\n ipv6 address 2001:db8:0:1::1/127\n!\n"
               "interface Te0/1\n ipv6 address 2001:db8:0:1::9/127\n!\n"
               "interface Te0/2\n ipv6 address 2001:db8:0:2::1/127\n!\n")
        st = self._report(["2001:db8::/48"], cfg).prefix_stats[0]
        self.assertEqual(st.capacity, 1)
        self.assertEqual(st.used, 1)

    def test_ipv6_capacity_scales_with_prefix_length(self):
        rep = self._report(["2001:db8::/32"], "hostname R\n")
        self.assertEqual(rep.prefix_stats[0].capacity, 65536)  # /32 含 65536 个 /48

    def test_ipv6_used_counts_distinct_48s(self):
        cfg = ("hostname R\ninterface Te0/0\n ipv6 address 2001:db8:1::1/127\n!\n"
               "interface Te0/1\n ipv6 address 2001:db8:1:5::1/127\n!\n"
               "interface Te0/2\n ipv6 address 2001:db8:9::1/127\n!\n")
        st = self._report(["2001:db8::/32"], cfg).prefix_stats[0]
        self.assertEqual(st.used, 2)   # 前两条同在 2001:db8:1::/48

    def test_suspicious_short_mask_warned(self):
        # 互联口配了 /12 基本是掩码打错，要报出来而不是默默算进占用
        cfg = "hostname R\ninterface Te0/0\n ipv6 address 240e:20:1800::1/12\n!\n"
        rep = self._report([], cfg)
        self.assertTrue(any("疑似掩码写错" in w for w in rep.warnings), rep.warnings)

    def test_short_v6_mask_does_not_break_report(self):
        # /12 比 /32 还短，按 /32 归并时不能把 supernet() 调爆
        from ipmlib.report import render_text
        cfg = "hostname R\ninterface Te0/0\n ipv6 address 240e:20:1800::1/12\n!\n"
        self.assertIn("2400::/12", render_text(self._report([], cfg)))

    def test_v4_and_v6_do_not_mix(self):
        cfg = ("hostname R\ninterface Te0/0\n ipv4 address 10.0.0.1 255.255.255.252\n"
               " ipv6 address 2001:db8::1/127\n!\n")
        rep = self._report(["10.0.0.0/24"], cfg)
        self.assertEqual(rep.prefix_stats[0].used, 4)
        self.assertEqual([str(u.network) for u in rep.outside], ["2001:db8::/127"])


class TestSplitBlocks(unittest.TestCase):
    """把自有前缀切成 /24 逐块统计。"""

    def _report(self, prefixes, lines):
        _, entries = parse_blocks(lines.split("\n"), "x.log", DIALECTS["iosxr"])
        return build_report(entries, [ipaddress.ip_network(p) for p in prefixes])

    def test_prefix_split_into_expected_block_count(self):
        rep = self._report(["10.0.0.0/22"], "hostname R\n")
        blocks = split_prefix(rep.prefix_stats[0], 24)
        self.assertEqual([str(b.block) for b in blocks],
                         ["10.0.0.0/24", "10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"])
        self.assertTrue(all(b.empty and b.used == 0 for b in blocks))

    def test_usage_lands_in_the_right_block(self):
        cfg = ("hostname R\ninterface Te0/0\n ipv4 address 10.0.2.1 255.255.255.252\n!\n")
        blocks = split_prefix(self._report(["10.0.0.0/22"], cfg).prefix_stats[0], 24)
        by = {str(b.block): b for b in blocks}
        self.assertEqual(by["10.0.2.0/24"].used, 4)
        self.assertEqual(by["10.0.2.0/24"].free, 252)
        self.assertEqual(sum(b.used for b in blocks if str(b.block) != "10.0.2.0/24"), 0)

    def test_block_totals_match_prefix_total(self):
        cfg = ("hostname R\ninterface Te0/0\n ipv4 address 10.0.1.1 255.255.255.252\n!\n"
               "interface Te0/1\n ipv4 address 10.0.3.5 255.255.255.248\n!\n")
        st = self._report(["10.0.0.0/22"], cfg).prefix_stats[0]
        self.assertEqual(sum(b.used for b in split_prefix(st, 24)), st.used)

    def test_subnet_spanning_blocks_is_apportioned(self):
        # 一条 /22 分给客户时，占用要按交集摊到它覆盖的每个 /24
        cfg = "hostname R\ninterface Te0/0\n ipv4 address 10.0.0.1 255.255.252.0\n!\n"
        blocks = split_prefix(self._report(["10.0.0.0/22"], cfg).prefix_stats[0], 24)
        self.assertEqual([b.used for b in blocks], [256, 256, 256, 256])
        self.assertTrue(all(len(b.subnets) == 1 for b in blocks))

    def test_prefix_longer_than_split_len_kept_whole(self):
        # /25 切不出 /24，整条作为一块返回而不是报错
        rep = self._report(["10.0.0.0/25"], "hostname R\n")
        blocks = split_prefix(rep.prefix_stats[0], 24)
        self.assertEqual([str(b.block) for b in blocks], ["10.0.0.0/25"])

    def test_ipv6_splits_into_48_by_default(self):
        cfg = ("hostname R\ninterface Te0/0\n ipv6 address 2001:db8:1::1/127\n!\n"
               "interface Te0/1\n ipv6 address 2001:db8:9::1/127\n!\n")
        blocks = split_prefix(self._report(["2001:db8::/32"], cfg).prefix_stats[0])
        # /32 能切出 65536 个 /48，超过枚举上限，只列出有使用的块
        self.assertEqual([str(b.block) for b in blocks],
                         ["2001:db8:1::/48", "2001:db8:9::/48"])
        self.assertTrue(all(b.used == 1 and b.capacity == 1 for b in blocks))

    def test_ipv6_small_prefix_fully_enumerated(self):
        # /36 只切出 4096 个 /48，在枚举上限内，空块也要列出来
        rep = self._report(["2602:fdda::/36"], "hostname R\n")
        blocks = split_prefix(rep.prefix_stats[0])
        self.assertEqual(len(blocks), 4096)
        self.assertTrue(all(b.empty for b in blocks))

    def test_ipv6_block_totals_match_prefix_total(self):
        cfg = ("hostname R\ninterface Te0/0\n ipv6 address 2001:db8:1::1/127\n!\n"
               "interface Te0/1\n ipv6 address 2001:db8:1:5::1/127\n!\n"
               "interface Te0/2\n ipv6 address 2001:db8:9::1/127\n!\n")
        st = self._report(["2001:db8::/32"], cfg).prefix_stats[0]
        self.assertEqual(sum(b.used for b in split_prefix(st)), st.used)

    def test_total_blocks_helper(self):
        from ipmlib.stats import total_blocks
        self.assertEqual(total_blocks(ipaddress.ip_network("10.0.0.0/19"), 24), 32)
        self.assertEqual(total_blocks(ipaddress.ip_network("2605:9d80::/32"), 48), 65536)
        self.assertEqual(total_blocks(ipaddress.ip_network("10.0.0.0/25"), 24), 1)

    def test_custom_split_len(self):
        rep = self._report(["10.0.0.0/24"], "hostname R\n")
        self.assertEqual(len(split_prefix(rep.prefix_stats[0], 26)), 4)


class TestUnregisteredBlocks(unittest.TestCase):
    """prefix.list 之外的地址也要按 /24 / /48 归并出来。"""

    def _report(self, prefixes, lines):
        _, entries = parse_blocks(lines.split("\n"), "x.log", DIALECTS["iosxr"])
        return build_report(entries, [ipaddress.ip_network(p) for p in prefixes])

    def test_v4_outside_grouped_into_24(self):
        cfg = ("hostname R\ninterface Te0/0\n ipv4 address 203.0.113.1 255.255.255.252\n!\n"
               "interface Te0/1\n ipv4 address 203.0.113.9 255.255.255.252\n!\n"
               "interface Te0/2\n ipv4 address 198.51.100.1 255.255.255.252\n!\n")
        blocks = unregistered_blocks(self._report(["10.0.0.0/8"], cfg), 4)
        self.assertEqual([str(b.block) for b in blocks],
                         ["198.51.100.0/24", "203.0.113.0/24"])
        by = {str(b.block): b for b in blocks}
        self.assertEqual(len(by["203.0.113.0/24"].subnets), 2)
        self.assertEqual(by["203.0.113.0/24"].used, 8)

    def test_v6_outside_grouped_into_48(self):
        cfg = ("hostname R\ninterface Te0/0\n ipv6 address 2001:db8:1::1/127\n!\n"
               "interface Te0/1\n ipv6 address 2001:db8:1:9::1/127\n!\n")
        blocks = unregistered_blocks(self._report([], cfg), 6)
        self.assertEqual([str(b.block) for b in blocks], ["2001:db8:1::/48"])
        self.assertEqual(len(blocks[0].subnets), 2)

    def test_subnet_larger_than_block_kept_whole(self):
        # IX 的 /20 LAN 归并不到 /24，按它自己成块
        cfg = "hostname R\ninterface Te0/0\n ipv4 address 187.16.219.234 255.255.240.0\n!\n"
        blocks = unregistered_blocks(self._report(["10.0.0.0/8"], cfg), 4)
        self.assertEqual([str(b.block) for b in blocks], ["187.16.208.0/20"])

    def test_unregistered_blocks_marked_without_owner(self):
        cfg = "hostname R\ninterface Te0/0\n ipv4 address 203.0.113.1 255.255.255.252\n!\n"
        blocks = unregistered_blocks(self._report(["10.0.0.0/8"], cfg), 4)
        self.assertIsNone(blocks[0].prefix)

    def test_owned_addresses_never_appear_as_unregistered(self):
        cfg = ("hostname R\ninterface Te0/0\n ipv4 address 10.0.0.1 255.255.255.252\n!\n"
               "interface Te0/1\n ipv4 address 203.0.113.1 255.255.255.252\n!\n")
        rep = self._report(["10.0.0.0/8"], cfg)
        blocks = unregistered_blocks(rep, 4)
        self.assertEqual([str(b.block) for b in blocks], ["203.0.113.0/24"])
        self.assertEqual(rep.prefix_stats[0].used, 4)


class TestRoleInference(unittest.TestCase):
    """CN2 / 163 设备的描述不带方括号标签，靠命名约定推断角色。"""

    def _entry(self, desc, interface="Te0/0", vrf=""):
        from ipmlib.parsers import AddrEntry
        return AddrEntry("R", "x.log", "iosxr", interface, vrf, desc,
                         "ipv4", "10.0.0.1", ipaddress.ip_network("10.0.0.0/30"))

    def test_bracket_tag_wins(self):
        from ipmlib.report import role_of
        self.assertEqual(role_of(self._entry("[CUSTOMER] DEST=x")), "CUSTOMER")

    def test_asn_suffix_convention(self):
        from ipmlib.report import role_of
        self.assertEqual(role_of(self._entry("To Vodafone-AS1273-P 20GE")), "PEERING")
        self.assertEqual(role_of(self._entry("To Enfusion-AS14689-C 100M")), "CUSTOMER")
        self.assertEqual(role_of(self._entry("To Level3-AS3356-T GE-1")), "TRANSIT")

    def test_static_circuit_is_customer(self):
        from ipmlib.report import role_of
        self.assertEqual(role_of(self._entry("To MNJTech-STATIC-C 10M")), "CUSTOMER")

    def test_ctvpn_and_circuit_ids(self):
        from ipmlib.report import role_of
        self.assertEqual(role_of(self._entry("For Gap CTVPN55225A 64K-N")), "CUSTOMER")
        self.assertEqual(role_of(self._entry("x <Chicago-GIA-0001>")), "CUSTOMER")
        self.assertEqual(role_of(self._entry("y", vrf="CTVPN1-Apple")), "CUSTOMER")

    def test_loopback_fallback(self):
        from ipmlib.report import role_of
        self.assertEqual(role_of(self._entry("For Global Routing", "Loopback0")),
                         "LOOPBACK")

    def test_unknown_is_labeled_not_guessed(self):
        from ipmlib.report import role_of, UNLABELED
        self.assertEqual(role_of(self._entry("To Sao Paulo DNS SW-2 Gi1/1/1")),
                         UNLABELED)


class TestRealConfigs(unittest.TestCase):
    """跑一遍仓库里的真实采集文件，确保端到端不回归。"""

    @classmethod
    def setUpClass(cls):
        from ipmlib.parsers import parse_file
        cfg_dir = BASE / "running-config"
        if not cfg_dir.is_dir():
            raise unittest.SkipTest("没有 running-config 目录")
        cls.files = [parse_file(p) for p in sorted(cfg_dir.glob("*.log"))]
        entries = [e for f in cls.files for e in f.entries]
        cls.rep = build_report(entries, load_prefixes(BASE / "prefix.list"),
                               cls.files)

    def test_every_file_yields_addresses(self):
        """漏解析一整台设备只会让占用率悄悄偏低，必须挡住。"""
        empty = [f.name for f in self.files if not f.entries]
        self.assertEqual(empty, [], f"这些采集文件没解析出任何地址：{empty}")

    def test_no_hostname_fallback_to_filename(self):
        bad = [f.name for f in self.files if f.device == f.name]
        self.assertEqual(bad, [], f"这些文件没取到 hostname：{bad}")

    def test_platform_detection_is_stable(self):
        got = {f.name: f.platform for f in self.files}
        # 每种平台至少有一台被识别出来，避免某类方言整体退化成 iosxr
        self.assertEqual(set(got.values()) & {"iosxr", "ios", "nxos", "vrp", "junos"},
                         {"iosxr", "ios", "nxos", "vrp", "junos"})

    def test_every_entry_has_a_network(self):
        self.assertTrue(all(e.network is not None for e in self.rep.entries))

    def test_no_pager_residue_leaked_into_fields(self):
        for e in self.rep.entries:
            self.assertNotIn("More", e.interface)
            self.assertNotIn("more ", e.description)

    def test_used_never_exceeds_capacity(self):
        for st in self.rep.prefix_stats:
            self.assertLessEqual(st.used, st.capacity, str(st.prefix))

    def test_report_renders_without_error(self):
        from ipmlib.report import render_text
        text = render_text(self.rep)
        self.assertIn("IP 使用统计", text)
        self.assertIn("采集与解析覆盖", text)
        self.assertIn("IPv4 /24 粒度占用", text)

    def test_block_totals_reconcile_with_prefix_totals(self):
        """逐块已用之和必须等于前缀汇总的已用，否则两张表会互相打架。"""
        for family, plen in (("ipv4", 24), ("ipv6", 48)):
            per_prefix = sum(st.used for st in self.rep.by_family(family))
            per_block = sum(b.used for st in self.rep.by_family(family)
                            for b in split_prefix(st, plen))
            self.assertEqual(per_block, per_prefix, family)

    def test_every_subnet_is_either_owned_or_unregistered(self):
        """每条子网要么落在自有前缀里，要么出现在未登记块里，不能凭空消失。"""
        owned = {s.network for st in self.rep.prefix_stats for s in st.subnets}
        unreg = {u.network for v in (4, 6)
                 for b in unregistered_blocks(self.rep, v) for u in b.subnets}
        allnets = {e.network for e in self.rep.entries}
        self.assertEqual(allnets, owned | unreg)
        self.assertEqual(owned & unreg, set())

    def test_ipv6_prefixes_are_registered(self):
        # prefix.list 里有 v6 前缀时，v6 汇总表不能是空的
        self.assertTrue(self.rep.by_family("ipv6"))
        self.assertIn("IPv6 /48 粒度占用", __import__(
            "ipmlib.report", fromlist=["render_text"]).render_text(self.rep))

    def test_no_overlap_anomalies_in_current_configs(self):
        self.assertEqual(self.rep.overlapping, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
