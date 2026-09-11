"""把统计结果渲染成终端报表（汇总 + 明细）。"""

from __future__ import annotations

import re
import unicodedata
from collections import Counter

from .stats import (DEFAULT_SPLIT, PrefixStat, Report, SubnetUse,
                    block_of, split_prefix, total_blocks,
                    unregistered_blocks)

_ROLE_RE = re.compile(r"^\[([A-Z0-9 _-]+)\]")
_LOOPBACK_RE = re.compile(r"^(loopback|lo)\d", re.I)

# CN2 / 163 侧的描述不带方括号标签，改用它们自己的命名约定：
# `To <对端>-AS<号>-P/-C/-T` 和 `To <客户>-STATIC-C`，后缀含义在全网一致。
_SUFFIX_RE = re.compile(r"(?:AS\d+|STATIC)-([PCT])\b")
_SUFFIX_ROLE = {"P": "PEERING", "C": "CUSTOMER", "T": "TRANSIT"}
# CTVPN 是 VPN 专线实例，GIA/DIA 是客户电路编号，两者都指向客户业务
_CUSTOMER_RE = re.compile(r"CTVPN|-GIA-|-DIA-")

UNLABELED = "未标注"


def role_of(entry) -> str:
    """判断一条接口地址的业务角色。

    优先用描述里的 `[TAG]` 标签；没有标签的设备再按 CN2/163 的命名约定推断；
    都推不出来时返回「未标注」，而不是硬套一个角色。
    """
    m = _ROLE_RE.match(entry.description)
    if m:
        return m.group(1).strip()
    m = _SUFFIX_RE.search(entry.description)
    if m:
        return _SUFFIX_ROLE[m.group(1)]
    if _CUSTOMER_RE.search(entry.description) or entry.vrf.startswith("CTVPN"):
        return "CUSTOMER"
    if _LOOPBACK_RE.match(entry.interface):
        return "LOOPBACK"
    return UNLABELED


# ---------------------------------------------------------------- 宽度对齐

def _width(s: str) -> int:
    return sum(2 if unicodedata.east_asian_width(c) in "WF" else 1 for c in s)


def _pad(s: str, width: int) -> str:
    return s + " " * max(0, width - _width(s))


def _trunc(s: str, width: int) -> str:
    if _width(s) <= width:
        return s
    out, used = [], 0
    for c in s:
        w = 2 if unicodedata.east_asian_width(c) in "WF" else 1
        if used + w > width - 1:
            break
        out.append(c)
        used += w
    return "".join(out) + "…"


def _rule(title: str, width: int = 96) -> str:
    head = f"── {title} "
    return head + "─" * max(0, width - _width(head))


# ---------------------------------------------------------------- 汇总表

_SUM_COLS = [("前缀", 20), ("容量", 10), ("已用", 9), ("空闲", 10),
             ("占用率", 8), ("子网数", 7), ("地址条目", 8)]


def _summary_table(stats: list[PrefixStat], unit: str) -> list[str]:
    if not stats:
        return ["  （prefix.list 中没有该协议族的前缀）"]

    lines = ["  " + "".join(_pad(n, w) for n, w in _SUM_COLS)]
    lines.append("  " + "-" * sum(w for _, w in _SUM_COLS))
    cap = used = subnets = items = 0
    for st in stats:
        n_items = sum(len(s.entries) for s in st.subnets)
        cap += st.capacity
        used += st.used
        subnets += len(st.subnets)
        items += n_items
        lines.append("  " + "".join(_pad(v, w) for v, (_, w) in zip(
            [str(st.prefix), f"{st.capacity:,}", f"{st.used:,}", f"{st.free:,}",
             f"{st.ratio * 100:.2f}%", str(len(st.subnets)), str(n_items)], _SUM_COLS)))
    lines.append("  " + "-" * sum(w for _, w in _SUM_COLS))
    ratio = used / cap * 100 if cap else 0.0
    lines.append("  " + "".join(_pad(v, w) for v, (_, w) in zip(
        ["合计", f"{cap:,}", f"{used:,}", f"{cap - used:,}",
         f"{ratio:.2f}%", str(subnets), str(items)], _SUM_COLS)))
    lines.append(f"  单位：{unit}")
    return lines


# ---------------------------------------------------------------- 明细表

_DESC_W = 42


def _det_cols(subnet_w: int) -> list:
    """子网列按本节最长的子网自适应——IPv6 比 IPv4 长得多，写死会被截断。"""
    return [("子网", max(21, subnet_w + 1)), ("角色", 10), ("设备", 21),
            ("接口", 24), ("VRF", 11), ("状态", 11), ("描述", _DESC_W)]


def net_width(uses) -> int:
    return max((len(str(u.network)) for u in uses), default=20)


def _detail_rows(use: SubnetUse, subnet_w: int) -> list[str]:
    cols = _det_cols(subnet_w)
    rows = []
    for i, e in enumerate(use.entries):
        flags = []
        if e.preconfigure:
            flags.append("预配")
        if e.shutdown:
            flags.append("shut")
        if e.secondary:
            flags.append("sec")
        values = [str(use.network) if i == 0 else "", role_of(e), e.device,
                  e.interface, e.vrf or "-", "/".join(flags) or "-",
                  e.description or "-"]
        cells = [_pad(_trunc(v, w), w) for v, (_, w) in zip(values[:-1], cols[:-1])]
        cells.append(_trunc(values[-1], _DESC_W))   # 末列不补空格，避免行尾拖白
        rows.append("    " + "".join(cells))
    return rows


def _detail_header(subnet_w: int) -> list[str]:
    cols = _det_cols(subnet_w)
    return ["    " + "".join(_pad(n, w) for n, w in cols).rstrip(),
            "    " + "-" * sum(w for _, w in cols)]


# ---------------------------------------------------------------- 总入口

def render_text(report: Report, show_detail: bool = True,
                show_outside: bool = True, show_inventory: bool = True,
                split_len: int = DEFAULT_SPLIT[4], hide_empty: bool = False,
                split_len6: int = DEFAULT_SPLIT[6]) -> str:
    v4 = [e for e in report.entries if e.family == "ipv4"]
    v6 = [e for e in report.entries if e.family == "ipv6"]
    nets = {e.network for e in report.entries}

    plats = Counter(f.platform for f in report.files)
    plat_txt = "、".join(f"{k} {v}" for k, v in plats.most_common()) or "-"

    out = ["=" * 96,
           "IP 使用统计 — 基于 router running-config",
           "=" * 96,
           f"采集文件  {len(report.files) or len(report.sources)} 个（{plat_txt}）",
           f"设  备    {len(report.devices)} 台",
           f"自有前缀  {len(report.prefix_stats)} 条（prefix.list）",
           f"地址条目  {len(report.entries)} 条（IPv4 {len(v4)} / IPv6 {len(v6)}），"
           f"去重后子网 {len(nets)} 条",
           "统计口径  以接口所在的整条子网计入占用；同一子网多处出现只计一次容量",
           ""]

    if report.warnings:
        out.append(_rule("⚠ 解析告警"))
        out.extend(f"  · {w}" for w in report.warnings)
        out.append("")

    out.append(_rule("一、IPv4 自有前缀占用汇总"))
    out.extend(_summary_table(report.by_family("ipv4"), "IPv4 地址数"))
    out.append("")

    blocks = [b for st in report.by_family("ipv4")
              for b in split_prefix(st, split_len)]
    out.append(_rule(f"二、IPv4 /{split_len} 粒度占用"))
    out.append("  【自有前缀】")
    out.extend(_block_summary(blocks, split_len, hide_empty))
    out.append("")
    out.append("  【未登记】prefix.list 之外的地址")
    out.extend(_unreg_summary(report, 4, split_len))
    out.append("")

    out.append(_rule("三、IPv6 自有前缀占用汇总"))
    out.extend(_summary_table(report.by_family("ipv6"), f"/{split_len6} 块数"))
    out.append("")

    out.append(_rule(f"四、IPv6 /{split_len6} 粒度占用"))
    out.append("  【自有前缀】")
    out.extend(_v6_block_summary(report, split_len6))
    out.append("")
    out.append("  【未登记】prefix.list 之外的地址")
    out.extend(_unreg_summary(report, 6, split_len6))
    out.append("")

    if show_inventory and report.files:
        out.append(_rule("五、采集与解析覆盖"))
        out.extend(_inventory(report))
        out.append("")

    if show_detail:
        out.append(_rule(f"六、IPv4 占用明细（按 /{split_len} 分组）"))
        out.extend(_block_detail(blocks))
        out.append("")
        out.append(_rule(f"七、IPv6 占用明细（按 /{split_len6} 分组）"))
        out.extend(_v6_block_detail(report, split_len6))
        out.append("")

    if show_outside:
        out.append(_rule(f"八、未登记地址明细（按 /{split_len} 与 /{split_len6} 分组）"))
        out.extend(_unreg_detail(report, split_len, split_len6))
        out.append("")

    if report.overlapping:
        out.append(_rule("九、异常：与自有前缀部分重叠的子网"))
        w = net_width(report.overlapping)
        out.extend(_detail_header(w))
        for use in report.overlapping:
            out.extend(_detail_rows(use, w))
        out.append("")

    return "\n".join(out)


_INV_COLS = [("采集文件", 32), ("平台", 8), ("设备", 22),
             ("IPv4", 7), ("IPv6", 7), ("自有前缀内", 12)]


def _inventory(report: Report) -> list:
    """逐个采集文件列出解析结果——漏解析一台设备就会让占用率偏低，必须可核对。"""
    owned = {s.network for st in report.prefix_stats for s in st.subnets}
    lines = ["  " + "".join(_pad(n, w) for n, w in _INV_COLS).rstrip(),
             "  " + "-" * sum(w for _, w in _INV_COLS)]
    for f in sorted(report.files, key=lambda x: (x.platform, x.device)):
        v4 = sum(1 for e in f.entries if e.family == "ipv4")
        v6 = len(f.entries) - v4
        hit = sum(1 for e in f.entries if e.network in owned)
        lines.append("  " + "".join(_pad(_trunc(v, w), w) for v, (_, w) in zip(
            [f.name, f.platform, f.device, str(v4), str(v6), str(hit)],
            _INV_COLS)).rstrip())
    return lines


_BLK_COLS = [("块", 20), ("所属前缀", 20), ("容量", 8), ("已用", 8),
             ("空闲", 8), ("占用率", 9), ("子网数", 8), ("用途", 34)]


def _roles_of(block) -> str:
    c = Counter(role_of(e) for use in block.subnets for e in use.entries)
    return "、".join(f"{k} {v}" for k, v in c.most_common(3)) or "-"


def _block_summary(blocks: list, plen: int, hide_empty: bool) -> list:
    if not blocks:
        return ["  （没有可切分的 IPv4 自有前缀）"]

    used = sum(b.used for b in blocks)
    cap = sum(b.capacity for b in blocks)
    inuse = [b for b in blocks if not b.empty]
    lines = [f"  共 {len(blocks)} 个 /{plen} 块：{len(inuse)} 个有使用，"
             f"{len(blocks) - len(inuse)} 个完全空闲；"
             f"已用 {used:,}/{cap:,} 地址（{used / cap * 100:.2f}%）"]
    if hide_empty:
        lines.append(f"  （已隐藏 {len(blocks) - len(inuse)} 个完全空闲的块，"
                     f"去掉 --hide-empty 可完整列出）")

    shown = inuse if hide_empty else blocks
    lines.append("  " + "".join(_pad(n, w) for n, w in _BLK_COLS).rstrip())
    lines.append("  " + "-" * sum(w for _, w in _BLK_COLS))
    for b in shown:
        lines.append("  " + "".join(_pad(_trunc(v, w), w) for v, (_, w) in zip(
            [str(b.block), str(b.prefix), f"{b.capacity:,}", f"{b.used:,}",
             f"{b.free:,}", f"{b.ratio * 100:.2f}%", str(len(b.subnets)),
             _roles_of(b)], _BLK_COLS)).rstrip())
    return lines


def _block_detail(blocks: list) -> list:
    """IPv4 明细按 /24 块展开——和上面的粒度保持一致，便于对照。"""
    inuse = [b for b in blocks if not b.empty]
    if not inuse:
        return ["  （自有前缀内没有已使用的地址）"]
    lines = []
    for b in inuse:
        lines.append(f"\n  ▸ {b.block}（属 {b.prefix}）  已用 {b.used:,}/{b.capacity:,} "
                     f"地址 ({b.ratio * 100:.2f}%)，{len(b.subnets)} 个子网")
        w = net_width(b.subnets)
        lines.extend(_detail_header(w))
        for use in b.subnets:
            lines.extend(_detail_rows(use, w))
    return lines


_V6_COLS = [("块", 26), ("所属", 24), ("子网数", 9), ("/64 数", 9), ("用途", 34)]


def _v6_blocks(report: Report, plen: int):
    """列出有使用的 /plen 块。

    返回 (块, 所属标签, 子网列表) 三元组，以及一句关于空闲块的说明。
    prefix.list 里登记了 v6 前缀时按自有前缀切块；没登记时退而按 /32 归并，
    这时算不出占用率，只能把在用的块列出来。
    """
    owned = report.by_family("ipv6")
    if owned:
        rows, free = [], 0
        for st in owned:
            blocks = split_prefix(st, plen)
            inuse = [b for b in blocks if not b.empty]
            rows.extend((b.block, str(st.prefix), b.subnets) for b in inuse)
            free += total_blocks(st.prefix, plen) - len(inuse)
        return rows, f"自有 v6 前缀共可切出 {free + len(rows):,} 个 /{plen}，" \
                     f"其中 {len(rows)} 个有使用、{free:,} 个空闲"

    v6 = [u for u in report.outside + report.overlapping
          if u.network.version == 6]
    groups = {}
    for use in v6:
        groups.setdefault(block_of(use.network, plen), []).append(use)
    rows = [(b, str(block_of(b, 32)), sorted(groups[b],
                                             key=lambda u: u.network.network_address))
            for b in sorted(groups, key=lambda n: (n.network_address, n.prefixlen))]
    return rows, (f"prefix.list 中尚未登记 IPv6 前缀，算不出占用率；"
                  f"以下是在用的 {len(rows)} 个 /{plen}，「所属」列按 /32 归并。"
                  f"补上 v6 前缀后这里会切换为占用率视图")


def _v64_count(uses) -> int:
    """这些子网涉及多少个 /64。"""
    blocks = set()
    for u in uses:
        blocks.add(block_of(u.network, 64))
    return len(blocks)


def _v6_block_summary(report: Report, plen: int) -> list:
    rows, note = _v6_blocks(report, plen)
    if not rows:
        return ["  （配置中没有 IPv6 接口地址）"]
    lines = ["  " + note,
             "  " + "".join(_pad(n, w) for n, w in _V6_COLS).rstrip(),
             "  " + "-" * sum(w for _, w in _V6_COLS)]
    for block, parent, uses in rows:
        roles = Counter(role_of(e) for u in uses for e in u.entries)
        lines.append("  " + "".join(_pad(_trunc(v, w), w) for v, (_, w) in zip(
            [str(block), parent, str(len(uses)), str(_v64_count(uses)),
             "、".join(f"{k} {v}" for k, v in roles.most_common(3)) or "-"],
            _V6_COLS)).rstrip())
    return lines


def _v6_block_detail(report: Report, plen: int) -> list:
    rows, _ = _v6_blocks(report, plen)
    if not rows:
        return ["  （配置中没有 IPv6 接口地址）"]
    lines = []
    for block, parent, uses in rows:
        lines.append(f"\n  ▸ {block}（属 {parent}）  {len(uses)} 个子网，"
                     f"涉及 {_v64_count(uses)} 个 /64")
        w = net_width(uses)
        lines.extend(_detail_header(w))
        for use in uses:
            lines.extend(_detail_rows(use, w))
    return lines


# 未登记块的容量不归我方支配，所以不给占用率，只给「我们在里面占了多少」
_UNREG4_COLS = [("块", 20), ("子网数", 9), ("地址条目", 10), ("子网面积", 10),
                ("用途", 40)]
_UNREG6_COLS = [("块", 26), ("子网数", 9), ("/64 数", 9), ("地址条目", 10),
                ("用途", 34)]


def _entry_count(block) -> int:
    return sum(len(u.entries) for u in block.subnets)


def _block_roles(block) -> str:
    c = Counter(role_of(e) for u in block.subnets for e in u.entries)
    return "、".join(f"{k} {v}" for k, v in c.most_common(3)) or "-"


def _unreg_summary(report: Report, version: int, plen: int) -> list:
    """把不在 prefix.list 内的地址按 /plen 归并后列出。"""
    blocks = unregistered_blocks(report, version, plen)
    if not blocks:
        return [f"  （IPv{version} 没有 prefix.list 之外的地址）"]

    subnets = sum(len(b.subnets) for b in blocks)
    entries = sum(_entry_count(b) for b in blocks)
    cols = _UNREG4_COLS if version == 4 else _UNREG6_COLS
    lines = [f"  共 {len(blocks)} 个 /{plen} 块、{subnets} 条子网、{entries} 条地址条目。",
             "  这些块的容量不归我方支配（对端互联 / 上游分配 / IX LAN），"
             "因此不给占用率，也不计入上面的自有前缀统计。",
             "  " + "".join(_pad(n, w) for n, w in cols).rstrip(),
             "  " + "-" * sum(w for _, w in cols)]
    for b in sorted(blocks, key=lambda x: -len(x.subnets)):
        if version == 4:
            vals = [str(b.block), str(len(b.subnets)), str(_entry_count(b)),
                    f"{b.used:,}", _block_roles(b)]
        else:
            vals = [str(b.block), str(len(b.subnets)), str(_v64_count(b.subnets)),
                    str(_entry_count(b)), _block_roles(b)]
        lines.append("  " + "".join(_pad(_trunc(v, w), w)
                                    for v, (_, w) in zip(vals, cols)).rstrip())
    return lines


def _unreg_detail(report: Report, plen4: int, plen6: int) -> list:
    lines = []
    for version, plen in ((4, plen4), (6, plen6)):
        blocks = unregistered_blocks(report, version, plen)
        if not blocks:
            continue
        lines.append(f"\n  ── IPv{version}（按 /{plen} 分组，{len(blocks)} 个块）──")
        for b in blocks:
            lines.append(f"\n  ▸ {b.block}  {len(b.subnets)} 个子网，"
                         f"{_entry_count(b)} 条地址条目")
            w = net_width(b.subnets)
            lines.extend(_detail_header(w))
            for use in b.subnets:
                lines.extend(_detail_rows(use, w))
    return lines or ["  （无）"]
