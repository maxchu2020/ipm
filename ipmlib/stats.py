"""按自有前缀汇总接口地址占用情况。

口径（与需求一致）：以**接口所在的整条子网**作为已用容量，而不是单个 IP。
一条 /30 互联即视为占用 4 个地址，/31 占 2 个，Loopback /32 占 1 个。

同一子网可能出现在多台设备 / 多个接口上（互联两端、VRF 复用 Loopback），
容量只计一次，但明细里会把所有出现位置都列出来。
"""

from __future__ import annotations

import ipaddress
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Union

from .parsers import AddrEntry

# 运行环境是 Python 3.9，不能用 X | Y 写运行时联合类型
Network = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]


@dataclass
class SubnetUse:
    """一条被使用的子网，以及它出现在哪些设备接口上。"""

    network: Network
    entries: list[AddrEntry] = field(default_factory=list)

    @property
    def size(self) -> int:
        return self.network.num_addresses

    @property
    def all_shutdown(self) -> bool:
        return bool(self.entries) and all(e.shutdown for e in self.entries)

    @property
    def all_preconfigure(self) -> bool:
        return bool(self.entries) and all(e.preconfigure for e in self.entries)


@dataclass
class PrefixStat:
    """一条自有前缀的占用统计。"""

    prefix: Network
    subnets: list[SubnetUse] = field(default_factory=list)

    @property
    def family(self) -> str:
        return "ipv4" if self.prefix.version == 4 else "ipv6"

    @property
    def capacity(self) -> int:
        return _units(self.prefix.version, [self.prefix])

    @property
    def used(self) -> int:
        # 先折叠：互联子网之间可能相邻或包含，折叠后才是真实占用面积
        merged = _collapse([s.network for s in self.subnets])
        return _units(self.prefix.version, merged)

    @property
    def free(self) -> int:
        return self.capacity - self.used

    @property
    def ratio(self) -> float:
        return self.used / self.capacity if self.capacity else 0.0


@dataclass
class BlockStat:
    """把自有前缀切成等长块（默认 /24）后，单块的占用情况。"""

    block: Network
    prefix: Network              # 所属的自有前缀
    used: int = 0
    subnets: list = field(default_factory=list)   # 与本块有交集的子网

    @property
    def capacity(self) -> int:
        return _units(self.block.version, [self.block])

    @property
    def free(self) -> int:
        return self.capacity - self.used

    @property
    def ratio(self) -> float:
        return self.used / self.capacity if self.capacity else 0.0

    @property
    def empty(self) -> bool:
        return not self.subnets


@dataclass
class Report:
    prefix_stats: list[PrefixStat]
    outside: list[SubnetUse]          # 不落在任何自有前缀内的地址
    overlapping: list[SubnetUse]      # 与自有前缀部分重叠 / 反包含的异常
    entries: list[AddrEntry]
    devices: list[str]
    sources: list[str]
    files: list = field(default_factory=list)      # 每个采集文件的解析结果
    warnings: list = field(default_factory=list)   # 解析覆盖方面的告警

    def by_family(self, family: str) -> list[PrefixStat]:
        return [p for p in self.prefix_stats if p.family == family]


# ---------------------------------------------------------------- 容量换算

# 各协议族的统计粒度：IPv4 按 /24 切块并按地址数计；IPv6 按 /48 切块并按 /48 计
DEFAULT_SPLIT = {4: 24, 6: 48}
V6_UNIT = 48


def _units(version: int, nets) -> int:
    """IPv4 按地址数计；IPv6 按 /48 块数计（按地址数算没有可读性）。"""
    if version == 4:
        return sum(n.num_addresses for n in nets)
    total = 0
    blocks = set()
    for n in nets:
        if n.prefixlen >= V6_UNIT:
            blocks.add(n.supernet(new_prefix=V6_UNIT))
        else:
            total += 1 << (V6_UNIT - n.prefixlen)
    return total + len(blocks)


def _overlap(net, block) -> int:
    """net 落在 block 内的地址数。

    两条网段要么互相包含、要么完全不相交，所以只需判断包含关系。
    跨块的大网段（例如一条 /22 分给客户）会按交集分摊到各块。
    """
    if net.version != block.version:
        return 0
    if net.subnet_of(block):
        return net.num_addresses
    if block.subnet_of(net):
        return block.num_addresses
    return 0


def total_blocks(prefix, plen: int) -> int:
    """一条前缀理论上能切出多少个 /plen 块。"""
    return 1 if prefix.prefixlen >= plen else 1 << (plen - prefix.prefixlen)


# 一条 IPv6 /32 能切出 65536 个 /48，全量枚举既无意义又跑不动，
# 超过这个阈值就只列出实际有使用的块（空闲块数用 total_blocks 换算）。
MAX_ENUMERATE = 4096


def split_prefix(st: PrefixStat, plen=None, max_enumerate: int = MAX_ENUMERATE) -> list:
    """把一条自有前缀切成 /plen 的块，逐块统计占用。

    前缀本身比 /plen 更具体（切不动）时，整条作为一块返回。
    块数超过 max_enumerate 时只返回有使用的块 —— 这时报表里会说明省略了多少空块。
    """
    if plen is None:
        plen = DEFAULT_SPLIT[st.prefix.version]

    if st.prefix.prefixlen >= plen:
        blocks = [st.prefix]
    elif total_blocks(st.prefix, plen) <= max_enumerate:
        blocks = list(st.prefix.subnets(new_prefix=plen))
    else:
        blocks = sorted({_block_of(s.network, plen) for s in st.subnets},
                        key=lambda n: n.network_address)

    # 先折叠再分摊，避免嵌套/相邻的子网在同一块里被重复计面积
    merged = _collapse([s.network for s in st.subnets])
    out = []
    for b in blocks:
        bs = BlockStat(b, st.prefix)
        bs.used = _units(b.version, [n for n in _clip(merged, b)])
        bs.subnets = [s for s in st.subnets if _overlap(s.network, b)]
        out.append(bs)
    return out


def block_of(net, plen: int):
    """net 所属的 /plen 块；net 本身比块还大时返回它自己。"""
    return net if net.prefixlen <= plen else net.supernet(new_prefix=plen)


_block_of = block_of      # 内部旧名


def _clip(nets, block) -> list:
    """取每条网段落在 block 内的部分，用于把占用分摊到块。"""
    out = []
    for n in nets:
        if n.subnet_of(block):
            out.append(n)
        elif block.subnet_of(n):
            out.append(block)
    return out


def unregistered_blocks(report: Report, version: int, plen=None) -> list:
    """把不在 prefix.list 内的地址也按 /plen 归并成块。

    这些块不参与自有前缀的占用率（它们的容量不归我们支配），
    单独统计只是为了看清「我们在别人的段里用了哪些地址」。
    子网本身比 /plen 还大时（例如一条 /20 的 IX LAN）按它自己成块。
    """
    if plen is None:
        plen = DEFAULT_SPLIT[version]
    uses = [u for u in report.outside + report.overlapping
            if u.network.version == version]

    groups = {}
    for use in uses:
        groups.setdefault(block_of(use.network, plen), []).append(use)

    out = []
    for b in sorted(groups, key=lambda n: (n.network_address, n.prefixlen)):
        bs = BlockStat(b, None)          # prefix=None 表示未登记
        merged = _collapse([u.network for u in groups[b]])
        bs.used = _units(b.version, _clip(merged, b))
        bs.subnets = sorted(groups[b],
                            key=lambda u: (u.network.network_address,
                                           u.network.prefixlen))
        out.append(bs)
    return out


def split_report(report: Report, plen4=None, plen6=None) -> list:
    """把报表里全部自有前缀按各自协议族的粒度切开。"""
    out = []
    for st in report.prefix_stats:
        plen = plen4 if st.prefix.version == 4 else plen6
        out.extend(split_prefix(st, plen))
    return out


def _collapse(nets):
    if not nets:
        return []
    out = []
    for version in (4, 6):
        same = [n for n in nets if n.version == version]
        if same:
            out.extend(ipaddress.collapse_addresses(same))
    return out


# ---------------------------------------------------------------- 前缀表

def load_prefixes(path) -> list[Network]:
    prefixes = []
    for raw in Path(path).read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        try:
            prefixes.append(ipaddress.ip_network(line, strict=False))
        except ValueError:
            raise ValueError(f"{path}: 无法解析的前缀 {raw!r}") from None
    return prefixes


# ---------------------------------------------------------------- 汇总

def build_report(entries: list, prefixes: list, files=None) -> Report:
    # 同一子网合并，保留全部出现位置
    grouped: dict[Network, SubnetUse] = {}
    for e in entries:
        grouped.setdefault(e.network, SubnetUse(e.network)).entries.append(e)

    stats = {p: PrefixStat(p) for p in prefixes}
    outside: list[SubnetUse] = []
    overlapping: list[SubnetUse] = []

    for net, use in sorted(grouped.items(), key=_netkey):
        owner = _owner(net, prefixes)
        if owner is not None:
            stats[owner].subnets.append(use)
        elif any(p.overlaps(net) for p in prefixes if p.version == net.version):
            overlapping.append(use)
        else:
            outside.append(use)

    for st in stats.values():
        st.subnets.sort(key=lambda s: (s.network.network_address, s.network.prefixlen))

    devices = sorted({e.device for e in entries})
    sources = sorted({e.source for e in entries})
    files = list(files or [])
    return Report([stats[p] for p in prefixes], outside, overlapping,
                  entries, devices, sources, files, _warnings(files, entries))


# 接口地址的掩码短于这个长度基本就是配错了（互联口正常是 /30 /31 /126 /127）
_SUSPICIOUS = {4: 16, 6: 48}


def _warnings(files, entries=()) -> list:
    """解析覆盖与数据质量方面的问题——静默带过比数字不准更危险，必须显式报出来。"""
    warns = []
    for f in files:
        if f.note:
            warns.append(f"{f.name}（识别为 {f.platform}）：{f.note}")

    for e in entries:
        limit = _SUSPICIOUS[e.network.version]
        if e.network.prefixlen < limit:
            warns.append(
                f"{e.device} {e.interface} 配了 {e.address}/{e.network.prefixlen}"
                f"（{e.network}，{e.network.num_addresses:,} 个地址）——"
                f"接口掩码短于 /{limit}，疑似掩码写错，已按原样计入")

    seen = {}
    for f in files:
        seen.setdefault(f.device, []).append(f.name)
    for device, names in sorted(seen.items()):
        if len(names) > 1:
            warns.append(f"hostname {device} 同时出现在 {len(names)} 个采集文件中："
                         f"{'、'.join(sorted(names))} —— 可能是重复采集或改名，"
                         f"两份配置里的地址已合并统计")
    return warns


def _owner(net: Network, prefixes: list[Network]):
    """返回包含该子网的自有前缀；多条命中时取最具体的一条。"""
    hits = [p for p in prefixes
            if p.version == net.version and net.subnet_of(p)]
    return max(hits, key=lambda p: p.prefixlen) if hits else None


def _netkey(item):
    net = item[0]
    return (net.version, net.network_address, net.prefixlen)
