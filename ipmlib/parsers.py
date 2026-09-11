"""从 running-config 中解析接口地址。

支持 5 种采集格式：

* Cisco IOS XR   —— 缩进块式，`interface X` 顶格起、`!` 顶格止，`ipv4 address A MASK`
* Cisco IOS/XE   —— 同为缩进块式，但关键字是 `ip address A MASK`
* Cisco NX-OS    —— `ip address A/len`（CIDR），VRF 用 `vrf member`
* Huawei VRP     —— `#` 分隔，`ip address A MASK`，VRF 用 `ip binding vpn-instance`
* Juniper Junos  —— `display set` 的一行一条格式

除 Junos 外，其余 4 种都是「顶格 interface 起、缩进行属于该块」的结构，
差异只在关键字上，因此用 :class:`Dialect` 描述方言，共用一套块遍历逻辑。
解析结果统一为 :class:`AddrEntry`，上层统计不需要关心厂商差异。
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path

from .cleaner import load_config


@dataclass(frozen=True)
class AddrEntry:
    """一条接口地址记录。"""

    device: str          # 设备 hostname
    source: str          # 来源文件名
    platform: str        # iosxr / ios / nxos / vrp / junos
    interface: str       # 接口名（含子接口 / unit）
    vrf: str             # VRF / VPN 实例 / routing-instance，全局表为 ""
    description: str
    family: str          # ipv4 / ipv6
    address: str         # 配置的接口地址，不含掩码
    network: object      # 该地址所在子网（IPv4Network / IPv6Network）
    secondary: bool = False
    preconfigure: bool = False   # XR 预配置接口：硬件未上架，但地址已占用
    shutdown: bool = False

    @property
    def prefixlen(self) -> int:
        return self.network.prefixlen


@dataclass
class ParsedFile:
    """一个采集文件的解析结果，含平台与设备名，便于核对覆盖情况。"""

    path: Path
    platform: str
    device: str
    entries: list = field(default_factory=list)
    note: str = ""       # 解析异常时的说明

    @property
    def name(self) -> str:
        return self.path.name


# ---------------------------------------------------------------- 方言定义

_DESC_RE = re.compile(r"^\s+description (.*)$")


@dataclass(frozen=True)
class Dialect:
    name: str
    iface: object
    v4: object
    v6: object
    vrf: object
    host: object


def _d(name, iface, v4, v6, vrf, host):
    return Dialect(name, *(re.compile(p) for p in (iface, v4, v6, vrf, host)))


# 掩码一律要求以数字开头，这样 `ip address dhcp` / `no ip address` 不会误匹配
_MASK = r"(?:\s+(?P<mask>\d\S*))?"
_ADDR = r"(?P<addr>\d\S*)"

DIALECTS = {
    "iosxr": _d(
        "iosxr",
        r"^interface (?P<pre>preconfigure )?(?P<name>\S+)\s*$",
        r"^\s+ipv4 address " + _ADDR + _MASK + r"(?P<sec>\s+secondary)?\s*$",
        r"^\s+ipv6 address (?P<cidr>\S+/\d+)(?P<sec>\s+secondary)?\s*$",
        r"^\s+vrf (?P<vrf>\S+)\s*$",
        r"^hostname (?P<host>\S+)\s*$",
    ),
    "ios": _d(
        "ios",
        r"^interface (?P<name>\S+)\s*$",
        r"^\s+ip address " + _ADDR + _MASK + r"(?P<sec>\s+secondary)?\s*$",
        r"^\s+ipv6 address (?P<cidr>\S+/\d+)(?P<sec>\s+secondary)?\s*$",
        r"^\s+(?:ip )?vrf forwarding (?P<vrf>\S+)\s*$",
        r"^hostname (?P<host>\S+)\s*$",
    ),
    "nxos": _d(
        "nxos",
        r"^interface (?P<name>\S+)\s*$",
        r"^\s+ip address " + _ADDR + _MASK + r"(?P<sec>\s+secondary)?\s*$",
        r"^\s+ipv6 address (?P<cidr>\S+/\d+)(?P<sec>\s+secondary)?\s*$",
        r"^\s+vrf member (?P<vrf>\S+)\s*$",
        r"^hostname (?P<host>\S+)\s*$",
    ),
    "vrp": _d(
        "vrp",
        r"^interface (?P<name>\S+)\s*$",
        r"^\s+ip address " + _ADDR + _MASK + r"(?P<sec>\s+sub)?\s*$",
        r"^\s+ipv6 address (?P<cidr>\S+/\d+)(?P<sec>\s+sub)?\s*$",
        r"^\s+ip binding vpn-instance (?P<vrf>\S+)\s*$",
        r"^sysname (?P<host>\S+)\s*$",
    ),
}


# ---------------------------------------------------------------- 格式识别

def detect_platform(lines: list) -> str:
    head = lines[:120]
    joined = "\n".join(head)
    if any(l.startswith("set version") or "display set" in l for l in head):
        return "junos"
    if "IOS XR" in joined:
        return "iosxr"
    if "Software Version V800R" in joined or any(l.startswith("sysname ") for l in lines[:300]):
        return "vrp"
    if "Bios:version" in joined or any(l.startswith("vdc ") for l in head):
        return "nxos"
    if "Building configuration" in joined or any(re.match(r"^version \d", l) for l in head):
        return "ios"
    return _detect_by_keywords(lines)


def _detect_by_keywords(lines: list) -> str:
    """banner 被截断时的兜底：按配置里实际用的关键字反推方言。

    横幅行不一定采得到（分页、翻屏、命令回显被截断都可能吃掉它），
    而关键字是配置本身的一部分，比横幅可靠。
    """
    if sum(1 for l in lines if l.startswith("set ")) > len(lines) * 0.5:
        return "junos"
    votes = {"iosxr": 0, "ios": 0, "nxos": 0, "vrp": 0}
    for line in lines:
        if re.match(r"^\s+ipv4 address \d", line):
            votes["iosxr"] += 1
        elif re.match(r"^\s+ip address \d+\.\d+\.\d+\.\d+/\d", line):
            votes["nxos"] += 1
        elif re.match(r"^\s+ip address \d", line):
            votes["ios"] += 1
        elif re.match(r"^\s+ip binding vpn-instance ", line):
            votes["vrp"] += 5
        elif re.match(r"^\s+vrf member ", line):
            votes["nxos"] += 5
    best = max(votes, key=lambda k: votes[k])
    return best if votes[best] else "iosxr"


def parse_file(path) -> ParsedFile:
    path = Path(path)
    lines = load_config(path)
    platform = detect_platform(lines)
    if platform == "junos":
        device, entries = parse_junos(lines, path.name)
    else:
        device, entries = parse_blocks(lines, path.name, DIALECTS[platform])
    note = ""
    if not entries:
        note = "未解析出任何接口地址，请确认平台识别是否正确"
    elif device == path.name:
        note = "未能从配置中取到 hostname，已退回文件名"
    return ParsedFile(path, platform, device, entries, note)


# ------------------------------------------------ 缩进块式（XR / IOS / NX-OS / VRP）

def parse_blocks(lines: list, source: str, dialect: Dialect):
    device = source
    for line in lines:
        m = dialect.host.match(line)
        if m:
            device = m.group("host")
            break

    entries = []
    ifname = None
    vrf = desc = ""
    pre = shut = False
    pending = []    # 块内先收地址，块结束时再带上 vrf/description 落库

    def flush():
        nonlocal ifname, vrf, desc, pre, shut, pending
        for family, addr, net, secondary in pending:
            entries.append(AddrEntry(device, source, dialect.name, ifname, vrf,
                                     desc, family, addr, net, secondary, pre, shut))
        ifname, vrf, desc, pre, shut, pending = None, "", "", False, False, []

    for line in lines:
        m = dialect.iface.match(line)
        if m:
            if ifname:
                flush()
            ifname = m.group("name")
            pre = bool(m.groupdict().get("pre"))
            vrf = desc = ""
            shut = False
            pending = []
            continue
        if ifname is None:
            continue
        # 顶格的 `!` / `#` 结束当前接口块；顶格的其它关键字说明块已经结束
        if line and not line[0].isspace():
            flush()
            continue

        if line.strip() == "shutdown":
            shut = True
            continue
        m = dialect.vrf.match(line)
        if m:
            vrf = m.group("vrf")
            continue
        m = _DESC_RE.match(line)
        if m:
            desc = m.group(1).strip()
            continue
        m = dialect.v4.match(line)
        if m:
            net = _v4_network(m.group("addr"), m.group("mask"))
            if net:
                pending.append(("ipv4", m.group("addr").split("/")[0], net,
                                bool(m.groupdict().get("sec"))))
            continue
        m = dialect.v6.match(line)
        if m:
            net = _cidr_network(m.group("cidr"))
            if net:
                pending.append(("ipv6", m.group("cidr").split("/")[0], net,
                                bool(m.groupdict().get("sec"))))

    if ifname:
        flush()
    return device, entries


def _v4_network(addr: str, mask):
    """v4 地址可能写成 `A.B.C.D MASK`（XR/IOS/VRP）或 `A.B.C.D/len`（NX-OS）。"""
    if "/" in addr:
        return _cidr_network(addr)
    if not mask:
        return None
    try:
        return ipaddress.ip_network(f"{addr}/{mask}", strict=False)
    except ValueError:
        return None


def _cidr_network(cidr: str):
    try:
        return ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return None


# ---------------------------------------------------------------- Junos

_JUNOS_ADDR = re.compile(
    r"^set (?:groups (?P<group>\S+) )?interfaces (?P<if>\S+)"
    r"(?: unit (?P<unit>\S+))? family (?P<family>inet6?) address (?P<cidr>\S+)"
)
_JUNOS_DESC = re.compile(
    r"^set (?:groups (?P<group>\S+) )?interfaces (?P<if>\S+)"
    r"(?: unit (?P<unit>\S+))? description (?P<desc>.*)$"
)
_JUNOS_RI_IF = re.compile(r"^set routing-instances (?P<ri>\S+) interfaces? (?P<if>\S+)")


def parse_junos(lines: list, source: str):
    device = source
    for line in lines:
        if line.startswith("set system host-name "):
            device = line.split()[-1]
            break

    # apply-groups 决定 groups 下的接口配置是否真正生效
    applied = {l.split()[-1] for l in lines if l.startswith("set apply-groups ")}

    descs = {}
    vrfs = {}
    disabled = set()
    for line in lines:
        if line.startswith("set interfaces ") and line.rstrip().endswith(" disable"):
            disabled.add(line.split()[2])
            continue
        m = _JUNOS_DESC.match(line)
        if m:
            descs[_junos_ifkey(m)] = m.group("desc").strip().strip('"')
            continue
        m = _JUNOS_RI_IF.match(line)
        if m:
            vrfs[m.group("if")] = m.group("ri")

    entries = []
    for line in lines:
        m = _JUNOS_ADDR.match(line)
        if not m:
            continue
        group = m.group("group")
        if group and group not in applied:
            continue          # 定义了但没 apply 的 group，地址并未生效
        net = _cidr_network(m.group("cidr"))
        if net is None:
            continue
        key = _junos_ifkey(m)
        entries.append(AddrEntry(
            device=device,
            source=source,
            platform="junos",
            interface=key + (f" (group {group})" if group else ""),
            vrf=vrfs.get(key, ""),
            description=descs.get(key, ""),
            family="ipv4" if m.group("family") == "inet" else "ipv6",
            address=m.group("cidr").split("/")[0],
            network=net,
            shutdown=m.group("if") in disabled,
        ))
    return device, entries


def _junos_ifkey(m) -> str:
    unit = m.group("unit")
    return f"{m.group('if')}.{unit}" if unit else m.group("if")


# 旧接口：保留给只关心 IOS XR 块解析的调用方（测试用）
def parse_iosxr(lines: list, source: str) -> list:
    return parse_blocks(lines, source, DIALECTS["iosxr"])[1]
