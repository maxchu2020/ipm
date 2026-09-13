"""对自有 IPv4 前缀做在用地址扫描，按 /24 汇总。

用 nmap 做主机发现（`-sn`），探测方式是 ICMP + TCP SYN/ACK：
实测同一条 /20 里纯 ICMP 只发现 50 个在用，加上 TCP 80/443/22 探测后是 95 个 ——
近一半主机屏蔽 ICMP，只靠 ping 会系统性低估。

注意口径：这里量的是「从本机探测得到响应」，不等于「地址已分配」。
本机若不在对端的管理 ACL 白名单内，即使地址在用也可能无响应
（例如路由器 Loopback 通常只放行特定源网段）。
"""

from __future__ import annotations

import ipaddress
import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field

NMAP = "nmap"
# -sn 只做主机发现不扫端口；-n 不做 DNS 反查；-T4 与 --min-hostgroup 让
# nmap 大批量并发探测，实测比默认快一个数量级
BASE_ARGS = ["-sn", "-n", "-T4", "--min-hostgroup", "1024", "--max-retries", "1"]
ICMP_ARGS = ["-PE"]
TCP_ARGS = ["-PS80,443,22", "-PA80"]

_HOST_UP = re.compile(r"^Host:\s+(\S+).*?Status:\s+Up", re.M)


@dataclass
class BlockScan:
    """一个 /24（或更小的扫描单元）的在用情况。"""

    block: object
    alive: list = field(default_factory=list)
    prefix: object = None          # 所属自有前缀

    @property
    def total(self) -> int:
        return self.block.num_addresses

    @property
    def alive_count(self) -> int:
        return len(self.alive)

    @property
    def ratio(self) -> float:
        return self.alive_count / self.total if self.total else 0.0


@dataclass
class ScanResult:
    blocks: list = field(default_factory=list)
    prefixes: list = field(default_factory=list)
    started: float = 0.0
    elapsed: float = 0.0
    method: str = ""
    errors: list = field(default_factory=list)

    @property
    def total(self) -> int:
        return sum(b.total for b in self.blocks)

    @property
    def alive_count(self) -> int:
        return sum(b.alive_count for b in self.blocks)

    @property
    def ratio(self) -> float:
        return self.alive_count / self.total if self.total else 0.0

    def by_prefix(self) -> dict:
        out = {}
        for b in self.blocks:
            out.setdefault(b.prefix, []).append(b)
        return out


def nmap_available() -> bool:
    return shutil.which(NMAP) is not None


def build_args(tcp: bool = True) -> list:
    return BASE_ARGS + ICMP_ARGS + (TCP_ARGS if tcp else [])


def method_label(tcp: bool) -> str:
    return ("nmap -sn，ICMP echo + TCP SYN 80/443/22 + TCP ACK 80"
            if tcp else "nmap -sn，仅 ICMP echo")


def _run_nmap(target: str, args: list, timeout: int) -> str:
    proc = subprocess.run([NMAP] + args + ["-oG", "-", target],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=timeout)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.decode("utf-8", "replace").strip()[:200]
                           or f"nmap 退出码 {proc.returncode}")
    return proc.stdout.decode("utf-8", "replace")


def parse_alive(output: str) -> list:
    """从 nmap 的 grepable 输出里取出在用地址。"""
    out = []
    for addr in _HOST_UP.findall(output):
        try:
            out.append(ipaddress.ip_address(addr))
        except ValueError:
            continue
    return out


def split_blocks(prefix, block_len: int = 24) -> list:
    """把前缀切成 /block_len 的扫描单元；比它更具体的前缀整条作为一个单元。"""
    if prefix.prefixlen >= block_len:
        return [prefix]
    return list(prefix.subnets(new_prefix=block_len))


def scan(prefixes, tcp: bool = True, block_len: int = 24,
         timeout: int = 3600, progress=None, runner=_run_nmap) -> ScanResult:
    """逐条前缀扫描，结果按 /block_len 归并。

    一次 nmap 扫整条前缀比逐个 /24 起进程快得多（nmap 自己会批量并发），
    所以扫描粒度按前缀走，汇总粒度才按 /24。
    """
    args = build_args(tcp)
    result = ScanResult(prefixes=list(prefixes), started=time.time(),
                        method=method_label(tcp))
    started = time.time()

    for i, prefix in enumerate(prefixes, 1):
        if progress:
            progress(i, len(prefixes), prefix)
        alive = []
        try:
            alive = parse_alive(runner(str(prefix), args, timeout))
        except subprocess.TimeoutExpired:
            result.errors.append(f"{prefix}：扫描超时（>{timeout}s），该段计为 0 在用")
        except Exception as exc:
            result.errors.append(f"{prefix}：{exc}")

        by_block = {}
        for ip in alive:
            key = ipaddress.ip_network(f"{ip}/{block_len}", strict=False)
            by_block.setdefault(key, []).append(ip)

        for block in split_blocks(prefix, block_len):
            result.blocks.append(BlockScan(
                block, sorted(by_block.get(block, [])), prefix))

    result.elapsed = time.time() - started
    return result
