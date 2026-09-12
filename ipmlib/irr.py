"""IRR（RADB 及其镜像）route 对象查询。

两个必须注意的地方：

1. `-T route <prefix>` 会把 **less-specific 的覆盖对象**一并返回
   （查 218.30.33.0/24 会带出 218.30.0.0/15），所以要自己过滤成精确前缀。
2. RADB 镜像了一个 `source: RPKI` 的伪 IRR 源 —— 那是 IRRd 把 ROA 自动转换成
   route 对象的产物。做「无 ROA 覆盖时看 IRR 有没有」的判断时必须排除它，
   否则等于拿 ROA 数据去证明 ROA 缺失，成了循环论证。
"""

from __future__ import annotations

import ipaddress
import socket
import time
from dataclasses import dataclass

WHOIS_SERVER = "whois.radb.net"
WHOIS_PORT = 43
# IRRd 自动把 RPKI 转换成的 route 对象，不是真正的 IRR 登记
PSEUDO_SOURCES = {"RPKI"}


@dataclass(frozen=True)
class IrrRoute:
    network: object
    origin: int
    source: str
    descr: str = ""
    mnt_by: str = ""


def query(prefixes, server: str = WHOIS_SERVER, port: int = WHOIS_PORT,
          delay: float = 0.4, timeout: float = 20.0, attempts: int = 3,
          exclude_sources=PSEUDO_SOURCES, progress=None):
    """逐条查询前缀的精确 route 对象。

    返回 {prefix: [IrrRoute, ...]}。查询失败的前缀不会出现在结果里，
    而是记进 errors，报表要把「查不到」和「查询失败」区分开。
    """
    results, errors = {}, {}
    for i, prefix in enumerate(prefixes):
        if i and delay:
            time.sleep(delay)          # RADB 对未认证查询有速率限制，放慢一点
        if progress:
            progress(i + 1, len(prefixes), prefix)
        text = _ask(f"-T {_obj_type(prefix)} {prefix}", server, port,
                    timeout, attempts)
        if text is None:
            errors[prefix] = "查询失败（超时或连接错误）"
            continue
        results[prefix] = _parse(text, prefix, exclude_sources)
    return results, errors


def _obj_type(prefix) -> str:
    return "route6" if prefix.version == 6 else "route"


def _ask(query_string: str, server: str, port: int, timeout: float, attempts: int):
    for attempt in range(attempts):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                sock.connect((server, port))
                sock.sendall((query_string + "\r\n").encode())
                chunks = []
                while True:
                    data = sock.recv(8192)
                    if not data:
                        break
                    chunks.append(data)
            return b"".join(chunks).decode("utf-8", errors="replace")
        except (socket.timeout, OSError):
            if attempt == attempts - 1:
                return None
            time.sleep(1.0 + attempt)
    return None


def _parse(text: str, want, exclude_sources) -> list:
    """把 whois 响应切成记录，只留精确匹配 want 且来源不是伪源的 route 对象。"""
    out = []
    for block in text.split("\n\n"):
        fields = _fields(block)
        raw = fields.get("route") or fields.get("route6")
        if not raw or "origin" not in fields:
            continue
        try:
            net = ipaddress.ip_network(raw.strip(), strict=False)
        except ValueError:
            continue
        if net != want:                       # 过滤掉 less-specific 的覆盖对象
            continue
        source = fields.get("source", "").split("#")[0].strip().upper()
        if source in exclude_sources:
            continue
        try:
            origin = int(fields["origin"].strip().upper().replace("AS", ""))
        except ValueError:
            continue
        out.append(IrrRoute(net, origin, source or "?",
                            fields.get("descr", "").strip(),
                            fields.get("mnt-by", "").strip()))
    return out


def _fields(block: str) -> dict:
    """解析 RPSL 记录；续行（以空白开头）并入上一字段。"""
    fields, key = {}, None
    for line in block.splitlines():
        if not line.strip() or line.lstrip().startswith("%"):
            continue
        if line[0].isspace() and key:
            fields[key] += " " + line.strip()
            continue
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower()
        fields.setdefault(key, value.strip())
    return fields
