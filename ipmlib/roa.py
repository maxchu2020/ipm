"""ROA（RPKI）数据获取与 Route Origin Validation。

VRP 来自 Cloudflare 的 rpki.json 全量导出（rpki-client 生成）。取全量而不是
逐条查在线校验 API，有两个好处：一是不必把我们关心哪些前缀告诉对方，二是
89 条前缀只需一次下载，且结果可缓存复用。

校验遵循 RFC 6811：
* VRP «覆盖» 一条路由 —— VRP 的前缀是该路由前缀的 less-specific-or-equal
* VRP «匹配» 一条路由 —— 在覆盖的基础上，还要 ASN 相同且路由前缀长度 <= maxLength
* valid    至少有一条 VRP 匹配
* invalid  有 VRP 覆盖，但没有一条匹配
* notfound 没有任何 VRP 覆盖
"""

from __future__ import annotations

import gzip
import ipaddress
import json
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path

ROA_DUMP_URL = "https://rpki.cloudflare.com/rpki.json"
ROA_API_URL = "https://rpki.cloudflare.com/api/graphql"
CACHE_MAX_AGE = 12 * 3600          # 缓存超过 12 小时就重新拉取
CACHE_SCHEMA = 2                   # 缓存结构变了就作废重取

# 到期时间的两种来源，含义完全不同，报表必须标明用的是哪一种
EXPIRY_CERT = "cert"     # ROA 证书自身的 validTo（我们要的）
EXPIRY_CHAIN = "chain"   # 整条验证链的有效期，受 manifest/CRL 约束，只有几天

VALID = "valid"
INVALID = "invalid"
NOTFOUND = "notfound"


@dataclass(frozen=True)
class Vrp:
    network: object
    asn: int
    max_length: int
    expires: int            # 验证链有效期（来自 rpki.json 的 expires）
    ta: str = ""
    valid_to: int = 0       # ROA 证书自身的 validTo，0 表示没取到
    valid_from: int = 0

    @property
    def expiry(self):
        """优先给 ROA 证书有效期；取不到才退回验证链有效期。

        rpki.json 里的 expires 受 manifest/CRL 约束（通常每天重签），
        永远只有几天，拿它当「ROA 到期日」会误报成全网即将过期。
        """
        return self.valid_to or self.expires or None

    @property
    def expiry_kind(self) -> str:
        return EXPIRY_CERT if self.valid_to else EXPIRY_CHAIN

    def covers(self, prefix) -> bool:
        return (prefix.version == self.network.version
                and prefix.subnet_of(self.network))

    def matches(self, prefix, origin: int) -> bool:
        return (self.covers(prefix) and self.asn == origin
                and prefix.prefixlen <= self.max_length)

    def as_dict(self) -> dict:
        return {"prefix": str(self.network), "asn": self.asn,
                "maxLength": self.max_length, "expires": self.expires,
                "ta": self.ta, "validTo": self.valid_to,
                "validFrom": self.valid_from}


def _relevant(net, parents) -> bool:
    return any(net.version == p.version and net.overlaps(p) for p in parents)


def fetch_vrps(parents, cache_path, url: str = ROA_DUMP_URL,
               max_age: int = CACHE_MAX_AGE, refresh: bool = False):
    """取回与 parents 有交集的 VRP；优先用缓存。

    返回 (vrps, meta)，meta 含数据构建时间与来源，报表要如实标出数据新鲜度。
    """
    cache_path = Path(cache_path)
    if not refresh and cache_path.is_file():
        age = time.time() - cache_path.stat().st_mtime
        cached = json.loads(cache_path.read_text(encoding="utf-8"))
        if age < max_age and cached.get("meta", {}).get("schema") == CACHE_SCHEMA:
            meta = cached["meta"]
            meta["cache_age_sec"] = int(age)
            return [_vrp_from(d) for d in cached["vrps"]], meta

    vrps, meta = _download(url, parents)
    meta["schema"] = CACHE_SCHEMA
    vrps = attach_validity(vrps, parents, meta)
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(json.dumps(
        {"meta": meta, "vrps": [v.as_dict() for v in vrps]},
        indent=1), encoding="utf-8")
    meta["cache_age_sec"] = 0
    return vrps, meta


def _vrp_from(d: dict) -> Vrp:
    return Vrp(ipaddress.ip_network(d["prefix"], strict=False), int(d["asn"]),
               int(d["maxLength"]), int(d["expires"]), d.get("ta", ""),
               int(d.get("validTo") or 0), int(d.get("validFrom") or 0))


def _download(url: str, parents):
    """流式过滤全量导出。

    导出有上百 MB，但每个 VRP 独占一行，逐行解析即可，不必整份读进内存。
    """
    req = urllib.request.Request(
        url, headers={"User-Agent": "ipm/1.0", "Accept-Encoding": "gzip"})
    vrps = []
    meta = {"source": url, "buildtime": "", "total_vrps": 0}
    with urllib.request.urlopen(req, timeout=180) as resp:
        stream = resp
        if resp.headers.get("Content-Encoding") == "gzip":
            stream = gzip.GzipFile(fileobj=resp)
        for raw in stream:
            line = raw.decode("utf-8", errors="ignore").strip().rstrip(",")
            if not line.startswith("{"):
                if '"buildtime"' in line:
                    meta["buildtime"] = line.split('"')[3]
                continue
            try:
                entry = json.loads(line)
                net = ipaddress.ip_network(entry["prefix"], strict=False)
            except (ValueError, KeyError):
                continue
            meta["total_vrps"] += 1
            if _relevant(net, parents):
                vrps.append(Vrp(net, int(entry["asn"]), int(entry["maxLength"]),
                                int(entry.get("expires", 0)), entry.get("ta", "")))
    return vrps, meta


def covering(prefix, vrps) -> list:
    """所有覆盖该前缀的 VRP（含它自己这一级），按前缀长度排序。"""
    return sorted((v for v in vrps if v.covers(prefix)),
                  key=lambda v: (v.network.prefixlen, v.asn))


def validate(prefix, origin: int, vrps):
    """对一条前缀 + origin 做 RFC 6811 校验，返回 (状态, 匹配的 VRP, 覆盖的 VRP)。"""
    cover = covering(prefix, vrps)
    matched = [v for v in cover if v.matches(prefix, origin)]
    if matched:
        return VALID, matched, cover
    return (INVALID if cover else NOTFOUND), [], cover


# ---------------------------------------------------------------- 到期时间

def attach_validity(vrps, parents, meta, url: str = ROA_API_URL):
    """给 VRP 补上 ROA 证书自身的 validTo。

    Cloudflare 的 GraphQL 接口（其网页版 Route Validator 同源）返回 ROA 证书的
    validFrom / validTo。取不到时保留 dump 里的链路有效期，并在 meta 里标明，
    报表会如实说明当次用的是哪种口径。
    """
    try:
        validity = _fetch_validity(parents, url)
    except Exception as exc:                       # 接口不可用不该让整个校验失败
        meta["expiry_source"] = f"{ROA_DUMP_URL}（验证链有效期，GraphQL 不可用：{exc}）"
        meta["expiry_kind"] = EXPIRY_CHAIN
        return vrps

    if not validity:
        meta["expiry_source"] = f"{ROA_DUMP_URL}（验证链有效期，GraphQL 无数据）"
        meta["expiry_kind"] = EXPIRY_CHAIN
        return vrps

    out, hit = [], 0
    for v in vrps:
        got = validity.get((v.network, v.asn, v.max_length))
        if got:
            hit += 1
            out.append(Vrp(v.network, v.asn, v.max_length, v.expires, v.ta,
                           got[1], got[0]))
        else:
            out.append(v)
    meta["expiry_source"] = f"{url}（ROA 证书 validTo）"
    meta["expiry_kind"] = EXPIRY_CERT
    meta["expiry_hit"] = hit
    return out


def _fetch_validity(parents, url: str) -> dict:
    """按父前缀批量查 ROA 证书有效期，返回 {(网段, ASN, maxLength): (from, to)}。"""
    query = ('{resource(type:ROA, limit:1000, prefixFilters:{prefix:"%s", '
             'moreSpecific:true, lessSpecific:true, equal:true})'
             '{ta validFrom validTo state ... on ROA{asn roas{prefix maxLength}}}}')

    out = {}
    for parent in _aggregate(parents):
        payload = json.dumps({"query": query % parent}).encode()
        req = urllib.request.Request(
            url, data=payload,
            headers={"User-Agent": "ipm/1.0", "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=45) as resp:
            data = json.loads(resp.read().decode())

        for roa in (data.get("data", {}).get("resource") or []):
            if roa.get("state") != "ADDED" or not roa.get("validTo"):
                continue
            try:
                asn = int(roa["asn"])
                vt, vf = int(roa["validTo"]), int(roa.get("validFrom") or 0)
            except (KeyError, TypeError, ValueError):
                continue
            for item in (roa.get("roas") or []):
                try:
                    net = ipaddress.ip_network(item["prefix"], strict=False)
                    key = (net, asn, int(item["maxLength"]))
                except (ValueError, KeyError, TypeError):
                    continue
                # 同一 VRP 可能由多份 ROA 证书签出，取最晚的那份才是实际有效期
                prev = out.get(key)
                if prev is None or vt > prev[1]:
                    out[key] = (vf, vt)
    return out


def _aggregate(prefixes) -> list:
    """把待查前缀收敛成最少的父网段，减少 GraphQL 请求数。"""
    out = []
    for version in (4, 6):
        same = [p for p in prefixes if p.version == version]
        if same:
            out.extend(ipaddress.collapse_addresses(same))
    return out
