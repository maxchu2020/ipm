"""把 ROA 与 IRR 的查询结果合成每条前缀的授权判定。

判定口径（ROA 优先于 IRR，与实际 prefix-filter 行为一致）：

* ``ROA-MATCH``   —— ROA 覆盖且 origin 匹配（RFC 6811 valid）
* ``ROA-INVALID`` —— 有 ROA 覆盖但没有一条匹配。**不算 match**，
  即使 IRR 里登记了也一样：RPKI invalid 会被上游直接丢弃，IRR 救不回来。
* ``IRR-MATCH``   —— 没有任何 ROA 覆盖，但 IRR 有精确 route 对象且 origin 匹配
* ``NO-AUTH``     —— 没有 ROA 覆盖，IRR 也没有匹配的 route 对象
* ``NOT-ANNOUNCED`` —— 现网未广播（第二列为 NO），无 origin 可比，单独归类
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from pathlib import Path

from . import roa as roa_mod

ROA_MATCH = "ROA-MATCH"
ROA_INVALID = "ROA-INVALID"
IRR_MATCH = "IRR-MATCH"
NO_AUTH = "NO-AUTH"
NOT_ANNOUNCED = "NOT-ANNOUNCED"
QUERY_FAILED = "QUERY-FAILED"

# 报表里的排列顺序：先看有问题的
VERDICT_ORDER = [ROA_INVALID, NO_AUTH, IRR_MATCH, ROA_MATCH,
                 NOT_ANNOUNCED, QUERY_FAILED]

VERDICT_DESC = {
    ROA_MATCH: "ROA 覆盖且 origin 匹配（RFC 6811 valid）",
    ROA_INVALID: "有 ROA 覆盖但 origin/maxLength 不匹配 —— 会被上游丢弃",
    IRR_MATCH: "无 ROA 覆盖，靠 IRR 精确 route 对象授权",
    NO_AUTH: "无 ROA 覆盖，IRR 也没有匹配的 route 对象",
    NOT_ANNOUNCED: "现网未广播，无 origin 可比对",
    QUERY_FAILED: "IRR 查询失败，无法判定",
}
MATCHED = {ROA_MATCH, IRR_MATCH}


@dataclass
class RovResult:
    prefix: object
    origin: object                  # int，未广播为 None
    roa_state: str                  # valid / invalid / notfound
    roa_matched: list = field(default_factory=list)
    roa_covering: list = field(default_factory=list)
    irr_routes: list = field(default_factory=list)   # 精确 route 对象（已排除伪源）
    irr_error: str = ""
    verdict: str = ""

    @property
    def announced(self) -> bool:
        return self.origin is not None

    @property
    def matched(self) -> bool:
        return self.verdict in MATCHED

    @property
    def irr_origins(self) -> list:
        seen = []
        for r in self.irr_routes:
            if r.origin not in seen:
                seen.append(r.origin)
        return seen

    @property
    def irr_matching(self) -> list:
        return [r for r in self.irr_routes if r.origin == self.origin]

    @property
    def roa_usable(self) -> list:
        """覆盖本前缀、且 maxLength 允许本前缀长度的 VRP。

        只「覆盖」是不够的：218.30.0.0/15 → AS4134 maxLength 15 覆盖了
        218.30.37.0/24 的地址空间，却授权不了这条 /24 的广播。判断「这条前缀
        上线后 ROA 能不能放行」必须看 maxLength。
        """
        return [v for v in self.roa_covering
                if self.prefix.prefixlen <= v.max_length]

    @property
    def roa_origins(self) -> list:
        seen = []
        for v in self.roa_covering:
            if v.asn not in seen:
                seen.append(v.asn)
        return seen


def load_list(path):
    """读 ROA-IRR.list：第一列前缀，第二列现网 origin ASN，NO 表示未广播。"""
    rows = []
    for lineno, raw in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 2:
            raise ValueError(f"{path}:{lineno} 缺少第二列: {raw!r}")
        try:
            net = ipaddress.ip_network(parts[0], strict=False)
        except ValueError:
            raise ValueError(f"{path}:{lineno} 前缀无法解析: {parts[0]!r}") from None
        token = parts[1].strip().upper()
        if token in ("NO", "-", "NONE"):
            origin = None
        else:
            try:
                origin = int(token.replace("AS", ""))
            except ValueError:
                raise ValueError(f"{path}:{lineno} origin 无法解析: {parts[1]!r}") from None
        rows.append((net, origin))
    return rows


def evaluate(rows, vrps, irr_results, irr_errors) -> list:
    out = []
    for net, origin in rows:
        routes = irr_results.get(net, [])
        err = irr_errors.get(net, "")

        if origin is None:
            res = RovResult(net, None, roa_mod.NOTFOUND, [],
                            roa_mod.covering(net, vrps), routes, err,
                            NOT_ANNOUNCED)
            res.roa_state = (roa_mod.VALID if res.roa_covering
                             else roa_mod.NOTFOUND)
            # 未广播时 roa_state 只表示「有没有登记」，不代表校验结论
            res.roa_state = "registered" if res.roa_covering else "none"
            out.append(res)
            continue

        state, matched, cover = roa_mod.validate(net, origin, vrps)
        res = RovResult(net, origin, state, matched, cover, routes, err)

        if state == roa_mod.VALID:
            res.verdict = ROA_MATCH
        elif state == roa_mod.INVALID:
            res.verdict = ROA_INVALID
        elif err:
            res.verdict = QUERY_FAILED          # 无 ROA 覆盖又查不到 IRR，不能瞎判
        elif res.irr_matching:
            res.verdict = IRR_MATCH
        else:
            res.verdict = NO_AUTH
        out.append(res)
    return out
