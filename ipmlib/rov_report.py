"""ROA / IRR 授权校验报表。"""

from __future__ import annotations

import datetime as _dt
from collections import Counter

from .report import _pad, _rule, _trunc
from .rov import (IRR_MATCH, MATCHED, NOT_ANNOUNCED, NO_AUTH, QUERY_FAILED,
                  ROA_INVALID, ROA_MATCH, VERDICT_DESC, VERDICT_ORDER)

_COLS = [("前缀", 20), ("现网 origin", 13), ("ROA", 10),
         ("ROA 登记 (maxLen)", 34), ("IRR 登记 (source)", 32), ("判定", 14)]


def _vrp_label(vrp, prefix) -> str:
    """精确到本前缀的 VRP 只写 ASN；less-specific 的注明来自哪条覆盖前缀。

    maxLength 不足以授权本前缀长度的，加 ✗ 标出——它只是覆盖了地址空间。
    """
    who = f"AS{vrp.asn}" if vrp.network == prefix else f"AS{vrp.asn}@{vrp.network}"
    short = "" if prefix.prefixlen <= vrp.max_length else "✗"
    return f"{who}≤{vrp.max_length}{short}"


def _fmt_roa(res) -> str:
    """优先显示真正起作用的 VRP，其余覆盖项只给条数，避免关键信息被截断。"""
    if not res.roa_covering:
        return "-"
    if res.roa_matched:
        shown = [_vrp_label(v, res.prefix) for v in res.roa_matched]
        others = len(res.roa_covering) - len(res.roa_matched)
        if others:
            shown.append(f"+{others} 条覆盖")
        return "、".join(shown)
    return "、".join(_vrp_label(v, res.prefix) for v in res.roa_covering)


def _fmt_irr(res) -> str:
    if res.irr_error:
        return f"[{res.irr_error}]"
    if not res.irr_routes:
        return "-"
    by_origin = {}
    for r in res.irr_routes:
        by_origin.setdefault(r.origin, []).append(r.source)
    return "、".join(f"AS{o}({'/'.join(sorted(set(s)))})"
                    for o, s in sorted(by_origin.items()))


def _row(res) -> str:
    origin = f"AS{res.origin}" if res.announced else "未广播"
    if res.announced:
        roa = res.roa_state
    else:
        # 未广播时关心的是「上线后 ROA 能否放行」，取决于 maxLength 够不够
        roa = "可授权" if res.roa_usable else ("长度不足" if res.roa_covering
                                               else "无登记")
    vals = [str(res.prefix), origin, roa, _fmt_roa(res), _fmt_irr(res),
            res.verdict]
    return "  " + "".join(_pad(_trunc(v, w), w)
                          for v, (_, w) in zip(vals, _COLS)).rstrip()


def _header() -> list:
    return ["  " + "".join(_pad(n, w) for n, w in _COLS).rstrip(),
            "  " + "-" * sum(w for _, w in _COLS)]


def render(results, roa_meta, irr_server: str, width: int = 128) -> str:
    counts = Counter(r.verdict for r in results)
    announced = [r for r in results if r.announced]
    matched = [r for r in announced if r.matched]

    built = roa_meta.get("buildtime", "?")
    age = roa_meta.get("cache_age_sec")
    cache_note = ("刚下载" if not age else
                  f"本地缓存 {age // 60} 分钟前取得")

    out = ["=" * width,
           "ROA / IRR 授权校验",
           "=" * width,
           f"前缀总数  {len(results)} 条（已广播 {len(announced)}，"
           f"未广播 {len(results) - len(announced)}）",
           f"ROA 数据  {roa_meta.get('source', '?')}",
           f"          构建于 {built}，{cache_note}；"
           f"命中相关 VRP {roa_meta.get('relevant_vrps', '?')} 条"
           f"（全量 {roa_meta.get('total_vrps', '?')} 条）",
           f"IRR 数据  {irr_server}，只取精确前缀的 route 对象，"
           f"已排除 IRRd 由 ROA 自动转换的 source: RPKI 伪源",
           f"生成时间  {_dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
           "",
           "判定口径  ROA 优先于 IRR：ROA 覆盖且 origin 匹配即 match；",
           "          有 ROA 覆盖但不匹配一律不算 match（上游会直接丢弃，IRR 救不回来）；",
           "          没有任何 ROA 覆盖时，IRR 有精确 route 且 origin 匹配才算 match。",
           ""]

    out.append(_rule("一、总体结果", width))
    if announced:
        rate = len(matched) / len(announced) * 100
        out.append(f"  已广播的 {len(announced)} 条中，{len(matched)} 条有授权"
                   f"（{rate:.1f}%），{len(announced) - len(matched)} 条无授权")
    out.append("")
    out.append("  " + _pad("判定", 16) + _pad("条数", 8) + "说明")
    out.append("  " + "-" * 100)
    for verdict in VERDICT_ORDER:
        n = counts.get(verdict, 0)
        if n:
            out.append("  " + _pad(verdict, 16) + _pad(str(n), 8)
                       + VERDICT_DESC[verdict])
    out.append("")

    sections = [
        ("二、ROA-INVALID —— 有 ROA 覆盖但不匹配（最高优先级，会被丢弃）", ROA_INVALID),
        ("三、NO-AUTH —— 既无 ROA 覆盖也无 IRR 授权", NO_AUTH),
        ("四、IRR-MATCH —— 仅靠 IRR 授权（建议补 ROA）", IRR_MATCH),
        ("五、ROA-MATCH —— ROA 校验通过", ROA_MATCH),
        ("六、NOT-ANNOUNCED —— 现网未广播", NOT_ANNOUNCED),
        ("七、QUERY-FAILED —— IRR 查询失败", QUERY_FAILED),
    ]
    for title, verdict in sections:
        rows = [r for r in results if r.verdict == verdict]
        if not rows:
            continue
        out.append(_rule(f"{title}（{len(rows)} 条）", width))
        if verdict == NOT_ANNOUNCED:
            out.extend(_unannounced_summary(rows))
        out.extend(_header())
        out.extend(_row(r) for r in rows)
        out.append("")

    return "\n".join(out)


def _unannounced_summary(rows) -> list:
    """未广播前缀看的是「上线后能不能通过校验」，而不是「有没有 ROA 记录」。"""
    both = [r for r in rows if r.roa_usable and r.irr_routes]
    roa_only = [r for r in rows if r.roa_usable and not r.irr_routes]
    irr_only = [r for r in rows if not r.roa_usable and r.irr_routes]
    neither = [r for r in rows if not r.roa_usable and not r.irr_routes]
    short = [r for r in rows if not r.roa_usable and r.roa_covering]
    return [f"  若要上线，现有登记能否放行：ROA+IRR 都可 {len(both)} 条，"
            f"仅 ROA 可 {len(roa_only)} 条，仅 IRR 有 {len(irr_only)} 条，"
            f"两者都没有 {len(neither)} 条",
            f"  其中 {len(short)} 条虽被 less-specific 的 ROA 覆盖，但 maxLength "
            f"不足以授权本前缀长度（表中标 ✗），上线前需要补 ROA",
            "  （未广播本身不是问题；「已登记未广播」是可回收或待上线，"
            "「两者都没有」则是纯空闲）", ""]
