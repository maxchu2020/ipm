"""ROA / IRR 授权校验报表。"""

from __future__ import annotations

import datetime as _dt
from collections import Counter

from .report import _pad, _rule, _trunc
from .rov import (IRR_MATCH, MATCHED, NOT_ANNOUNCED, NO_AUTH, QUERY_FAILED,
                  ROA_INVALID, ROA_MATCH, VERDICT_DESC, VERDICT_ORDER)

_COLS = [("前缀", 20), ("现网 origin", 12), ("ROA", 10),
         ("ROA 登记 (maxLen)", 30), ("ROA 到期", 20),
         ("IRR 登记 (source)", 24), ("判定", 14)]

# 到期预警阈值（天）
EXPIRY_CRITICAL = 14
EXPIRY_WARN = 30


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


def _fmt_expiry(res) -> str:
    """给出真正起作用那条 VRP 的到期日；剩余天数少的加标记。"""
    vrps = res.roa_matched or res.roa_usable or res.roa_covering
    days = _min_days(vrps)
    if days is None:
        return "-"
    date = _dt.datetime.utcfromtimestamp(
        min(v.expiry for v in vrps if v.expiry)).strftime("%Y-%m-%d")
    if days < 0:
        return f"{date} 已过期!"
    if days < EXPIRY_CRITICAL:
        return f"{date} 剩{days}天!!"
    if days < EXPIRY_WARN:
        return f"{date} 剩{days}天!"
    return f"{date} 剩{days}天"


def days_until(stamp) -> int:
    """距 stamp 还有几天，向上取整。

    向下取整会系统性少算一天（3 天后到期会显示成「剩 2 天」），
    到期预警宁可说「还剩 N 天」也不要把时间说短。
    """
    now = _dt.datetime.now(_dt.timezone.utc).timestamp()
    return -int(-(stamp - now) // 86400)


def effective_vrps(res) -> list:
    """真正决定这条前缀命运的 VRP：优先匹配项，其次长度够用的覆盖项。"""
    return res.roa_matched or res.roa_usable or res.roa_covering


def expiry_stamp(res):
    stamps = [v.expiry for v in effective_vrps(res) if v.expiry]
    return min(stamps) if stamps else None


def _min_days(vrps):
    """这些 VRP 中最早的到期日距今多少天；没有可用到期信息则返回 None。"""
    stamps = [v.expiry for v in vrps if v.expiry]
    return days_until(min(stamps)) if stamps else None


def _row(res) -> str:
    origin = f"AS{res.origin}" if res.announced else "未广播"
    if res.announced:
        roa = res.roa_state
    else:
        # 未广播时关心的是「上线后 ROA 能否放行」，取决于 maxLength 够不够
        roa = "可授权" if res.roa_usable else ("长度不足" if res.roa_covering
                                               else "无登记")
    vals = [str(res.prefix), origin, roa, _fmt_roa(res), _fmt_expiry(res),
            _fmt_irr(res), res.verdict]
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
    cache_note = _freshness(roa_meta)

    out = ["=" * width,
           "ROA / IRR 授权校验",
           "=" * width,
           f"前缀总数  {len(results)} 条（已广播 {len(announced)}，"
           f"未广播 {len(results) - len(announced)}）",
           f"ROA 数据  {roa_meta.get('source', '?')}",
           f"          数据构建于 {built}（{cache_note}）；"
           f"命中相关 VRP {roa_meta.get('relevant_vrps', '?')} 条"
           f"（全量 {roa_meta.get('total_vrps', '?')} 条）",
           f"ROA 到期  {roa_meta.get('expiry_source', '?')}",
           f"IRR 数据  {irr_server}，只取精确前缀的 route 对象，"
           f"已排除 IRRd 由 ROA 自动转换的 source: RPKI 伪源",
           f"生成时间  {_dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
           "",
           "判定口径  ROA 优先于 IRR：ROA 覆盖且 origin 匹配即 match；",
           "          有 ROA 覆盖但不匹配一律不算 match（上游会直接丢弃，IRR 救不回来）；",
           "          没有任何 ROA 覆盖时，IRR 有精确 route 且 origin 匹配才算 match。",
           ""]

    if roa_meta.get("expiry_kind") == "chain":
        out.append("  ⚠ 本次没取到 ROA 证书的 validTo，到期列用的是 rpki.json 的")
        out.append("    验证链有效期（受 manifest/CRL 约束，通常只有几天），"
                   "不代表 ROA 真的快过期。")
        out.append("")

    out.extend(_expiry_section(results, width))
    out.append(_rule("一、总体结果", width))
    if announced:
        rate = len(matched) / len(announced) * 100
        out.append(f"  已广播的 {len(announced)} 条中，{len(matched)} 条有授权"
                   f"（{rate:.1f}%），{len(announced) - len(matched)} 条无授权")
    out.extend(_expiry_overview(results))
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


def _expiry_overview(results) -> list:
    """ROA 到期分布——没有触发预警时也要让人看到「最早哪天到期」。"""
    days = [d for d in (_min_days(effective_vrps(r)) for r in results)
            if d is not None]
    if not days:
        return []
    days.sort()
    buckets = [("已过期", lambda d: d < 0),
               ("30 天内", lambda d: 0 <= d < 30),
               ("30-90 天", lambda d: 30 <= d < 90),
               ("90-180 天", lambda d: 90 <= d < 180),
               ("180 天以上", lambda d: d >= 180)]
    parts = [f"{name} {sum(1 for d in days if pred(d))} 条"
             for name, pred in buckets if any(pred(d) for d in days)]
    return ["", f"  ROA 到期分布（{len(days)} 条有 ROA 覆盖）：" + "，".join(parts),
            f"  最早到期 {min(days)} 天后，中位 {days[len(days) // 2]} 天"]


def _expiry_section(results, width: int) -> list:
    """ROA 到期预警：过期或临近到期的 ROA 会让广播从 valid 掉成 invalid。"""
    rows = []
    for r in results:
        vrps = r.roa_matched or r.roa_usable
        days = _min_days(vrps)
        if days is not None and days < EXPIRY_WARN:
            rows.append((days, r))
    if not rows:
        return []

    rows.sort(key=lambda x: x[0])
    out = [_rule("⚠ ROA 到期预警", width),
           f"  {len(rows)} 条前缀依赖的 ROA 将在 {EXPIRY_WARN} 天内到期。"
           "ROA 过期后该广播会从 valid 掉成 invalid，被上游丢弃。",
           "  " + _pad("前缀", 20) + _pad("origin", 12) + _pad("剩余", 10)
           + _pad("到期日", 14) + "ROA",
           "  " + "-" * 96]
    for days, r in rows:
        vrps = r.roa_matched or r.roa_usable
        stamp = min(v.expiry for v in vrps if v.expiry)
        out.append("  " + _pad(str(r.prefix), 20)
                   + _pad(f"AS{r.origin}" if r.announced else "未广播", 12)
                   + _pad(f"{days} 天" if days >= 0 else "已过期", 10)
                   + _pad(_dt.datetime.utcfromtimestamp(stamp).strftime("%Y-%m-%d"), 14)
                   + "、".join(_vrp_label(v, r.prefix) for v in vrps))
    out.append("")
    return out


def subject_line(results, prefix: str = "[ipm] ROA/IRR 校验") -> str:
    """邮件标题直接带结论——收件人不展开附件也能知道要不要处理。"""
    announced = [r for r in results if r.announced]
    bad = [r for r in results if r.verdict in (ROA_INVALID, NO_AUTH)]
    failed = [r for r in results if r.verdict == QUERY_FAILED]
    expiring = [r for r in results
                if (_min_days(effective_vrps(r)) or 999) < EXPIRY_WARN
                and r.announced]

    alerts = []
    if bad:
        alerts.append(f"{len(bad)} 条无授权")
    if expiring:
        alerts.append(f"{len(expiring)} 条 ROA 将到期")
    if failed:
        alerts.append(f"{len(failed)} 条查询失败")

    if alerts:
        return f"{prefix} ⚠ " + "，".join(alerts)
    matched = sum(1 for r in announced if r.matched)
    return f"{prefix} 正常 — 已广播 {matched}/{len(announced)} 条授权有效"


def _freshness(roa_meta) -> str:
    """说清楚数据有多新——是刚下的还是复用了旧缓存，以及数据源本身有多旧。"""
    from .roa import STALE_BUILDTIME, buildtime_age

    parts = []
    age = buildtime_age(roa_meta)
    if age is None:
        parts.append("构建时间未知")
    else:
        mins = int(age // 60)
        parts.append(f"{mins} 分钟前" if mins < 180
                     else f"{mins // 60} 小时前")
        if age > STALE_BUILDTIME:
            parts.append("⚠ 数据源偏旧")

    if roa_meta.get("from_cache"):
        cached = roa_meta.get("cache_age_sec") or 0
        parts.append(f"⚠ 复用了 {cached // 60} 分钟前的本地缓存")
    else:
        parts.append("本次重新下载")
    return "，".join(parts)
