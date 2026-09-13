"""在用地址扫描报表。"""

from __future__ import annotations

import datetime as _dt

from .report import _pad, _rule, _trunc

_SUM_COLS = [("自有前缀", 20), ("总地址", 10), ("在用", 9), ("在用率", 10),
             ("/24 数", 9), ("有在用的 /24", 14)]
_BLK_COLS = [("/24 块", 20), ("所属前缀", 20), ("总数", 8), ("在用", 8),
             ("在用率", 10), ("在用地址", 46)]


def _pct(x: float) -> str:
    return f"{x * 100:.2f}%"


def _fmt_alive(block, limit: int = 4) -> str:
    if not block.alive:
        return "-"
    shown = [str(ip) for ip in block.alive[:limit]]
    if block.alive_count > limit:
        shown.append(f"…+{block.alive_count - limit}")
    return "、".join(shown)


def render(result, block_len: int = 24, width: int = 120) -> str:
    started = _dt.datetime.fromtimestamp(result.started)
    out = ["=" * width,
           f"IPv4 在用地址扫描 — 按 /{block_len} 统计",
           "=" * width,
           f"扫描范围  {len(result.prefixes)} 条自有前缀，"
           f"{result.total:,} 个地址，{len(result.blocks)} 个 /{block_len}",
           f"探测方式  {result.method}",
           f"开始时间  {started.strftime('%Y-%m-%d %H:%M:%S')}，"
           f"耗时 {result.elapsed / 60:.1f} 分钟",
           "",
           "口径说明  「在用」指该地址对探测有响应，可据此认定已分配或正在使用。",
           "          反向不成立：无响应不代表空闲 —— 本机若不在对端的管理 ACL",
           "          白名单内，地址在用也可能不响应（路由器 Loopback 就是如此）。",
           "          所以在用数是下限，不是精确值。完整分配情况见 ipm.py stats。",
           ""]

    if result.errors:
        out.append(_rule("⚠ 扫描异常", width))
        out.extend(f"  · {e}" for e in result.errors)
        out.append("")

    out.append(_rule("一、总体结果", width))
    out.append(f"  在用 {result.alive_count:,} / {result.total:,} 个地址"
               f"（{_pct(result.ratio)}）")
    nonempty = [b for b in result.blocks if b.alive]
    out.append(f"  {len(result.blocks)} 个 /{block_len} 中，{len(nonempty)} 个有在用地址，"
               f"{len(result.blocks) - len(nonempty)} 个未探测到在用地址")
    out.append("")

    out.append(_rule("二、按自有前缀汇总", width))
    out.extend(_prefix_table(result))
    out.append("")

    out.append(_rule(f"三、有在用地址的 /{block_len}（{len(nonempty)} 个）", width))
    out.extend(_block_table(sorted(nonempty, key=lambda b: -b.alive_count)))
    out.append("")

    empty = [b for b in result.blocks if not b.alive]
    if empty:
        out.append(_rule(f"四、未探测到在用地址的 /{block_len}（{len(empty)} 个）", width))
        out.extend(_empty_list(empty))
        out.append("")
    return "\n".join(out)


def _prefix_table(result) -> list:
    lines = ["  " + "".join(_pad(n, w) for n, w in _SUM_COLS).rstrip(),
             "  " + "-" * sum(w for _, w in _SUM_COLS)]
    grouped = result.by_prefix()
    for prefix in result.prefixes:
        blocks = grouped.get(prefix, [])
        total = sum(b.total for b in blocks)
        alive = sum(b.alive_count for b in blocks)
        hit = sum(1 for b in blocks if b.alive)
        lines.append("  " + "".join(_pad(v, w) for v, (_, w) in zip(
            [str(prefix), f"{total:,}", f"{alive:,}",
             _pct(alive / total if total else 0), str(len(blocks)), str(hit)],
            _SUM_COLS)).rstrip())
    lines.append("  " + "-" * sum(w for _, w in _SUM_COLS))
    lines.append("  " + "".join(_pad(v, w) for v, (_, w) in zip(
        ["合计", f"{result.total:,}", f"{result.alive_count:,}",
         _pct(result.ratio), str(len(result.blocks)),
         str(sum(1 for b in result.blocks if b.alive))], _SUM_COLS)).rstrip())
    return lines


def _block_table(blocks) -> list:
    if not blocks:
        return ["  （没有探测到任何在用地址）"]
    lines = ["  " + "".join(_pad(n, w) for n, w in _BLK_COLS).rstrip(),
             "  " + "-" * sum(w for _, w in _BLK_COLS)]
    for b in blocks:
        lines.append("  " + "".join(_pad(_trunc(v, w), w) for v, (_, w) in zip(
            [str(b.block), str(b.prefix), str(b.total), str(b.alive_count),
             _pct(b.ratio), _fmt_alive(b)], _BLK_COLS)).rstrip())
    return lines


def _empty_list(blocks, per_line: int = 5) -> list:
    """未探测到在用地址的段只列出块名，不必逐个占一行。"""
    names = [str(b.block) for b in blocks]
    return ["  " + "".join(_pad(n, 22) for n in names[i:i + per_line]).rstrip()
            for i in range(0, len(names), per_line)]


def subject_line(result, block_len: int = 24,
                 prefix: str = "[ipm] IPv4 在用地址扫描") -> str:
    head = f"{prefix} — 在用 {result.alive_count:,}/{result.total:,}（{_pct(result.ratio)}）"
    if result.errors:
        head += f"，⚠ {len(result.errors)} 段扫描异常"
    return head
