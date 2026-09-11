"""清洗抓取 running-config 时混入的终端分页残留。

采集日志是直接录屏得到的，里面混有分页提示符和终端光标控制字符，例如::

    " --More-- \\x08 \\x08...\\x08!\\r"                  -> "!"          (IOS XR)
    "---(more 2%)---\\r        \\rset interfaces ..."   -> "set ..."     (Junos)
    "  ---- More ----\\x1b[16D   \\x1b[16D ip address"  -> " ip address" (华为 VRP)

不能简单地把这些标记删掉：删掉后残留的空格会破坏配置的缩进层级
（块内的 ` ip address` 与块外的 `interface` 只靠列位置区分）。
所以这里按终端语义重放每一行：\\r 回行首、\\x08 退一格、ESC[nD 左移 n 列，
后续字符覆盖写入。
"""

from __future__ import annotations

import re

_PAGER_HINTS = ("--More--", "(more ", "---- More ----")
_CSI_RE = re.compile(r"\x1b\[([0-9;]*)([A-Za-z])")


def render_line(line: str) -> str:
    """按终端语义重放一行，返回屏幕上真正显示的内容。"""
    buf: list = []
    col = 0
    i = 0
    n = len(line)
    while i < n:
        ch = line[i]
        if ch == "\x1b":
            m = _CSI_RE.match(line, i)
            if m:
                col = _apply_csi(buf, col, m.group(1), m.group(2))
                i = m.end()
                continue
            i += 2          # 非 CSI 的转义序列，跳过 ESC 和后一个字符
            continue
        if ch == "\r":
            col = 0
        elif ch == "\x08":
            col = max(0, col - 1)
        elif ch == "\n":
            pass
        else:
            _put(buf, col, ch)
            col += 1
        i += 1
    return "".join(buf).rstrip()


def _put(buf: list, col: int, ch: str) -> None:
    if col < len(buf):
        buf[col] = ch
    else:
        buf.extend(" " * (col - len(buf)))
        buf.append(ch)


def _apply_csi(buf: list, col: int, params: str, final: str) -> int:
    """只处理会影响行内容的几种 CSI，其余（颜色等）直接忽略。"""
    try:
        n = int(params.split(";")[0]) if params.split(";")[0] else 1
    except ValueError:
        n = 1
    if final == "D":            # 光标左移
        return max(0, col - n)
    if final == "C":            # 光标右移
        return col + n
    if final == "G":            # 移到第 n 列
        return max(0, n - 1)
    if final == "K":            # 清除行内容
        mode = params.split(";")[0] or "0"
        if mode == "0":
            del buf[col:]
        elif mode == "1":
            for j in range(min(col + 1, len(buf))):
                buf[j] = " "
        else:
            buf.clear()
    return col


def clean_config(text: str) -> list:
    """把原始采集文本清洗为可解析的配置行列表。"""
    out = []
    # 只按 \n 切分：str.splitlines() 会把 \r 也当行分隔符，
    # 那样回车覆盖的语义就丢了，行号也对不上原文件。
    for raw in text.split("\n"):
        if "\x08" in raw or "\r" in raw or "\x1b" in raw:
            line = render_line(raw)
        else:
            line = raw.rstrip()
        # 少数分页标记后面没跟覆盖字符，重放后仍留在行首，这里再兜底剥掉。
        if any(h in line for h in _PAGER_HINTS):
            line = _strip_pager(line)
        out.append(line)
    return out


def _strip_pager(line: str) -> str:
    line = re.sub(r"-{2,}\s*More\s*-{2,}", "", line)
    line = re.sub(r"-{2,}\(more[^)]*\)-{2,}", "", line)
    return line.rstrip()


def load_config(path) -> list:
    """读取并清洗一个 running-config 采集文件。

    必须用 newline="" 打开：默认的 universal newlines 会把裸 \\r 翻译成 \\n，
    分页标记的覆盖语义就还原不出来了。
    """
    with open(path, "r", encoding="utf-8", errors="replace", newline="") as fh:
        return clean_config(fh.read())
