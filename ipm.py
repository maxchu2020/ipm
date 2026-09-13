#!/usr/bin/env python3
"""ipm — 网络 IP 管理工具。

功能一：根据 router running-config 统计 IP 使用情况。

    ./ipm.py stats                      # 汇总 + 明细
    ./ipm.py stats --no-detail          # 只看汇总
    ./ipm.py stats --csv used.csv       # 另存逐条明细
    ./ipm.py stats --json used.json     # 另存结构化结果
"""

from __future__ import annotations

import argparse
import csv
import datetime
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from ipmlib import irr as irr_mod
from ipmlib import mailer
from ipmlib import scan as scan_mod
from ipmlib import scan_report
from ipmlib import roa as roa_mod
from ipmlib.parsers import parse_file
from ipmlib.report import render_text, role_of
from ipmlib.rov import evaluate, load_list
from ipmlib.rov_report import days_until, effective_vrps, expiry_stamp
from ipmlib.rov_report import render as render_rov
from ipmlib.rov_report import subject_line
from ipmlib.stats import (block_of, build_report, load_prefixes,
                          split_prefix, unregistered_blocks)

BASE = Path(__file__).resolve().parent


def collect(config_dir: Path):
    files = sorted(p for p in config_dir.iterdir()
                   if p.is_file() and p.suffix in {".log", ".txt", ".cfg", ".conf"})
    if not files:
        raise SystemExit(f"{config_dir} 下没有找到配置文件")
    parsed = []
    for path in files:
        try:
            parsed.append(parse_file(path))
        except Exception as exc:                      # 单台设备解析失败不影响整体统计
            print(f"[warn] 解析 {path.name} 失败：{exc}", file=sys.stderr)
    return parsed


def cmd_stats(args) -> int:
    if not 1 <= args.split_len <= 32:
        raise SystemExit("--split-len 只能取 1..32")
    if not 1 <= args.split_len6 <= 128:
        raise SystemExit("--split-len6 只能取 1..128")
    parsed = collect(args.config_dir)
    entries = [e for f in parsed for e in f.entries]
    prefixes = load_prefixes(args.prefix_list)
    report = build_report(entries, prefixes, parsed)

    print(render_text(report, show_detail=args.detail,
                      show_outside=args.outside, show_inventory=args.inventory,
                      split_len=args.split_len, hide_empty=args.hide_empty,
                      split_len6=args.split_len6))

    plens = {4: args.split_len, 6: args.split_len6}
    if args.csv:
        _write_csv(report, args.csv, plens)
        print(f"[ok] 明细已写入 {args.csv}")
    if args.json:
        _write_json(report, args.json, plens)
        print(f"[ok] 结构化结果已写入 {args.json}")
    return 0


def _owner_of(report, net):
    for st in report.prefix_stats:
        if any(s.network == net for s in st.subnets):
            return str(st.prefix)
    return ""


def _write_csv(report, path, plens) -> None:
    with open(path, "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.writer(fh)
        w.writerow(["device", "source", "platform", "interface", "vrf", "family",
                    "address", "subnet", "prefixlen", "subnet_size", "owned_prefix",
                    "block", "block_len", "in_owned", "role", "preconfigure",
                    "shutdown", "description"])
        for e in sorted(report.entries,
                        key=lambda x: (x.device, x.network.version,
                                       x.network.network_address, x.interface)):
            owner = _owner_of(report, e.network)
            w.writerow([e.device, e.source, e.platform, e.interface, e.vrf, e.family,
                        e.address, str(e.network), e.prefixlen,
                        e.network.num_addresses, owner,
                        str(block_of(e.network, plens[e.network.version])),
                        plens[e.network.version],
                        "Y" if owner else "N",
                        role_of(e), "Y" if e.preconfigure else "",
                        "Y" if e.shutdown else "", e.description])


def _write_json(report, path, plens) -> None:
    data = {
        "split_len": {"ipv4": plens[4], "ipv6": plens[6]},
        "devices": report.devices,
        "sources": report.sources,
        "prefixes": [{
            "prefix": str(st.prefix),
            "family": st.family,
            "unit": "addresses" if st.family == "ipv4" else "/48",
            "split_len": plens[st.prefix.version],
            "capacity": st.capacity,
            "used": st.used,
            "free": st.free,
            "ratio": round(st.ratio, 6),
            "subnets": [{
                "subnet": str(s.network),
                "size": s.size,
                "uses": [_entry_json(e) for e in s.entries],
            } for s in st.subnets],
            "blocks": [{
                "block": str(b.block),
                "capacity": b.capacity,
                "used": b.used,
                "free": b.free,
                "ratio": round(b.ratio, 6),
                "subnets": [str(x.network) for x in b.subnets],
            } for b in split_prefix(st, plens[st.prefix.version])
              if not b.empty or st.prefix.version == 4],
        } for st in report.prefix_stats],
        "unregistered": {
            f"ipv{v}": [{
                "block": str(b.block),
                "subnets": [{
                    "subnet": str(x.network),
                    "size": x.size,
                    "uses": [_entry_json(e) for e in x.entries],
                } for x in b.subnets],
                "subnet_area": b.used,
            } for b in unregistered_blocks(report, v, plens[v])]
            for v in (4, 6)
        },
        "overlapping": [str(s.network) for s in report.overlapping],
    }
    Path(path).write_text(json.dumps(data, indent=2, ensure_ascii=False),
                          encoding="utf-8")


def _entry_json(e):
    return {"device": e.device, "interface": e.interface, "vrf": e.vrf,
            "family": e.family, "address": e.address, "role": role_of(e),
            "preconfigure": e.preconfigure, "shutdown": e.shutdown,
            "description": e.description}


def cmd_rov(args) -> int:
    rows = load_list(args.list)
    prefixes = [net for net, _ in rows]
    how = "复用缓存" if args.roa_max_age else "重新下载"
    print(f"[1/2] 取 ROA 数据（{len(prefixes)} 条前缀，{how}）…", file=sys.stderr)
    vrps, meta = roa_mod.fetch_vrps(prefixes, args.roa_cache,
                                    max_age=args.roa_max_age * 60)
    meta["relevant_vrps"] = len(vrps)

    if args.no_irr:
        irr_results, irr_errors = {}, {}
        print("[2/2] 已跳过 IRR 查询（--no-irr）", file=sys.stderr)
    else:
        def progress(i, total, prefix):
            # 重定向到文件时逐行刷进度会把日志刷爆，只在终端里做原地刷新
            if sys.stderr.isatty():
                end = "\n" if i == total else "\r"
                print(f"[2/2] IRR 查询 {i}/{total} {prefix}      ",
                      file=sys.stderr, end=end)
            elif i == total:
                print(f"[2/2] IRR 查询完成（{total} 条）", file=sys.stderr)

        irr_results, irr_errors = irr_mod.query(
            prefixes, server=args.whois_server, delay=args.irr_delay,
            progress=progress)

    results = evaluate(rows, vrps, irr_results, irr_errors)
    report = render_rov(results, meta, args.whois_server)

    attachments = []
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(report + "\n", encoding="utf-8")
        attachments.append(args.report)
        print(f"[ok] 报表已写入 {args.report}")
    else:
        # 没指定落盘位置就直接打到 stdout；定时任务用 --report 免得日志无限膨胀
        print(report)

    if args.csv:
        _write_rov_csv(results, args.csv)
        attachments.append(args.csv)
        print(f"[ok] 明细已写入 {args.csv}")
    if args.json:
        _write_rov_json(results, meta, args.json)
        attachments.append(args.json)
        print(f"[ok] 结构化结果已写入 {args.json}")

    if args.email:
        return _send_rov_email(args, results, report, attachments)
    return 0


def _send_rov_email(args, results, report, attachments) -> int:
    cfg = mailer.MailConfig(mailer.load_env(args.env))
    subject = subject_line(results)
    try:
        sent = mailer.send(cfg, subject, report, attachments)
    except Exception as exc:
        # 邮件发不出去不该让定时任务被判定成校验失败，但必须留下明确记录
        print(f"[error] 邮件发送失败：{exc}", file=sys.stderr)
        return 2
    print(f"[ok] 邮件已发送给 {len(sent)} 个地址：{subject}")
    return 0


def _write_rov_csv(results, path) -> None:
    with open(path, "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.writer(fh)
        w.writerow(["prefix", "announced_origin", "roa_state", "roa_origins",
                    "roa_covering", "roa_expiry", "roa_expiry_days",
                    "roa_expiry_kind", "irr_origins", "irr_sources",
                    "irr_error", "verdict", "matched"])
        for r in results:
            w.writerow([
                str(r.prefix),
                r.origin if r.announced else "NO",
                r.roa_state,
                " ".join(f"AS{a}" for a in r.roa_origins),
                " ".join(f"{v.network}@AS{v.asn}(<={v.max_length})"
                         for v in r.roa_covering),
                _expiry_date(r), _expiry_days(r), _expiry_kind(r),
                " ".join(f"AS{a}" for a in r.irr_origins),
                " ".join(sorted({x.source for x in r.irr_routes})),
                r.irr_error,
                r.verdict,
                "Y" if r.matched else "N",
            ])


def _expiry_date(r) -> str:
    ts = expiry_stamp(r)
    return datetime.datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d") if ts else ""


def _expiry_days(r):
    ts = expiry_stamp(r)
    return days_until(ts) if ts is not None else ""


def _expiry_kind(r) -> str:
    vrps = [v for v in effective_vrps(r) if v.expiry]
    return vrps[0].expiry_kind if vrps else ""


def _write_rov_json(results, meta, path) -> None:
    data = {
        "roa_meta": meta,
        "results": [{
            "prefix": str(r.prefix),
            "announced_origin": r.origin,
            "announced": r.announced,
            "roa_state": r.roa_state,
            "roa_covering": [v.as_dict() for v in r.roa_covering],
            "roa_matched": [v.as_dict() for v in r.roa_matched],
            "roa_usable": [v.as_dict() for v in r.roa_usable],
            "roa_expiry": _expiry_date(r),
            "roa_expiry_days": _expiry_days(r),
            "roa_expiry_kind": _expiry_kind(r),
            "irr_routes": [{"prefix": str(x.network), "origin": x.origin,
                            "source": x.source, "descr": x.descr,
                            "mnt_by": x.mnt_by} for x in r.irr_routes],
            "irr_error": r.irr_error,
            "verdict": r.verdict,
            "matched": r.matched,
        } for r in results],
    }
    Path(path).write_text(json.dumps(data, indent=2, ensure_ascii=False),
                          encoding="utf-8")


def cmd_scan(args) -> int:
    if not scan_mod.nmap_available():
        raise SystemExit("未找到 nmap，请先安装：dnf install -y nmap")

    prefixes = [p for p in load_prefixes(args.prefix_list) if p.version == 4]
    if not prefixes:
        raise SystemExit(f"{args.prefix_list} 里没有 IPv4 前缀")

    def progress(i, total, prefix):
        msg = f"[{i}/{total}] 扫描 {prefix} …"
        if sys.stderr.isatty():
            print(msg, file=sys.stderr, end="\r")
        else:
            print(msg, file=sys.stderr)

    result = scan_mod.scan(prefixes, tcp=not args.icmp_only,
                           block_len=args.block_len, timeout=args.timeout,
                           progress=progress)
    if sys.stderr.isatty():
        print(file=sys.stderr)

    report = scan_report.render(result, args.block_len)
    attachments = []
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(report + "\n", encoding="utf-8")
        attachments.append(args.report)
        print(f"[ok] 报表已写入 {args.report}")
    else:
        print(report)

    if args.csv:
        _write_scan_csv(result, args.csv)
        attachments.append(args.csv)
        print(f"[ok] 明细已写入 {args.csv}")
    if args.json:
        _write_scan_json(result, args.json)
        attachments.append(args.json)
        print(f"[ok] 结构化结果已写入 {args.json}")

    if args.email:
        cfg = mailer.MailConfig(mailer.load_env(args.env))
        subject = scan_report.subject_line(result, args.block_len)
        try:
            sent = mailer.send(cfg, subject, report, attachments)
        except Exception as exc:
            print(f"[error] 邮件发送失败：{exc}", file=sys.stderr)
            return 2
        print(f"[ok] 邮件已发送给 {len(sent)} 个地址：{subject}")
    return 0


def _write_scan_csv(result, path) -> None:
    with open(path, "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.writer(fh)
        w.writerow(["block", "owned_prefix", "total", "alive", "alive_ratio",
                    "alive_ips"])
        for b in result.blocks:
            w.writerow([str(b.block), str(b.prefix), b.total, b.alive_count,
                        f"{b.ratio:.6f}",
                        " ".join(str(ip) for ip in b.alive)])


def _write_scan_json(result, path) -> None:
    data = {
        "method": result.method,
        "started": result.started,
        "elapsed_sec": round(result.elapsed, 1),
        "total": result.total,
        "alive": result.alive_count,
        "ratio": round(result.ratio, 6),
        "errors": result.errors,
        "blocks": [{
            "block": str(b.block),
            "owned_prefix": str(b.prefix),
            "total": b.total,
            "alive": b.alive_count,
            "ratio": round(b.ratio, 6),
            "alive_ips": [str(ip) for ip in b.alive],
        } for b in result.blocks],
    }
    Path(path).write_text(json.dumps(data, indent=2, ensure_ascii=False),
                          encoding="utf-8")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="ipm", description="根据 router config 统计 IP 使用情况")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("stats", help="统计接口地址对自有前缀的占用")
    s.add_argument("--config-dir", type=Path, default=BASE / "running-config",
                   help="running-config 目录（默认 ./running-config）")
    s.add_argument("--prefix-list", type=Path, default=BASE / "prefix.list",
                   help="自有前缀列表（默认 ./prefix.list）")
    s.add_argument("--no-detail", dest="detail", action="store_false",
                   help="只输出汇总，不展开明细")
    s.add_argument("--no-outside", dest="outside", action="store_false",
                   help="不输出「不在自有前缀内」的地址")
    s.add_argument("--no-inventory", dest="inventory", action="store_false",
                   help="不输出采集与解析覆盖清单")
    s.add_argument("--split-len", type=int, default=24, metavar="N",
                   help="IPv4 自有前缀切成 /N 的块来统计（默认 24）")
    s.add_argument("--split-len6", type=int, default=48, metavar="N",
                   help="IPv6 按 /N 为单位统计（默认 48）")
    s.add_argument("--hide-empty", action="store_true",
                   help="/N 粒度表里不列出完全空闲的块")
    s.add_argument("--csv", type=Path, help="把逐条明细另存为 CSV")
    s.add_argument("--json", type=Path, help="把统计结果另存为 JSON")
    s.set_defaults(func=cmd_stats)

    r = sub.add_parser("rov", help="按 ROA / IRR 校验前缀的 origin 授权")
    r.add_argument("--list", type=Path, default=BASE / "ROA-IRR.list",
                   help="前缀表：第一列前缀，第二列现网 origin ASN（NO=未广播）")
    r.add_argument("--roa-cache", type=Path, default=BASE / "cache/vrps.json",
                   help="ROA VRP 缓存文件（默认 ./cache/vrps.json）")
    r.add_argument("--roa-max-age", type=int, default=0, metavar="MIN",
                   help="ROA 缓存可复用的分钟数；默认 0 表示每次都重新下载"
                        "（约 100MB，需数分钟）。调试时可设大以复用缓存")
    r.add_argument("--whois-server", default=irr_mod.WHOIS_SERVER,
                   help=f"IRR whois 服务器（默认 {irr_mod.WHOIS_SERVER}）")
    r.add_argument("--irr-delay", type=float, default=0.4, metavar="SEC",
                   help="IRR 查询间隔秒数，避免触发速率限制（默认 0.4）")
    r.add_argument("--no-irr", action="store_true",
                   help="跳过 IRR 查询，只做 ROA 校验（离线可用）")
    r.add_argument("--report", type=Path,
                   help="把报表写入文件而不是打印到 stdout（定时任务用，避免日志膨胀）")
    r.add_argument("--csv", type=Path, help="把逐条结果另存为 CSV")
    r.add_argument("--json", type=Path, help="把结果另存为 JSON")
    r.add_argument("--email", action="store_true",
                   help="把报表通过邮件推送（收件人等配置读 .env）")
    r.add_argument("--env", type=Path, default=BASE / ".env",
                   help="邮件配置文件（默认 ./.env）")
    r.set_defaults(func=cmd_rov)

    sc = sub.add_parser("scan", help="对 prefix.list 里的 IPv4 前缀做存活扫描")
    sc.add_argument("--prefix-list", type=Path, default=BASE / "prefix.list",
                    help="自有前缀列表（默认 ./prefix.list，只取 IPv4）")
    sc.add_argument("--block-len", type=int, default=24, metavar="N",
                    help="按 /N 为单位统计（默认 24）")
    sc.add_argument("--icmp-only", action="store_true",
                    help="只用 ICMP 探测（快得多，但会漏掉约一半屏蔽 ICMP 的主机）")
    sc.add_argument("--timeout", type=int, default=3600, metavar="SEC",
                    help="单条前缀的扫描超时秒数（默认 3600）")
    sc.add_argument("--report", type=Path,
                    help="把报表写入文件而不是打印到 stdout")
    sc.add_argument("--csv", type=Path, help="把逐块结果另存为 CSV")
    sc.add_argument("--json", type=Path, help="把结果另存为 JSON")
    sc.add_argument("--email", action="store_true", help="把报表通过邮件推送")
    sc.add_argument("--env", type=Path, default=BASE / ".env",
                    help="邮件配置文件（默认 ./.env）")
    sc.set_defaults(func=cmd_scan)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
