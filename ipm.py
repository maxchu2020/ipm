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
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from ipmlib import irr as irr_mod
from ipmlib import roa as roa_mod
from ipmlib.parsers import parse_file
from ipmlib.report import render_text, role_of
from ipmlib.rov import evaluate, load_list
from ipmlib.rov_report import render as render_rov
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
    print(f"[1/2] 取 ROA 数据（{len(prefixes)} 条前缀）…", file=sys.stderr)
    vrps, meta = roa_mod.fetch_vrps(prefixes, args.roa_cache,
                                    refresh=args.refresh_roa)
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
    print(render_rov(results, meta, args.whois_server))

    if args.csv:
        _write_rov_csv(results, args.csv)
        print(f"[ok] 明细已写入 {args.csv}")
    if args.json:
        _write_rov_json(results, meta, args.json)
        print(f"[ok] 结构化结果已写入 {args.json}")
    return 0


def _write_rov_csv(results, path) -> None:
    with open(path, "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.writer(fh)
        w.writerow(["prefix", "announced_origin", "roa_state", "roa_origins",
                    "roa_covering", "irr_origins", "irr_sources", "irr_error",
                    "verdict", "matched"])
        for r in results:
            w.writerow([
                str(r.prefix),
                r.origin if r.announced else "NO",
                r.roa_state,
                " ".join(f"AS{a}" for a in r.roa_origins),
                " ".join(f"{v.network}@AS{v.asn}(<={v.max_length})"
                         for v in r.roa_covering),
                " ".join(f"AS{a}" for a in r.irr_origins),
                " ".join(sorted({x.source for x in r.irr_routes})),
                r.irr_error,
                r.verdict,
                "Y" if r.matched else "N",
            ])


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
    r.add_argument("--refresh-roa", action="store_true",
                   help="强制重新下载 ROA 全量导出（约 100MB，需数分钟）")
    r.add_argument("--whois-server", default=irr_mod.WHOIS_SERVER,
                   help=f"IRR whois 服务器（默认 {irr_mod.WHOIS_SERVER}）")
    r.add_argument("--irr-delay", type=float, default=0.4, metavar="SEC",
                   help="IRR 查询间隔秒数，避免触发速率限制（默认 0.4）")
    r.add_argument("--no-irr", action="store_true",
                   help="跳过 IRR 查询，只做 ROA 校验（离线可用）")
    r.add_argument("--csv", type=Path, help="把逐条结果另存为 CSV")
    r.add_argument("--json", type=Path, help="把结果另存为 JSON")
    r.set_defaults(func=cmd_rov)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
