# ipm — 网络 IP 管理

## 功能一：根据 router config 统计 IP 使用情况

从 `running-config/` 下的设备配置中解析接口地址，按 `prefix.list` 里的自有前缀
统计占用率，并列出每条子网落在哪台设备的哪个接口上。

```bash
./ipm.py stats                    # 汇总 + 明细（默认）
./ipm.py stats --no-detail        # 只看汇总表
./ipm.py stats --csv used.csv     # 逐条明细另存 CSV
./ipm.py stats --json used.json   # 结构化结果另存 JSON
```

常用参数：`--config-dir`（默认 `./running-config`）、`--prefix-list`（默认
`./prefix.list`）、`--no-outside`（不输出非自有前缀的地址）、`--no-inventory`（不输出解析覆盖清单）、
`--split-len N`（IPv4 按 /N 切块，默认 24）、`--split-len6 N`（IPv6 按 /N 为单位，
默认 48）、`--hide-empty`（IPv4 切块表里不列完全空闲的块）。

### 统计口径

- **以接口所在的整条子网计入占用**，而不是单个 IP。一条 `/30` 互联算 4 个地址，
  `/31` 算 2 个，Loopback `/32` 算 1 个。
- IPv4 自有前缀会**按 `/24` 切块逐块统计**（`--split-len` 可改）。跨块的大网段
  （例如一条 `/22` 整体分给客户）按交集分摊到它覆盖的每个块，因此逐块已用之和
  始终等于前缀汇总的已用。前缀本身比 `/24` 更具体时整条作为一块。
- 同一子网出现在多处（互联两端、VRF 复用 Loopback、预配置的备用板卡）时，
  **容量只计一次**，但明细里所有出现位置都会列出来。
- 子网之间嵌套或相邻时先折叠再计面积，不会重复计算。
- `interface preconfigure`（硬件未上架）和 `shutdown` 的接口**计入占用** ——
  地址已经分配出去了 —— 明细的「状态」列标为 `预配` / `shut`。
- Junos `groups` 下的地址只有在 `apply-groups` 里出现才算生效。
- IPv4 按**地址数**统计，粒度 `/24`；IPv6 按 **`/48` 块数**统计，粒度也是 `/48`
  （`--split-len6` 可改）—— v6 按地址数算没有可读性，一个 `/48` 里配多少条链路
  都只算 1 个单位。`/32` 含 65,536 个 `/48`，`/36` 含 4,096 个。
- 一条前缀能切出的块超过 4,096 个时（例如 v6 的 `/32`），切块表只列出**有使用**的
  块，空闲块数以数字给出，不逐条枚举。
- 不落在任何自有前缀内的地址（对端互联、上游分配、IX LAN、OOB 管理网）也按
  `/24`（v4）/ `/48`（v6）归并成块，作为**「未登记」**部分单独列出。这些块的容量
  不归我方支配，所以不给占用率，也不并入自有前缀的统计；主指标是「我们在里面占了
  多少条子网 / 多少条地址条目」。子网本身比块还大时（例如 IX 的 `/20` LAN）
  按它自己成块。

### 报表结构

| 小节 | 内容 |
| --- | --- |
| ⚠ | 解析告警：漏解析、hostname 取不到、同名设备、可疑掩码 |
| 一 | IPv4 自有前缀占用汇总（容量 / 已用 / 空闲 / 占用率 / 子网数） |
| 二 | **IPv4 `/24` 粒度占用**：【自有前缀】逐块容量/已用/占用率 +【未登记】逐块子网数/条目数 |
| 三 | IPv6 自有前缀占用汇总（单位 `/48`） |
| 四 | **IPv6 `/48` 粒度占用**：【自有前缀】+【未登记】两部分，同上 |
| 五 | 采集与解析覆盖：逐文件列出平台、设备、v4/v6 条数、命中自有前缀数 |
| 六 | IPv4 占用明细，按 `/24` 分组展开到设备、接口、VRF、角色、描述 |
| 七 | IPv6 占用明细，按 `/48` 分组 |
| 八 | 未登记地址明细，按 `/24` / `/48` 分组展开 |
| 九 | 异常：与自有前缀部分重叠 / 反包含的子网（正常情况下为空） |

`prefix.list` 里没有登记 IPv6 前缀时，第四节算不出占用率，会退而按 `/32` 归并
把在用的 `/48` 列出来；补上 v6 前缀后自动切换为占用率视图。

第五节的「采集与解析覆盖」用来核对有没有整台设备被漏掉 —— 漏解析一台设备只会
让占用率悄悄偏低，不会报错，所以必须逐文件可核对。`tests/` 里有对应的回归测试：
任何一个采集文件解析不出地址、或取不到 hostname，测试就会失败。

「角色」按以下顺序判定，推不出来时标为 `未标注`（不硬套）：

1. 描述开头的方括号标签：`[TRANSIT]` / `[BB]` / `[CUSTOMER]` / `[PEERING]` /
   `[INTERNAL]` / `[OOB]` / `[MGMT]`（ANET 设备的约定）
2. CN2 / 163 设备的命名约定：`To <对端>-AS<号>-P/-C/-T` 和 `To <客户>-STATIC-C`，
   后缀 `-P` 对等、`-C` 客户、`-T` 上游
3. 描述里出现 `CTVPN` / `-GIA-` / `-DIA-`，或 VRF 以 `CTVPN` 开头 → 客户业务
4. Loopback 接口 → `LOOPBACK`

当前数据下约 70% 的地址能判定出角色。

### 支持的配置格式

| 平台 | 接口地址语法 | VRF 语法 | 块结束 |
| --- | --- | --- | --- |
| Cisco IOS XR | `ipv4 address A MASK` | `vrf X` | `!` |
| Cisco IOS / IOS-XE | `ip address A MASK` | `vrf forwarding X` | `!` |
| Cisco NX-OS | `ip address A/len` | `vrf member X` | 空行 |
| Huawei VRP | `ip address A MASK` | `ip binding vpn-instance X` | `#` |
| Juniper Junos | `set interfaces … family inet address A/len` | `routing-instances` | 一行一条 |

前四种都是「顶格 `interface` 起、缩进行属于该块」的结构，差异只在关键字上，
因此用 `Dialect` 描述方言、共用一套块遍历逻辑（`ipmlib/parsers.py`）。

平台识别先看横幅（`!! IOS XR`、`Software Version V800R`、`Bios:version`、
`Building configuration`、`set version`）；横幅被分页截断时，再按配置里实际
出现的关键字（`ipv4 address` / `ip address A/len` / `vrf member` /
`ip binding vpn-instance`）投票反推 —— 关键字是配置本身的一部分，比横幅可靠。

采集日志是录屏得到的，混有终端分页残留，`ipmlib/cleaner.py` 按终端语义重放
每一行来还原真实内容：

| 平台 | 分页残留 | 还原方式 |
| --- | --- | --- |
| IOS XR | `--More--` + `\x08` 退格 | 退格回退光标，后续字符覆盖 |
| Junos | `---(more N%)---` + `\r` | 回车回行首，后续字符覆盖 |
| Huawei VRP | `---- More ----` + `ESC[16D` | CSI 左移光标，后续字符覆盖 |

不能直接删标记，否则残留的空格会破坏配置依赖的缩进层级。

### 代码结构

```
ipm.py              CLI 入口（子命令 stats）
ipmlib/cleaner.py   终端分页残留清洗（退格 / 回车 / ANSI CSI 重放）
ipmlib/parsers.py   五种方言的接口地址解析 -> AddrEntry
ipmlib/stats.py     按自有前缀汇总、按 /24 与 /48 切块 -> Report
ipmlib/report.py    终端报表渲染
ipmlib/roa.py       ROA (VRP) 获取与 RFC 6811 校验
ipmlib/irr.py       IRR (RADB) route 对象查询
ipmlib/rov.py       ROA + IRR 合成授权判定
ipmlib/rov_report.py 校验报表渲染
ipmlib/mailer.py    SMTP 推送
tests/test_ipm.py   IP 统计单元测试
tests/test_rov.py   ROA/IRR 校验单元测试（离线，不发网络请求）
tests/test_mailer.py 邮件推送单元测试（离线，不连 SMTP）
prefix.list         自有前缀（IPv4 / IPv6 混排），一行一条，支持 # 注释
ROA-IRR.list        前缀 + 现网 origin ASN（NO = 未广播）
running-config/     设备配置采集文件（.gitignore）
output/             统计输出（.gitignore）
cache/              ROA VRP 缓存（.gitignore）
.env                邮件凭证（.gitignore，600 权限）
```

`running-config/` 和 `output/` 不入库：前者含明文口令哈希、SNMP community 和客户
电路信息，后者由前者生成、可随时重跑。因此新克隆的仓库里真实配置的回归测试会自动
跳过（`TestRealConfigs` 检测不到 `running-config/` 就 skip），其余测试照常运行。

### 测试

CSV 比报表多三列可用于透视：`owned_prefix`（所属自有前缀，未登记则为空）、
`block`（所属块，v4 是 `/24`、v6 是 `/48`，登记与否都填）和 `block_len`；
配合 `in_owned` 列即可区分自有与未登记。JSON 里每条自有前缀带 `blocks` 数组，
顶层另有 `unregistered.ipv4` / `unregistered.ipv6` 两组块。

```bash
python3 -m unittest discover -s tests
```

环境为 Python 3.9，无第三方依赖。


## 功能二：ROA / IRR 授权校验

读 `ROA-IRR.list`（第一列前缀，第二列现网广播的 origin ASN，`NO` 表示现网未广播），
查每条前缀的 ROA 与 IRR 登记，判定这条广播是否被授权。

```bash
./ipm.py rov                       # 完整校验（ROA + IRR）
./ipm.py rov --no-irr              # 只做 ROA 校验，不联 whois
./ipm.py rov --roa-max-age 60      # 调试时允许复用 60 分钟内的 ROA 缓存
./ipm.py rov --csv output/rov.csv --json output/rov.json
```

### 判定口径

**ROA 优先于 IRR**，与上游实际的 prefix-filter 行为一致：

| 判定 | 含义 | 算 match |
| --- | --- | --- |
| `ROA-MATCH` | ROA 覆盖且 origin 匹配（RFC 6811 valid） | ✅ |
| `ROA-INVALID` | 有 ROA 覆盖但没有一条匹配 | ❌ |
| `IRR-MATCH` | 无任何 ROA 覆盖，IRR 有精确 route 且 origin 匹配 | ✅ |
| `NO-AUTH` | 无 ROA 覆盖，IRR 也无匹配 route | ❌ |
| `NOT-ANNOUNCED` | 现网未广播，无 origin 可比 | — |
| `QUERY-FAILED` | IRR 查询失败，不下结论 | — |

`ROA-INVALID` **不会**因为 IRR 里有登记就转为 match —— RPKI invalid 会被上游直接
丢弃，IRR 救不回来。反过来，`QUERY-FAILED` 与 `NO-AUTH` 严格区分：查不到和查询
失败是两回事，后者不能误报成无授权。

ROA 校验严格按 RFC 6811：VRP 覆盖是 less-specific-or-equal，且必须
`前缀长度 <= maxLength` 才算匹配。这一点在未广播的前缀上尤其重要 ——
`218.30.0.0/15 → AS4134 maxLength 15` 覆盖了 `218.30.37.0/24` 的地址空间，
却授权不了这条 `/24` 上线，报表里标 `✗` 并单独计数。

IRR 只认**精确前缀**的 route 对象（`-T route` 会把 less-specific 覆盖对象一并
返回，需自行过滤），origin 必须等于现网广播的 ASN。

### 数据源

| 数据 | 来源 | 说明 |
| --- | --- | --- |
| ROA (VRP) | `https://rpki.cloudflare.com/rpki.json` | rpki-client 全量导出，约 100MB |
| ROA 到期 | `https://rpki.cloudflare.com/api/graphql` | ROA 证书的 `validTo` |
| IRR | `whois.radb.net:43` | RADB 及其镜像（RIPE / APNIC / ARIN / NTTCOM / LEVEL3 …） |

### ROA 到期时间的两种口径

**不能拿 `rpki.json` 里的 `expires` 当 ROA 到期日。** 那是整条验证链的有效期，
受 manifest/CRL 约束（通常每天重签），永远只剩几天 —— 当前数据里 130 条 VRP
全部显示 0.6~5.6 天到期，据此会得出「全网 ROA 即将过期」的错误结论。

真正的 ROA 证书有效期来自 Cloudflare GraphQL 接口的 `validTo`（与其网页版
Route Validator 同源），同一批 VRP 实际是 40~355 天。报表用 `validTo`，
接口不可用时才退回链路有效期，**并在表头明确标注当次用的是哪种口径**。

剩余天数向上取整：3 天后到期显示「剩 3 天」，向下取整会系统性少算一天。
30 天内到期会单独列出预警段；未触发时总体结果里仍给出到期分布。

取 ROA **全量**导出而不是逐条查在线校验 API，有两个好处：不必把「我们关心哪些
前缀」告诉对方；89 条前缀只需一次下载。

**每次校验都重新下载，默认不复用缓存**（`--roa-max-age 0`）。校验的意义就在于
反映当下的 RPKI 状态，拿几小时前的快照去判 valid/invalid 可能得出与现网相反的
结论 —— 一条刚过期或刚修好的 ROA 在旧快照里是看不出来的。Cloudflare 约每 20
分钟重建一次 dump，重下一次约 2～3 分钟，对每日两次的任务完全可接受。

调试时可以用 `--roa-max-age 60` 之类放宽，此时报表头会明确标出
「⚠ 复用了 N 分钟前的本地缓存」。报表同时给出 dump 自身的构建时间与距今多久，
数据源本身超过 2 小时没更新会标「⚠ 数据源偏旧」—— 那是 Cloudflare 侧的问题，
不是我们缓存旧。

**IRR 查询会把前缀逐条发给 RADB**（89 次 whois，默认间隔 0.4 秒避免触发速率
限制）。不希望外发时用 `--no-irr`，此时只做 ROA 校验，全程离线。

RADB 镜像了一个 `source: RPKI` 的伪 IRR 源（IRRd 把 ROA 自动转换成的 route
对象），代码里已排除 —— 否则「无 ROA 覆盖但 IRR 有」会变成拿 ROA 证明 ROA 缺失
的循环论证。


### 定时运行与邮件推送

每天 **07:00 / 19:00** 各跑一次，结果邮件推送（错开 `radb-query.timer` 的
03:00/15:00，避免同一时刻集中访问 rpki.cloudflare.com 与 whois.radb.net）。

```
/etc/systemd/system/ipm-rov.timer     每日两次触发
/etc/systemd/system/ipm-rov.service   oneshot，跑 ipm.py rov --email
/etc/logrotate.d/ipm-rov              轮转 output/rov-cron.log，周切 8 份
```

```bash
systemctl list-timers ipm-rov.timer   # 看下次执行时间
systemctl start ipm-rov.service       # 立刻手动跑一次（会真的发信）
journalctl -u ipm-rov -n 50           # 看执行记录
tail -f /opt/project/ipm/output/rov-cron.log
```

邮件标题直接带结论，不展开附件也知道要不要处理：

| 情况 | 标题 |
| --- | --- |
| 正常 | `[ipm] ROA/IRR 校验 正常 — 已广播 32/32 条授权有效` |
| 有问题 | `[ipm] ROA/IRR 校验 ⚠ 2 条无授权，1 条 ROA 将到期` |

正文是等宽排版的完整报表（HTML 用 `<pre>` 保持对齐），附件为
`rov-report.txt` / `rov.csv` / `rov.json`。

定时任务用 `--report` 把报表写进文件而不是打到 stdout —— 否则每次执行都会把
一百多行报表追加进日志，一年下来十几 MB。

#### 邮件配置

凭证放 `.env`（`600` 权限，已在 `.gitignore` 里），格式见 `.env.example`：

```env
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SENDER_EMAIL=your-account@gmail.com
SENDER_PASSWORD=xxxx xxxx xxxx xxxx   # Gmail 应用专用密码，不是账号密码
RECIPIENT_EMAILS=someone@example.com,another@example.com
BCC_EMAILS=
```

密送地址只进投递列表、不写进信头 —— 写进去就不是密送了（有测试锁住这一点）。
邮件发送失败时退出码为 `2` 且日志留有明确记录，但不会把校验结果本身判成失败。
