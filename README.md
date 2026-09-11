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
tests/test_ipm.py   单元测试
prefix.list         自有前缀（IPv4 / IPv6 混排），一行一条，支持 # 注释
running-config/     设备配置采集文件（.gitignore）
output/             统计输出（.gitignore）
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
