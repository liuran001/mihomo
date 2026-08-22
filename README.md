<h1 align="center">
  <img src="Meta.png" alt="Meta Kernel" width="200">
  <br>mihomo · smart + eBPF + Tailscale<br>
</h1>

<p align="center">
  <a href="https://github.com/liuran001/mihomo/actions"><img src="https://img.shields.io/github/actions/workflow/status/liuran001/mihomo/build.yml?branch=Alpha&style=flat-square&label=build"></a>
  <img src="https://img.shields.io/github/go-mod/go-version/liuran001/mihomo/Alpha?style=flat-square">
  <a href="https://github.com/liuran001/mihomo/releases"><img src="https://img.shields.io/github/release/liuran001/mihomo/all.svg?style=flat-square"></a>
</p>

一个 [mihomo](https://github.com/MetaCubeX/mihomo) 的三方合并分支，以 [vernesong](https://github.com/vernesong/mihomo) 的 smart 内核为底，合入 [TanakaLun](https://github.com/TanakaLun/mihomo/tree/ebpf-inbound) 的 eBPF 透明入站。主要面向**随身 WiFi / 手机热点 / 软路由当旁路网关**这个场景。

## 和原版相比多了什么

**一、eBPF 入站，国内 IP 可以完全不过核心。**
和 dae 一样的做法：国内 IP 的判定放进内核里，命中的包在内核网络栈里就直接放行，根本不进 mihomo 进程。国内流量不再经过用户态转发，延迟和 CPU 都省下来，机器越弱越明显。同时它是透明代理，下联设备什么都不用配。

**二、自动选择能挑出真正支持 UDP / IPv6 的节点。**
原版的 url-test 只比 HTTP 延迟。一个 UDP 被黑洞的中转（IEPL 线路很常见）在面板上延迟一片绿，实际 QUIC、游戏、通话全部静默失败。这个分支会主动探测节点到底转不转 UDP、能不能走 IPv6，然后优先选能用的。

**三、Tailscale 可以接受入站连接，能当 Subnet Router 和 Exit Node。**
原版的 `type: tailscale` 只能作为出站。这里可以反过来，把这台机器通告成 Subnet Router 或 Exit Node，让 tailnet 里的其他设备访问进来——而且进来的流量会走一遍你的分流规则。

---

# 一、eBPF 入站

## 它能干什么

- **透明代理**：下联设备不用改任何配置，接上就走代理。
- **国内流量不过核心**：命中 CN IP 的包直接在内核放行，不进 mihomo。
- **不需要 iptables / nftables**：不写任何防火墙规则，也不需要策略路由。
- **能管本机，也能管下联**：`local` 管本机应用，`shared` 管转发流量，`hybrid` 两个都管。

## 最小可用配置

```yaml
listeners:
  - name: ebpf-in
    type: ebpf
    mode: hybrid
    dns-mode: hijack
    shared:
      interface: [br0]        # 换成你的下联网卡名

# 用 eBPF 就不要再开 TUN，两者会打架，见下面「注意事项」
tun:
  enable: false
```

## 让国内 IP 不过核心

这是这个分支最主要的功能，需要两步。

**第一步，准备一个 CN IP 的规则集。** 必须是 `behavior: ipcidr`，域名规则集在这里没有用：

```yaml
rule-providers:
  CN-IP:
    type: http
    behavior: ipcidr          # 必须是 ipcidr，写成 domain 会被静默忽略
    format: mrs
    interval: 86400
    path: ./rule_provider/cn-ip.mrs
    url: "https://github.com/MetaCubeX/meta-rules-dat/raw/meta/geo/geoip/cn.mrs"
```

**第二步，在 listener 里引用它：**

```yaml
listeners:
  - name: ebpf-in
    type: ebpf
    mode: hybrid
    dns-mode: hijack
    bypass-rule-set:
      - CN-IP                 # 写 rule-providers 里的名字
    shared:
      interface: [br0]
```

配好之后，去往这些网段的 TCP / UDP 包在内核里就直接放行了，mihomo 的连接列表里看不到它们——这是正常的，说明生效了。上面那个 `cn.mrs` 同时包含 IPv4 和 IPv6 网段，两边都会生效。

规则集内容变化后每 3 秒自动同步进内核，不用重启。

## 注意事项（这几条不看会踩坑）

**必须关掉 TUN。** 这条最重要。TUN 的 `auto-route` 会装一条策略路由，把转发流量整个抓进 TUN 设备。这条规则在 eBPF 之后生效，结果就是：你配了 `bypass-rule-set`，包也确实被 eBPF 放行了，但转头就被策略路由捞进 TUN 又送回 mihomo——白配，而且国内网站会直接不通。

已经有 eBPF 了就不需要 TUN，直接：

```yaml
tun:
  enable: false
```

**DNS 永远走核心，不受 bypass 影响。** `dns-mode: hijack` 时所有 53 端口的流量无条件劫持进核心，内核里对端口 53 的判断排在所有 CIDR 判断之前。所以基于 DNS 的广告拦截（`nameserver-policy` 里配 `rcode://success` 那种）照常工作，不会因为开了 CN IP 直连就失效。

**只有 `behavior: ipcidr` 的规则集会被采纳。** 写成 `domain` 不会报错，会被安静地跳过，然后你会以为没生效。

**下联网卡要填对。** `shared.interface` 填的是下联那张卡（热点是 `wlan0`、桥接是 `br0`），填成上联网卡不会生效。

## 完整参数表

```yaml
listeners:
  - name: ebpf-in
    type: ebpf

    # ---- 顶层 ----

    # local  = 只管本机进程发出的连接
    # shared = 只管从下联网卡转发过来的连接（旁路网关用这个）
    # hybrid = 两个都管
    # 默认 local
    mode: hybrid

    # 要接管的协议，默认两个都接管
    network: [tcp, udp]

    # DNS 处理方式，默认 hijack
    #   hijack         = 所有 53 端口无条件劫持进核心（推荐，广告拦截/分流都靠它）
    #   respect_bypass = 劫持，但命中 bypass 的 DNS 放行直连
    #   off            = 完全不管 DNS
    dns-mode: hijack

    # UDP 会话保活时间，单位秒。默认 300，最小 5
    udp-timeout: 300

    # 命中这些规则集的目标 IP 直接在内核放行，不进核心
    # 只认 behavior: ipcidr 的规则集
    bypass-rule-set:
      - CN-IP

    # 是否放行私网地址（10/8、192.168/16 等），默认 true
    # 做旁路网关时通常设 false，否则下联互访会被放行、拿不到统计
    bypass-private-address: false

    # ---- local：本机进程 ----
    local:
      # cgroup v2 挂载点，一般不用填，会自动找
      cgroup-path: /sys/fs/cgroup

      # IPv6 处理
      #   auto   = 探测到本机有可用 IPv6 出口才接管（默认）
      #   always = 总是接管
      #   off    = 不接管
      ipv6-mode: auto

      # 只接管这些 UID 的流量（不填 = 全部接管）
      include-uid: [0, 1000]
      include-uid-range: ["10000:19999"]   # 注意分隔符是冒号，不是连字符

      # 排除这些 UID，优先级高于 include
      exclude-uid: [1052]
      exclude-uid-range: ["20000:20100"]

      # 以下三个是 Android 专用，会自动解析成 UID
      include-android-user: [0]                 # 只接管主用户
      include-package: [com.android.chrome]     # 只接管这些应用
      exclude-package: [com.tencent.mm]         # 排除这些应用

      # 内核状态表容量，默认 32768，上限 1048576
      # 日志里出现 "map ... is 85.0% full" 之类的告警时调大它
      state-capacity: 32768

    # ---- shared：下联转发 ----
    shared:
      # 下联网卡，必填。可以填多个
      interface: [br0]

      # IPv6 处理，always（默认）/ off
      ipv6-mode: always

      # 只接管来自这些网段的客户端（不填 = 全部）
      include-source-cidr: [192.168.0.0/24]
      exclude-source-cidr: [192.168.0.100/32]

      # 按 MAC 过滤客户端，优先级高于 CIDR
      include-mac-address: ["aa:bb:cc:dd:ee:ff"]
      exclude-mac-address: ["11:22:33:44:55:66"]

      # 状态表容量，默认 32768
      state-capacity: 32768

      advanced:
        # TC filter 优先级，默认 1，和别的 TC 程序冲突时才需要改
        tc-priority: 1
```

## 对内核版本的要求

能跑起来的最低要求不高，但内核越新，回收状态越及时：

| 内核 | 影响 |
| --- | --- |
| 5.4 及以上 | 可以正常工作 |
| 5.5 及以上 | socket 关闭时能立刻回收状态，否则只能等 LRU 淘汰 |
| 5.14 及以上 | 用户态可以主动清理过期的重定向表项，否则同样只靠 LRU |
| 6.6 及以上 | 用 TCX 挂载，不依赖 qdisc；更早的内核自动回退到 clsact |

低于上述版本不会报错也不会不工作，只是回收慢一些。启动时会在日志里列出当前内核缺哪些能力、各自意味着什么，不用自己猜。

---

# 二、自动选择支持 UDP / IPv6 的节点

## 怎么配

在策略组里加两个开关就行：

```yaml
proxy-groups:
  - name: 自动选择
    type: url-test            # 对 url-test / smart / load-balance 生效
    use: [机场A, 机场B]
    prefer-udp: true          # 优先选真的能转发 UDP 的节点
    prefer-ipv6: true         # 优先选真的能走 IPv6 出站的节点
    penalize-unstable: true   # 经常断流的节点自动降权
```

UDP 用 STUN 探测，IPv6 用一个只有 v6 的端点探连通性。探测走独立通道，不会污染面板上的延迟和存活状态。

## 它是降权，不是过滤

节点不会被踢出候选池，只是在排序时加一笔"罚时"：

| 探测结果 | 加多少 |
| --- | --- |
| 确认支持 | 0 ms |
| 还没探测 | 50 ms |
| 确认不支持 | 600 ms |

两个开关都开时罚时累加，最多 1200 ms。所以一个 100 ms 但不支持 IPv6 的节点（算作 700 ms）仍然赢过一个 900 ms 的 IPv6 节点；延迟差不多的时候，能用的那个总是排前面。

**故意不做成过滤。** 探测本身就不可靠——IPv6 探测目标只有在你自己的 IPv6 通的时候才能到达，失败率上六成很正常。如果探测失败就把节点踢掉，一个组可能因为和"能不能转发流量"毫无关系的原因被削光，甚至连 `DIRECT` 一起削掉，让本该直连的流量悄悄绕进代理。

## 各类型策略组的行为

| 组类型 | 怎么起作用 |
| --- | --- |
| `url-test` / `smart` | 罚时计入排序延迟 |
| `load-balance` | 优先在满足条件的节点里分流量，全挂了才用其他的 |
| `select` / `fallback` | 不介入 |

`select` 和 `fallback` 刻意不动：手动选的节点、显式写好的优先级顺序，不该被一次探测结果改掉。

## penalize-unstable

有一类节点延迟探测永远合格，但真实流量一进去就死——连接表里的特征是"握手成功、发出去几个字节、一个字节都没回来、几秒后关闭"。url-test 永远发现不了这种。

开了 `penalize-unstable` 之后，这类连接会被记进 10 分钟滑动窗口，每次事件加 150 ms 罚时，最多 1.5 秒。同样是降权不是摘除，全网都不行的时候还能兜底；窗口过期后节点自己恢复。

## 缓存说明

探测结果按节点身份（名字 + 类型 + 提供者 + 地址）缓存在内存里，成功缓存 30 分钟，失败 10 分钟，异步刷新，最多 8 个并发，占满就跳过等下轮。**核心重启后要重新探测**，这段收敛期里所有节点都按"还没探测"算，只带最小罚时。

---

# 三、Tailscale 入站 / Subnet Router / Exit Node

## 怎么配

```yaml
proxies:
  - name: TS
    type: tailscale
    hostname: my-gateway              # 在 tailnet 里显示的机器名
    auth-key: tskey-auth-xxxxx
    udp: true
    accept-routes: true               # 接受其他 Subnet Router 通告的路由

    listen-port: 41641                # 固定 magicsock 端口，配 TUN 时需要，见下

    advertise-routes:                 # 通告成 Subnet Router
      - 192.168.0.0/24
    advertise-exit-node: true         # 通告成 Exit Node
```

配好后要去 tailnet 管理后台批准路由（或者在 ACL 里配 autoApprovers），这一步 Tailscale 官方流程一样。

## 进来的流量会走分流规则

从 tailnet 进来的连接会经过 mihomo 的规则引擎（新增了 `TAILSCALE` 入站类型）。这意味着当 Exit Node 用的时候，出口流量按你的规则走——国内直连、国外走代理，比原版 Tailscale 的 Exit Node 灵活得多。

有 `advertise-routes` 或 `advertise-exit-node` 时，tsnet 会在启动时就主动连上 tailnet，不等第一个连接触发。否则核心重启后这台机器在 tailnet 里会短暂消失，`ts://` 的 DNS 查询也会在这段时间里失败。

## 如果你还在用 TUN

用 eBPF 就不需要 TUN 了，可以跳过这一节。

仍然用 TUN 的话，Tailscale 的 magicsock 会有一个问题：它的 UDP socket 出站源地址不定，会被 TUN 的 auto-route 策略路由抓走，导致 magicsock 流量绕回 mihomo 自己。两种解法选一个：

```yaml
# 解法一：固定端口 + sing-tun 原生豁免（推荐，纯配置）
proxies:
  - name: TS
    type: tailscale
    listen-port: 41641
tun:
  exclude-src-port: [41641]

# 解法二：打 routing-mark，自己写策略路由绕开 TUN
proxies:
  - name: TS
    type: tailscale
    routing-mark: 0x2333
```

另外规则里 tailnet 的网段要排在所有 GEOIP / 私网 DIRECT 规则**前面**，否则会被提前匹配走：

```yaml
rules:
  - IP-CIDR,100.64.0.0/10,TS,no-resolve
  - IP-CIDR6,fd7a:115c:a1e0::/48,TS,no-resolve
  - GEOIP,CN,DIRECT
  - MATCH,自动选择
```

---

# 完整配置示例

一台随身 WiFi，同时做透明网关、CN IP 直连、Tailscale Subnet Router 和 Exit Node：

```yaml
mode: rule

# 各地区组共用的锚点
use: &use
  type: smart
  use: [机场A, 机场B, 备用机场]
  prefer-udp: true
  prefer-ipv6: true
  policy-priority: '\[备用机场\]:0.3'    # smart 内核原生选项，<1 降权
  health-check:
    enable: true
    url: https://cp.cloudflare.com
    interval: 300

proxies:
  - name: TS
    type: tailscale
    hostname: my-gateway
    auth-key: tskey-auth-xxxxx
    udp: true
    accept-routes: true
    advertise-routes: [192.168.0.0/24]
    advertise-exit-node: true

proxy-groups:
  - {name: 香港, <<: *use, filter: "(?i)港|hk"}
  - {name: 日本, <<: *use, filter: "(?i)日本|jp"}
  - {name: 自动选择, <<: *use, type: url-test, tolerance: 2, penalize-unstable: true}

rule-providers:
  CN-IP:
    type: http
    behavior: ipcidr              # eBPF bypass 只认 ipcidr
    format: mrs
    interval: 86400
    path: ./rule_provider/cn-ip.mrs
    url: "https://github.com/MetaCubeX/meta-rules-dat/raw/meta/geo/geoip/cn.mrs"
  广告规则:
    type: http
    behavior: domain              # 广告拦截在 DNS 层做，用域名规则集
    format: mrs
    interval: 86400
    path: ./rule_provider/ads.mrs
    url: "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/Filters/AWAvenue-Ads-Rule-Clash.mrs"

listeners:
  - name: ebpf-in
    type: ebpf
    mode: hybrid
    dns-mode: hijack
    bypass-rule-set: [CN-IP]        # 国内 IP 不过核心
    bypass-private-address: false
    local:
      ipv6-mode: auto
    shared:
      interface: [br0]
      ipv6-mode: always

# 用 eBPF 就别开 TUN
tun:
  enable: false

dns:
  enable: true
  listen: 0.0.0.0:1053
  enhanced-mode: redir-host
  nameserver-policy:
    "rule-set:广告规则": rcode://success   # DNS 层拦广告，不受 bypass 影响
  nameserver: [223.5.5.5, 119.29.29.29]

rules:
  - IP-CIDR,100.64.0.0/10,TS,no-resolve
  - IP-CIDR6,fd7a:115c:a1e0::/48,TS,no-resolve
  - GEOIP,CN,DIRECT
  - MATCH,自动选择
```

---

# 构建

不需要 NDK，不需要 cgo：

```bash
# Android / arm64（随身 WiFi、手机）
CGO_ENABLED=0 GOOS=android GOARCH=arm64 \
  go build -tags "with_gvisor with_ebpf" -trimpath \
  -ldflags '-w -s -buildid=' -o mihomo .

# Linux / amd64
CGO_ENABLED=0 GOARCH=amd64 go build -tags "with_gvisor with_ebpf" -o mihomo .
```

必须带 `with_ebpf` 才会编入 eBPF 入站。BPF 对象已经随仓库提供，编译时不需要 clang。

---

# 技术细节

这一节是实现层面的东西，正常使用不用看。

## eBPF 入站是怎么做的

`local` 模式挂 cgroup BPF 程序（`connect4/6`、`sendmsg4/6`、`recvmsg4/6`），在 `connect()` 和 `sendmsg()` 的时候把目标地址改写成本机 loopback 上的一个重定向地址，原始目标存进 BPF map，mihomo 收到连接后再查回来。`shared` 模式挂 TC 程序在下联网卡的 ingress/egress 上，做同样的事情但是在包这一层。

CN IP 直连是把规则集里的网段编译进两个 LPM trie（IPv4 一个、IPv6 一个），BPF 程序查表命中就直接返回放行，整个改写流程都不走。判断顺序是：DHCP → 端口 53（DNS）→ 保留地址 → 本机地址 → fake-ip → 私网 → bypass CIDR。DNS 排在 CIDR 前面，所以劫持 DNS 不受 bypass 影响。

## 状态表与回收

内核里维护若干张状态表，主要是重定向表（cookie/token → 原始目标）和流表。大部分是 LRU，满了会淘汰最久没用的表项，不会拒绝新连接。

回收有三条路：

1. **BPF 侧**：`sock_release` 在 socket 关闭时删掉对应表项——需要内核 5.5+。
2. **用户态定期清扫**：扫描过期表项并删除。删除用 `BPF_MAP_LOOKUP_AND_DELETE_ELEM` 保证原子性，避免和内核里的刷新竞争——这个操作对 hash map 需要内核 5.14+。低于这个版本时清扫会主动放弃，不走有竞态的 lookup-then-delete。
3. **LRU 淘汰**：上面两条都没有时的兜底。

所以在 5.4 这种老内核上，回收完全依赖 LRU。这不影响正确性（LRU 优先淘汰的正是已关闭连接的死表项，活跃表项每次访问都会刷新位置），但安全余量会小很多。启动时的能力报告会明确说明当前内核处于哪种情况。

## 已修的问题

**UDP 超时单位错误。** `udp-timeout` 的值被当成纳秒而不是秒用了，配置 300 实际是 300 纳秒，导致 UDP 状态每 5 秒左右被清空一次。

**重定向表耗尽导致断流。** 重定向表原本是固定大小的 hash map，而 BPF 侧从不删除 TCP 表项。跑一段时间填满之后，`bpf_map_update_elem` 返回 `-E2BIG`，四次 token 尝试全部失败，`connect()` 直接被拒绝，从此每个新连接都失败，重启才恢复。改成 LRU 之后满了只淘汰最久未用的表项，不再拒绝新连接。

**统计计数器索引撞车。** Go 侧的常量声明漏了 `iota`，UDP 的失败计数索引被写成了 0，和 TCP 共用一个槽位，读到的数是错的。

**TCP 连接路径上的多余查表。** `token_v4_attempt` / `token_v6_attempt` 对 TCP 会先查一次 UDP 表再查 TCP 表。协议是 key 的一部分，那次查询不可能命中，纯属浪费——每次 `connect()` 白算一次哈希，最坏四次。改成三目选表后，带 TCP 的程序共减少 230 条指令。

**共享网络的回程 ARP。** `shared` 模式改写回程包源地址为 loopback 重定向地址，内核解析下联客户端 MAC 时会拿这个地址当 ARP sender，客户端的 `arp_process` 会把 sender 为 loopback 的 ARP 当 martian 丢掉，邻居表项一过期回程就间歇黑洞。修复是挂载期间把下联网卡的 `arp_announce` 提到 2，卸载时恢复。

**两处内存泄漏。** 一是节点健康记录表的清扫挂在读路径上，而写路径无条件插入，配置里没开 `penalize-unstable` 时表只增不减；二是 TCX 挂载失败时的重试队列没有上限。

**诊断数据算了但没人看。** 清扫器每轮都算出状态表的占用率，`LookupAndDeleteMode()` 知道内核能不能回收，`ProbeKernel()` 会生成完整的内核能力报告——这三个都没有任何调用方。现在占用率超过 85% 会告警（70% 以下解除，避免抖动），内核能力报告在启动后打一次。断流那个 bug 之所以拖了那么久才被发现，就是因为这些降级路径全都"能用，只是没余量"，从外面看和健康状态一模一样。

## Tailscale

上游的 `type: tailscale` 只有出站。这里把 tsnet 的 fallback TCP/UDP 流处理接到了 mihomo 的 tunnel 上，从 tailnet 进来的流量因此会走规则引擎。netstack 本身就处理 subnet 流量，所以 Subnet Router 和 Exit Node 是顺带就有的。

还修了一个 TUN 模式下的直连问题：上游把 magicsock 的 UDP socket 交给 outbound dialer，于是被 `auto-detect-interface` 用 `SO_BINDTODEVICE` 绑到了默认出口网卡上。绑了网卡的 socket 收不到从其他本地网卡（比如自家 LAN）到达的 disco 包，同一个局域网里的两台设备也只能走 DERP 中继，实测从 4 ms 恶化到 250 ms。现在默认不绑，只有显式配了 `interface-name` / `routing-mark` 或存在 socket hook（CMFA）时才保留原行为。

## 其他

**内核自更新指向本分支。** `POST /upgrade` 的 alpha 通道原本从上游拉，下载到的版本不含这些改动，用了新配置项的 config 会直接启动失败。现在指向本仓库的 `Prerelease-Alpha`。

**`cmd/tcclean`。** 通过 netlink 列出并清除指定网卡上 TC BPF filter 与 clsact qdisc 的小工具，用于 Android 上 `/system/bin/tc` 缺失、异常退出留下残留的场景。仅 Linux 可用。注意它是删除工具不是查看工具，Android 的 tethering offload 程序也挂在同一位置，误删会中断内核转发加速（netd 重启后会重建）。

---

# 上游与致谢

代码来自这三处，通用配置和用法请优先看它们的文档：

- [MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo) — 上游本体，[官方文档](https://wiki.metacubex.one/)
- [vernesong/mihomo](https://github.com/vernesong/mihomo) — smart 内核（`type: smart` 策略组、LightGBM 权重模型、`policy-priority` 等）
- [TanakaLun/mihomo](https://github.com/TanakaLun/mihomo/tree/ebpf-inbound) — eBPF 透明入站（移植自 sing-box 的 cilium/ebpf 后端）

以及 mihomo 自身所站立的项目：

- [Dreamacro/clash](https://github.com/Dreamacro/clash)
- [SagerNet/sing-box](https://github.com/SagerNet/sing-box)
- [riobard/go-shadowsocks2](https://github.com/riobard/go-shadowsocks2)
- [v2ray/v2ray-core](https://github.com/v2ray/v2ray-core)
- [WireGuard/wireguard-go](https://github.com/WireGuard/wireguard-go)
- [yaling888/clash-plus-pro](https://github.com/yaling888/clash)

# 许可

GPL-3.0，与上游一致。
