<h1 align="center">
  <img src="Meta.png" alt="Meta Kernel" width="200">
  <br>mihomo · smart + eBPF + Tailscale<br>
</h1>

<p align="center">
  <a href="https://github.com/liuran001/mihomo/actions"><img src="https://img.shields.io/github/actions/workflow/status/liuran001/mihomo/build.yml?branch=Alpha&style=flat-square&label=build"></a>
  <img src="https://img.shields.io/github/go-mod/go-version/liuran001/mihomo/Alpha?style=flat-square">
  <a href="https://github.com/liuran001/mihomo/releases"><img src="https://img.shields.io/github/release/liuran001/mihomo/all.svg?style=flat-square"></a>
</p>

一个 [mihomo](https://github.com/MetaCubeX/mihomo) 的三方合并分支：以 [vernesong](https://github.com/vernesong/mihomo) 的 **smart 内核**为底，合入 [TanakaLun](https://github.com/TanakaLun/mihomo/tree/ebpf-inbound) 的 **eBPF 透明入站**，并针对**随身 WiFi / 手机热点当旁路网关**这一场景补了若干实现。

下面「本分支的改动」是相对上述两个上游的增量，其余用法与上游一致，见 [官方文档](https://wiki.metacubex.one/)。

---

## 本分支的改动

### 1. 按实测能力择优节点

`filter` / `exclude-filter` 只能按名字筛，而**节点是否真的转发 UDP、能否走 IPv6 出站，配置里看不出来**。url-test 只按 HTTP 延迟排序，于是完全可能稳定选中一个 UDP 被黑洞的中转（IEPL 线路很常见），结果 QUIC、STUN、游戏、通话全部静默失败，而面板上延迟一片绿。

本分支给策略组加了两个选项，按**主动探测的结果**择优：UDP 用 STUN binding request 探回包，IPv6 用一个 v6-only 端点做 URLTest。

```yaml
proxy-groups:
  - name: 自动选择
    type: url-test          # smart / url-test / fallback / select / load-balance 均可
    use: [机场A, 机场B]
    prefer-udp: true        # 优先支持 UDP 转发的节点
    prefer-ipv6: true       # 优先能走 IPv6 出站的节点
```

**是分层择优而不是硬过滤**。硬过滤在合格节点很少时会把某个地区组砍到只剩一两个节点，一旦它们出问题该组就无处可选。实际行为是按下面的阶梯分层，从最优层往下合并，直到候选数达到 5 个：

| 层级 | 含义 |
| --- | --- |
| 1 | UDP 与 IPv6 均已确认可用 |
| 2 | UDP 已确认，IPv6 尚未探测 |
| 3 | 仅 UDP 可用（IPv6 确认不可用） |
| 4 | 尚未探测 |
| 5 | 确认不满足 |

所以一个 filter 后只剩 3 个节点的小众地区组不会被再次削减，而节点充裕的组则只用最优层。组成员总数本来就 ≤5 时完全不介入。

探测结果按节点名全局缓存（成功 30 分钟、失败 10 分钟），异步刷新，最多 8 个并发。**缓存在内存中，核心重启后需要重新探测**，收敛期间（约 30～60 秒）所有节点按「尚未探测」对待。

### 2. 断流节点自动降权

延迟探测合格、但真实流量一进去就死的节点，url-test 永远发现不了——连接表里的特征是「握手成功、发出去若干字节、一个字节都没回来、几秒后关闭」。

```yaml
proxy-groups:
  - name: 自动选择
    type: url-test
    use: [机场A, 机场B]
    penalize-unstable: true   # 断流频繁的节点自动降权
```

TCP tracker 在连接关闭时识别这类黑洞连接，记入 10 分钟滑动窗口，排序时每次事件加 150 ms 虚拟延迟，上限 1.5 秒。上限是故意留的：坏节点只是排到后面，而不是被摘掉，全网都不理想时仍可兜底；窗口过期后节点自行恢复。目前作用于 url-test 组的排序。

### 3. Tailscale：Subnet Router 与 Exit Node

上游的 `type: tailscale` 只能作为出站使用。本分支让它可以**对外提供服务**：

```yaml
proxies:
  - name: TS
    type: tailscale
    hostname: my-gateway
    auth-key: tskey-auth-xxxxx
    udp: true
    accept-routes: true
    listen-port: 41641              # 固定 magicsock 端口，见下文
    advertise-routes:               # 作为 Subnet Router 通告网段
      - 192.168.0.0/24
    advertise-exit-node: true       # 作为 Exit Node
```

tsnet 的 netstack 本身就处理 subnet 流量，本分支把它的 fallback TCP/UDP 流处理接到 mihomo 的 tunnel 上，**从 tailnet 进来的流量会走一遍规则引擎**（新增 `TAILSCALE` 入站类型）。这意味着 Exit Node 的出口流量同样按你的规则分流——国内直连、国外走代理——比原版 Tailscale 的 Exit Node 更灵活。

有通告时 tsnet 会**主动启动**而不是等首个连接触发，否则节点在核心重启后对 tailnet 不可见，`ts://` 的 DNS 查询也会在这段窗口内失败。

路由审批仍在 tailnet 管理后台（或 ACL 的 autoApprovers）完成。

### 4. Tailscale 在 TUN 模式下的直连修复

这是本分支最初的起因。上游把 magicsock 的 UDP socket 交给 outbound dialer，于是它被 `auto-detect-interface` 用 `SO_BINDTODEVICE` 绑到了默认出口网卡上。绑定网卡的 socket **收不到从其他本地网卡（比如自家 LAN）到达的 disco 包**，于是同一个局域网里的两台设备也只能走 DERP 中继——实测从 4 ms 恶化到 250 ms。

现在默认不绑定该 socket。只有显式配了 `interface-name` / `routing-mark`，或存在 socket hook（CMFA）时才保留原行为。

不绑定带来第二个问题：这个 socket 的出站源地址未定，会命中 sing-tun auto-route 的策略路由而被自己的 TUN 抓走，magicsock 流量绕回 mihomo 自身（conntrack 里能看到源地址是 TUN 地址的 STUN 连接）。两条出路，任选其一：

```yaml
# 方案一：固定端口，用 sing-tun 原生的豁免（推荐，纯配置）
proxies:
  - name: TS
    type: tailscale
    listen-port: 41641
tun:
  exclude-src-port: [41641]

# 方案二：给该出站打 routing-mark，自行写策略路由绕开 TUN
proxies:
  - name: TS
    type: tailscale
    routing-mark: 0x2333
```

### 5. eBPF 共享网络的回程 ARP 修复

合入的 eBPF 入站在 `shared` 模式下（TC 挂下联网卡，用于热点/旁路网关）改写回程包的源地址为 loopback 重定向池地址（`127.128.0.0/9`）。内核解析下联客户端 MAC 时会拿这个地址当 ARP sender，而客户端的 `arp_process` 会丢弃 sender 为 loopback 的 martian ARP——邻居表项一过期，回程流量就间歇黑洞。

修复是在 TC 挂载期间把下联网卡的 `arp_announce` 提到 2（强制用网卡自身主地址做 ARP sender），detach 时恢复原值，与已有的 `route_localnet` 处理方式一致。无需配置。

### 6. 内核自更新指向本分支

`POST /upgrade` 的 alpha 通道原本从上游拉取，下载到的版本不含上述改动，遇到用到新配置项的 config 会直接启动失败。现在指向本仓库的 `Prerelease-Alpha`。

### 7. tcclean

`cmd/tcclean`：一个通过 netlink 列出并清除指定网卡上 TC BPF filter 与 clsact qdisc 的小工具，用于 Android 上 `/system/bin/tc` 缺失、而异常退出留下 TC 程序残留的场景。仅 Linux 可用。

> 它是删除工具而非查看工具。Android 的 tethering offload 程序也挂在同一位置，误删会中断内核转发加速（netd 重启后会重建）。

---

## 完整配置示例

一台随身 WiFi 同时作为透明网关、Tailscale Subnet Router 与 Exit Node：

```yaml
# 各地区组共用的锚点
use: &use
  type: smart
  use: [机场A, 机场B, 备用机场]
  prefer-udp: true
  prefer-ipv6: true
  policy-priority: '\[备用机场\]:0.3'   # smart 内核原生选项，<1 降权
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
    listen-port: 41641
    advertise-routes: [192.168.0.0/24]
    advertise-exit-node: true

proxy-groups:
  - {name: 香港, <<: *use, filter: "(?i)港|hk"}
  - {name: 日本, <<: *use, filter: "(?i)日本|jp"}
  - {name: 自动选择, <<: *use, type: url-test, tolerance: 2, penalize-unstable: true}

listeners:
  - name: ebpf-in
    type: ebpf
    mode: hybrid            # local: 本机应用 / shared: 下联转发 / hybrid: 两者
    dns-mode: hijack
    local:
      ipv6-mode: auto
    shared:
      interface: [br0]      # 下联网卡
      ipv6-mode: always

tun:
  enable: true
  device: meta
  auto-route: true
  exclude-src-port: [41641]   # 放行 magicsock，避免绕回自身

rules:
  # tailnet 网段要排在所有 GEOIP / 私网 DIRECT 规则之前
  - IP-CIDR,100.64.0.0/10,TS,no-resolve
  - IP-CIDR6,fd7a:115c:a1e0::/48,TS,no-resolve
  - GEOIP,CN,DIRECT
  - MATCH,自动选择
```

## 构建

无需 NDK 与 cgo：

```bash
# Android / arm64（随身 WiFi、手机）
CGO_ENABLED=0 GOOS=android GOARCH=arm64 \
  go build -tags "with_gvisor with_ebpf" -trimpath \
  -ldflags '-w -s -buildid=' -o mihomo .

# Linux / amd64
CGO_ENABLED=0 GOARCH=amd64 go build -tags "with_gvisor with_ebpf" -o mihomo .
```

`with_ebpf` 才会编入 eBPF 入站；BPF 对象已随仓库提供，无需 clang。eBPF 的 TCX 挂载需要内核 6.6+，更早的内核（如 5.4）自动回退到 clsact。

## 上游与致谢

本分支的代码来自这三处，配置与用法请优先参考它们的文档：

- [MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo) — 上游本体
- [vernesong/mihomo](https://github.com/vernesong/mihomo) — smart 内核（`type: smart` 策略组、LightGBM 权重模型、`policy-priority` 等）
- [TanakaLun/mihomo](https://github.com/TanakaLun/mihomo/tree/ebpf-inbound) — eBPF 透明入站（移植自 sing-box 的 cilium/ebpf 后端）

以及 mihomo 自身所站立的项目：

- [Dreamacro/clash](https://github.com/Dreamacro/clash)
- [SagerNet/sing-box](https://github.com/SagerNet/sing-box)
- [riobard/go-shadowsocks2](https://github.com/riobard/go-shadowsocks2)
- [v2ray/v2ray-core](https://github.com/v2ray/v2ray-core)
- [WireGuard/wireguard-go](https://github.com/WireGuard/wireguard-go)
- [yaling888/clash-plus-pro](https://github.com/yaling888/clash)

## 许可

GPL-3.0，与上游一致。
