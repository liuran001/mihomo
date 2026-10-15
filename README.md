<h1 align="center">
  <img src="Meta.png" alt="Meta Kernel" width="200">
  <br>mihomo · smart + eBPF + Tailscale<br>
</h1>

<p align="center">
  <a href="https://github.com/liuran001/mihomo/actions"><img src="https://img.shields.io/github/actions/workflow/status/liuran001/mihomo/build.yml?branch=Alpha&style=flat-square&label=build"></a>
  <img src="https://img.shields.io/github/go-mod/go-version/liuran001/mihomo/Alpha?style=flat-square">
  <a href="https://github.com/liuran001/mihomo/releases"><img src="https://img.shields.io/github/release/liuran001/mihomo/all.svg?style=flat-square"></a>
</p>

一个面向**随身 WiFi / 手机热点 / 旁路由网关**深度优化的 [mihomo](https://github.com/MetaCubeX/mihomo) 分支。以 [vernesong](https://github.com/vernesong/mihomo) smart 内核为底，合入 [TanakaLun](https://github.com/TanakaLun/mihomo/tree/ebpf-inbound) / [CHIZI-0618](https://github.com/CHIZI-0618/sing-box) 的 eBPF 透明入站，并增强了 Tailscale 双向网关与节点智能优选能力。

> 通用配置与规则用法请参考[上游官方文档](https://wiki.metacubex.one/)。本文档主要聚焦于**分支新增特性**与**对应配置说明**。

---

## 核心变动

| 特性 | 说明 | 适用场景 |
| --- | --- | --- |
| **eBPF 透明入站** | 流量在内核层捕获或放行，无需 iptables/nftables。国内 IP 在内核直接放行不进核心进程；支持热更新与分角色（本机/下联）独立分流。 | 随身 WiFi、热点共享、软路由旁路 |
| **节点真实可用性优选** | 主动探测并优先选中真正支持 UDP / IPv6 的节点；对频繁丢包断流的节点动态降权；支持基于 ASN 的会话粘性调度。 | QUIC、外服游戏、语音通话、流媒体 |
| **Tailscale 双向入站与网关** | Tailscale 不仅能出站，还可作为 Inbound 接收 Tailnet 设备访问，并支持作为 Subnet Router 和 Exit Node，进站流量完整经过规则分流。 | 远程组网、异地漫游、家庭网关分流 |
| **网络与 DNS 优化** | 默认开启 DNS 连接池复用；TUN 默认采用高性能 `mips` 栈并支持 BBR 拥塞控制；eBPF 与 TUN 智能协同。 | 全场景 |

---

## 配置指南

### 1. eBPF 透明入站

#### 基础透明入站（最小配置）
只需在 `listeners` 中添加 `type: ebpf` 监听。下联设备无需配置代理或安装证书，连上即可接管：

```yaml
# 方式 A：mihomo 原生写法
listeners:
  - name: ebpf-in
    type: ebpf
    mode: hybrid              # local: 仅本机; shared: 仅下联; hybrid: 二者均接管
    dns-mode: hijack          # 劫持 53 端口 DNS 到核心
    shared:
      interface: [br0]        # 替换为下联网卡名（热点填 wlan0，桥接填 br0）

# 方式 B：sing-box 风格写法（效果相同，二选一）
listeners:
  - name: ebpf-in
    type: ebpf
    local:
      enable: true
    shared:
      enable: true
      interface: [br0]

tun:
  enable: false               # 纯 eBPF 环境建议关闭 TUN
```

#### 国内 IP 内核直接放行
通过 `bypass-rule-set` 关联 IP 规则集，命中目标直接在 Linux 内核层直连放行，不再进入 mihomo 核心进程：

```yaml
rule-providers:
  CN-IP:
    type: http
    behavior: ipcidr          # 注意：eBPF 旁路仅支持 ipcidr 规则集
    format: mrs
    interval: 86400
    path: ./rule_provider/cn-ip.mrs
    url: "https://github.com/MetaCubeX/meta-rules-dat/raw/meta/geo/geoip/cn.mrs"

listeners:
  - name: ebpf-in
    type: ebpf
    mode: hybrid
    bypass-rule-set: [CN-IP]  # 顶层配置对 local 与 shared 均生效
    shared:
      interface: [br0]
```

> **分角色独立直连**：
> - 顶层 `bypass-rule-set` 会作用于所有角色。
> - 若希望本机与下联采取不同策略（例如本机国内直连、随身 WiFi 下联设备全走代理），可在角色内单独配置：
>   ```yaml
>   listeners:
>     - name: ebpf-in
>       type: ebpf
>       local:
>         enable: true
>         bypass-rule-set: [CN-IP]   # 仅本机直连放行 CN-IP
>       shared:
>         enable: true
>         interface: [wlan0]         # 下联设备全部接管代理
>   ```

#### 与 TUN 模式共存
若需要同时开启 TUN 和 eBPF：
- 默认保持 `bypass-tun-direct: true`，被 TUN auto-route 抓取的 bypass 流量直接直连，不进入规则引擎重复匹配。
- 建议将 `tun.strict-route` 设为 `false`，避免与 eBPF 重定向冲突。
- 避免在同一张网卡上同时开启 eBPF `shared` 和 TUN `auto-redirect`。

#### eBPF 常用参数说明

```yaml
listeners:
  - name: ebpf-in
    type: ebpf
    # 模式选择：使用 mode: hybrid 或在 local/shared 内设置 enable: true
    mode: hybrid                      # [local | shared | hybrid]，默认 local
    network: [tcp, udp]               # 接管协议
    udp-timeout: 300                  # UDP 会话保持超时（秒），默认 300
    bypass-rule-set: [CN-IP]          # 内核直连 IP 规则集（全局生效，需 behavior: ipcidr）
    bypass-tun-direct: true           # TUN 共存时 bypass 目标是否直接直连
    fakeip-icmp: off                  # 是否在内核回显 fake-ip 的 ICMP（off/reply）

    # 本机进程接管配置
    local:
      enable: true                    # 启用本机接管（与 mode 二选一）
      bypass-rule-set: []             # 仅对本机生效的额外直连规则集
      data-plane: cgroup              # 数据面：cgroup（默认，兼容性广）或 tc
      dns-mode: hijack                # [hijack | respect_policy | off]，推荐 hijack
      ipv6: true                      # 是否接管本机 IPv6
      bypass-private-address: true    # 是否放行私网地址（默认 true）
      include-uid: [0, 1000]          # 仅接管指定 UID（可选）
      exclude-uid: [1052]             # 排除指定 UID（可选）
      bypass-port: [22]               # 本机直连端口

    # 下联转发接管配置（旁路由 / 热点网关）
    shared:
      enable: true                    # 启用下联接管（与 mode 二选一）
      interface: [br0]                # 下联网卡名（必填，可填多张网卡）
      allow-default-upstream: false    # 单臂旁路由（下联=默认上游同一张网卡）设为 true 强制接管
      bypass-rule-set: []             # 仅对下联生效的额外直连规则集
      data-plane: packet_rewrite      # 数据面：packet_rewrite（默认）或 socket_assign
      dns-mode: hijack
      ipv6: true
      bypass-private-address: false   # 旁路由通常设为 false 以便统计下联互访
      include-source-cidr: []         # 仅接管特定下联来源网段（默认全部）
      exclude-source-cidr: []         # 排除特定来源网段
      include-mac-address: []         # 按 MAC 过滤客户端（优先级高于 CIDR）
      exclude-mac-address: []
      bypass-port: []                 # 下联直连端口
```

#### eBPF 关键注意事项
1. **平滑热重载支持**：更新 `udp-timeout`、`bypass-rule-set` 及 `bypass-tun-direct` 时支持原地平滑应用，无需销毁重建内核 BPF map，现有连接不中断。规则集更新时亦会自动增量同步进内核。
2. **DNS 劫持不受 bypass 影响**：`dns-mode: hijack` 在内核最前置步骤接管 53 端口，DNS 广告拦截与分流策略（如 `nameserver-policy`）依然正常生效。
3. **Fake-IP 永不被直连放行**：即使 fake-ip 段落在私网网段内，也会准确进入核心处理。开启 `fakeip-icmp: reply` 可在内核直接回复 ICMP Echo，解决 ping 连通性测试超时。
4. **下联网卡必须准确**：`shared.interface` 必须指定真实的下联物理/桥接网卡（如 `br0`、`wlan0`），上联出口网卡会自动跳过。
   单臂旁路由（唯一网卡既是下联又是默认上游）请设 `shared.allow-default-upstream: true`，否则该网卡会被上述防呆逻辑剔除、接管静默失效。
5. **内核版本要求**：推荐 Linux 5.4 及以上内核（主流 5.10+、6.x 原生支持良好）。详细特性矩阵与平台测试见 [docs/ebpf-validation.md](docs/ebpf-validation.md)。

---

### 2. 节点智能优选 (UDP / IPv6 / ASN 聚合 / 稳定性探针)

在策略组中开启以下参数，适用于 `url-test`、`smart` 和 `load-balance` 策略组：

```yaml
proxy-groups:
  - name: 智能优选
    type: smart
    use: [订阅A, 订阅B]
    prefer-udp: true          # 优先选择经 STUN 探测确认能正常转发 UDP 的节点
    prefer-ipv6: true         # 优先选择确认具备可用 IPv6 出站的节点
    prefer-asn: true          # 基于目标 ASN 进行服务聚合与粘性调度，大幅降低跨节点抖动
    penalize-unstable: true   # 对经常握手成功但无法收发数据的断流节点实施动态降权惩罚
```

- **机制说明**：采用**延时惩罚降权机制**而非直接剔除节点。当延迟相近时优先调度真实可用的节点；若探测不通或网络波动，节点仍保留在候选池作为备选。
- **独立探测通道**：UDP/IPv6 探针走独立通道，不污染 Web 面板上的常规延迟与存活状态。
- **配置注意**：
  - smart 策略组的健康检查参数为同级字段（`url` / `interval` / `lazy`），无需嵌套 `health-check` 字段。
  - `sample-rate` 仅控制 LightGBM 训练样本采集比例，非全局省电开关。

---

### 3. Tailscale 入站、Subnet Router 与 Exit Node

本分支支持将 Tailscale 作为 Inbound 接入，并可兼任子网路由与出口节点：

```yaml
proxies:
  - name: TS
    type: tailscale
    hostname: my-gateway              # Tailnet 内显示的设备名
    auth-key: tskey-auth-xxxxx
    udp: true
    accept-routes: true               # 接收其他节点广播的子网路由
    listen-port: 41641                # 固定 magicsock 端口
    advertise-routes:                 # 广播子网路由（Subnet Router）
      - 192.168.0.0/24
    advertise-exit-node: true         # 声明为出口节点（Exit Node）
```

- **规则分流**：从 Tailnet 接入的流量经过核心规则引擎（Inbound 类型为 `TAILSCALE`）。作为 Exit Node 时，出口流量同样享受 mihomo 的国内外分流规则。
- **与 TUN 共存避坑**：若同时开启了 TUN，需在 TUN 中排除 Tailscale 端口以防流量回环：
  ```yaml
  tun:
    exclude-src-port: [41641]
  ```
- **路由规则顺序**：Tailscale 虚拟私网 IP（`100.64.0.0/10` / `fd7a:115c:a1e0::/48`）需放在 `GEOIP,CN` 与私网 DIRECT 规则**之前**：
  ```yaml
  rules:
    - IP-CIDR,100.64.0.0/10,TS,no-resolve
    - IP-CIDR6,fd7a:115c:a1e0::/48,TS,no-resolve
    - GEOIP,CN,DIRECT
    - MATCH,智能优选
  ```

---

### 4. 网络与 DNS 增强

- **DNS 连接复用**：普通 UDP、TCP 和 DoT 默认开启长连接池复用，无需额外配置。如需对特定上游关闭复用，可在服务器末尾追加参数：
  ```yaml
  dns:
    nameserver:
      - 'tls://1.1.1.1:853#disable-reuse=true'
  ```
- **TUN 协议栈优化**：当开启 TUN 时，默认协议栈已切换为自研高性能 `stack: mips`，并支持指定 TCP 拥塞控制算法：
  ```yaml
  tun:
    enable: true
    stack: mips                       # 默认 mips（亦可选 gvisor / mixed / system）
    congestion-controller: bbr        # 可选 bbr, bbr3, cubic, reno（仅 mips 生效）
  ```

---

## 完整配置示例

以下为一个即开即用的随身 WiFi / 旁路由网关配置（包含 eBPF 透明入站、国内 IP 内核直连、DNS 广告拦截与 Tailscale 网关）：

```yaml
mode: rule

# 策略组通用锚点
use: &use
  type: smart
  use: [机场A, 备用机场]
  prefer-udp: true
  prefer-ipv6: true
  prefer-asn: true              # 开启基于 ASN 的会话粘性调度
  policy-priority: '\[备用机场\]:0.3'    # smart 原生权重调整
  url: https://cp.cloudflare.com
  interval: 300
  lazy: true

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
  - {name: 智能优选, <<: *use, type: url-test, tolerance: 2, penalize-unstable: true}
  - {name: 香港节点, <<: *use, filter: "(?i)港|hk"}
  - {name: 日本节点, <<: *use, filter: "(?i)日|jp"}

rule-providers:
  CN-IP:
    type: http
    behavior: ipcidr              # eBPF bypass 仅支持 ipcidr 规则集
    format: mrs
    interval: 86400
    path: ./rule_provider/cn-ip.mrs
    url: "https://github.com/MetaCubeX/meta-rules-dat/raw/meta/geo/geoip/cn.mrs"
  广告拦截:
    type: http
    behavior: domain              # 域名规则集用于 DNS 拦截
    format: mrs
    interval: 86400
    path: ./rule_provider/ads.mrs
    url: "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/Filters/AWAvenue-Ads-Rule-Clash.mrs"

listeners:
  - name: ebpf-in
    type: ebpf
    mode: hybrid
    dns-mode: hijack
    bypass-rule-set: [CN-IP]      # 国内 IP 直连不进核心
    bypass-private-address: false # 旁网关场景保留下联互访进核心统计
    shared:
      interface: [br0]            # 下联网卡名（随身 WiFi 填 wlan0，桥接填 br0）

tun:
  enable: false                   # 纯 eBPF 模式下关闭 TUN

dns:
  enable: true
  listen: 0.0.0.0:1053
  enhanced-mode: redir-host
  nameserver-policy:
    "rule-set:广告拦截": rcode://success
  nameserver: [223.5.5.5, 119.29.29.29]

rules:
  - IP-CIDR,100.64.0.0/10,TS,no-resolve
  - IP-CIDR6,fd7a:115c:a1e0::/48,TS,no-resolve
  - GEOIP,CN,DIRECT
  - MATCH,智能优选
```

---

## 编译构建

预编译 BPF 对象已包含在仓库中，无需安装 NDK / LLVM / Clang，亦无需开启 CGO：

```bash
# Android / arm64（随身 WiFi、手机）
CGO_ENABLED=0 GOOS=android GOARCH=arm64 \
  go build -tags "with_gvisor with_ebpf" -trimpath \
  -ldflags '-w -s -buildid=' -o mihomo .

# Linux / amd64（软路由、服务器）
CGO_ENABLED=0 GOARCH=amd64 \
  go build -tags "with_gvisor with_ebpf" -trimpath \
  -ldflags '-w -s -buildid=' -o mihomo .
```

> **注意**：必须携带 `with_ebpf` 编译标签才会启用 eBPF 透明入站模块。

---

## 技术细节与参考文档

若需深入了解实现机制、内核数据面架构或兼容性测试，请参阅：
- [docs/ebpf-inbound.md](docs/ebpf-inbound.md) — eBPF 透明入站完整英文规范与数据流设计
- [docs/internals.md](docs/internals.md) — 核心改动记录与内部机制细节
- [docs/ebpf-validation.md](docs/ebpf-validation.md) — 内核版本支持矩阵与实机验证记录

---

## 上游与致谢

- [MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo) — 上游项目本体及 [官方文档](https://wiki.metacubex.one/)
- [vernesong/mihomo](https://github.com/vernesong/mihomo) — smart 策略组与模型选择机制
- [TanakaLun/mihomo](https://github.com/TanakaLun/mihomo/tree/ebpf-inbound) — eBPF 透明入站适配层
- [CHIZI-0618/sing-ebpf](https://github.com/CHIZI-0618/sing-ebpf) — eBPF TC + cgroup 后端后续开发；本分支保留内置后端
- [Dreamacro/clash](https://github.com/Dreamacro/clash) 与 [SagerNet/sing-box](https://github.com/SagerNet/sing-box)


最后感谢以下大模型，代码都是它们写的

- Claude Opus 5.5
- Claude Fable 5.1
- Claude Opus 5
- GPT 6 Astra
- GPT 6.1 Sol
- GPT 5.6 Sol
- Gemini 3.8 Flash: 本文档编写

## 许可证

本项目遵循与上游一致的 [GPL-3.0](LICENSE) 许可证。
