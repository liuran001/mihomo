# 实现细节

本文件是 [README](../README.md) 里 eBPF 入站、smart 选择器和 Tailscale 入站的实现
说明与改动记录，正常使用不需要看。英文的完整规格见 [ebpf-inbound.md](ebpf-inbound.md)。

## eBPF 入站是怎么做的

后端代码移植自 [CHIZI-0618/sing-box](https://github.com/CHIZI-0618/sing-box) 的 `testing-ebpf-tc-rewrite` 分支（经 TanakaLun 的 mihomo 适配层），是"一份策略 + 可选数据面"的结构：

- **local 默认走 cgroup**：挂 `connect4/6`、`sendmsg4/6`、`recvmsg4/6`，在 `connect()` 和 `sendmsg()` 的时候把目标地址改写成本机 loopback 上的一个重定向地址（从 `127.128.0.0/9` 等候选里自动挑一个不和路由、网卡地址、fake-ip 段冲突的），原始目标存进 BPF map，mihomo 收到连接后再查回来。可选 `data-plane: tc`：在默认网卡 egress 上选包，改目的 MAC 后 `bpf_redirect` 进一对 veth，在对端 ingress 用 `bpf_sk_assign` 直接塞给内部监听 socket，配合自动分配的 fwmark / 路由表把包送进本机协议栈。
- **shared 默认走 packet_rewrite**：在下联网卡 ingress 把目的地址改写到重定向地址，egress 再改回来，回程包的源地址也一起还原；可选 `socket_assign` 保留原始五元组、直接 `bpf_sk_assign`。
- **自身流量识别**：mihomo 自己的 socket 通过 socket cookie 登记到一张 LRU map（进程独占 cgroup 时由 `sock_create/release` 钩子维护，否则由 dialer 建 socket 时登记），所有数据面在拦截前先查它，不再依赖 TGID 比对。
- **进程归属**：可选的 cgroup 跟踪程序记下 cookie → pid/uid，用户态只读 `/proc/<pid>/exe` 就能给 `PROCESS-NAME` 规则用，不必扫全部进程的 fd。
- **策略只编译一次**：UID 区间、源 CIDR/MAC、端口、fake-ip 段、DNS 模式编成一份不可变快照，各数据面编码进自己的 control map；`bypass-rule-set` 和 `fake-ip-range` 变化时同时刷进所有活着的后端。

CN IP 直连是把规则集里的网段编译进两个 LPM trie（IPv4 一个、IPv6 一个），BPF 程序查表命中就直接返回放行，整个改写流程都不走。判断顺序是：自身 socket → 安全网关（分片、DHCP、保留地址）→ fake-ip 强制拦截 → DNS 模式 → UID / 源策略 → bypass 端口 → 本机地址 → 私网 → bypass CIDR。DNS 排在 CIDR 前面，所以劫持 DNS 不受 bypass 影响。

## 状态表与回收

状态回收按数据面和表的用途区分，不能概括为「5.4 完全依赖 LRU」：

- **cgroup 重定向状态**：具备相应能力时通过 socket 关闭钩子清理；用户态消费和释放也会删除对应记录。缺少原子 lookup-and-delete 时，UDP 恢复表保留记录交给 LRU，避免删除并发写入的新值。
- **shared 流状态**：用户态跟踪流引用和代次，连接释放及定期清扫共同回收；表占用超过 70% 时加速清扫，回落到 50% 以下退出压力模式。
- **用户态 UDP 状态**：按 `udp-timeout` 回收空闲客户端，排队中的包、正在解析的 DNS 和下行回包都会参与保活。每次每张表最多检查 1024 个客户端，每批最多检查 32 个后释放收发锁；大表按游标每秒续扫，完整一轮结束后恢复常规间隔。这不是活跃客户端或目的地址绑定的总量上限。
- **LRU 表**：容量满时可淘汰记录，但并不保证只淘汰已关闭连接；高压力下仍可能影响存量流量，不能把 LRU 当成无限容量保证。

当前还有两项固定资源限制，无需也没有对应 YAML 开关：每个入站的 DNS 中继按传输方式分账——TCP 中继占用名额的时间是整条连接，UDP 中继只占一个数据报，因此 UDP 256 个并发名额、TCP 128 个并发连接，且 TCP 名额用掉一半以后，单个来源地址最多再占 8 个。超限 UDP 查询丢弃、TCP 连接关闭，两者都会限速打日志。透明 UDP 回包 socket 缓存分成 16 个分片，每片最多 64 个存活 socket（总上限 1024，包含等待在途写入完成才关闭的 socket）。单片满且全部被占用时，该次回包会失败。

这些优化复用现有 `udp-timeout`（默认 300 秒、最小 5 秒）。若设备内存紧张，可结合业务调整空闲超时；过短可能打断长时间无收发的 UDP 会话。内核与设备测试范围见 [验证记录](ebpf-validation.md)，其中的分类器微基准不代表整机吞吐或耗电收益。

## 已修的问题

**UDP 超时单位错误。** `udp-timeout` 的值被当成纳秒而不是秒用了，配置 300 实际是 300 纳秒，导致 UDP 状态每 5 秒左右被清空一次。上游重写后这个问题又回来了一次，这里再次修掉，并用测试钉死。

**重定向表耗尽导致断流。** 重定向表原本是固定大小的 hash map，而 BPF 侧从不删除 TCP 表项。跑一段时间填满之后，`bpf_map_update_elem` 返回 `-E2BIG`，四次 token 尝试全部失败，`connect()` 直接被拒绝，从此每个新连接都失败，重启才恢复。改成 LRU 之后满了只淘汰最久未用的表项，不再拒绝新连接。

**统计计数器索引撞车。** Go 侧的常量声明漏了 `iota`，UDP 的失败计数索引被写成了 0，和 TCP 共用一个槽位，读到的数是错的。（统计计数器随上游重写一起被移除，此条只作历史记录。）

**TCP 连接路径上的多余查表。** `token_v4_attempt` / `token_v6_attempt` 对 TCP 会先查一次 UDP 表再查 TCP 表。协议是 key 的一部分，那次查询不可能命中，纯属浪费——每次 `connect()` 白算一次哈希，最坏四次。上游最终的写法是按协议走两条静态路径（部分内核的 verifier 拒绝把动态选出的 map 指针传给 `bpf_map_lookup_elem`），已同步。

**共享网络的回程 ARP。** `shared` 模式改写回程包源地址为 loopback 重定向地址，内核解析下联客户端 MAC 时会拿这个地址当 ARP sender，客户端的 `arp_process` 会把 sender 为 loopback 的 ARP 当 martian 丢掉，邻居表项一过期回程就间歇黑洞。修复是挂载期间把下联网卡的 `arp_announce` 提到 2，卸载时恢复。

**两处内存泄漏。** 一是节点健康记录表的清扫挂在读路径上，而写路径无条件插入，配置里没开 `penalize-unstable` 时表只增不减；二是 TCX 挂载失败时的重试队列没有上限（上游重写后挂载改为事件驱动的按网卡对账，不再有这个队列）。

**诊断数据算了但没人看。** `ProbeKernel()` 会生成完整的内核能力报告，却没有任何调用方。现在内核能力报告在启动后打一次，列出当前内核缺哪些可选能力、各自意味着什么。共享流表的容量压力则由清扫器自己处理：占用超过 70% 进入加速清扫，回落到 50% 以下退出。断流那个 bug 之所以拖了那么久才被发现，就是因为这些降级路径全都"能用，只是没余量"，从外面看和健康状态一模一样。

**UDP 收发热路径。** 劫持的 UDP DNS 查询原来在收包循环里同步解析——一次上游查询期间，这张监听 socket 上所有客户端的 UDP 包都停着等它；现在解析放到独立 goroutine。本机/TC 数据面的回包路径原来握着一把全局互斥锁做 sendmsg，所有客户端的回包排成一队；现在是读锁。每个包的缓冲区原来用完就丢给 GC（`Drop` 是空的），现在归还池；每包一次的 NAT 键地址格式化改为按客户端缓存一次；每包解析两遍 cmsg 改为一遍；TC 数据面每个 UDP 包一次 assignment map 系统调用改为每条流一次。shared 模式的 TCP 连接包装层补上了 sing 的 unwrap 接口，直连出站时中继可以走内核 splice。

**fake-ip 段热更新与 TUN 共存。** 上游把 fake-ip 段编进一份启动时的不可变策略快照；这里保留了运行时更新——`fake-ip-range` 改了之后重编快照并推进所有活着的后端，后来才出现的下联网卡也按新段建后端——以及「和 TUN 共存」一节描述的整套路由排除 / 到达即直连机制，这两样 sing-box 侧都没有。

## 与 sing-box 上游的同步

2026-10-20 对照 `sing-ebpf/dev` 的 `9505052` 做了增量移植，未整体替换内置后端：

- 可选的进程跟踪和共享 self-bypass 清理钩子只使用 multi-program 挂载，避免旧内核的单程序回退阻止后续 cgroup 入站启动。
- UDP 代理缓存命中时重新核对重定向记录，覆盖记录被 LRU 淘汰或 token 被其他流复用的情况；同时修正大端目标上的地址转换及 UID 策略使用的字节序指令。
- shared packet-rewrite 区分 IPv4 UDP 禁用校验和与零值 `CHECKSUM_PARTIAL` 种子，维护 IPv6 `CHECKSUM_COMPLETE` 状态，并拉取驱动留在非线性区的包头。
- BPF batch 扫描也遵守每轮预算，跨轮保留游标；接口流清理使用独立游标，避免沿用空闲清扫进度而漏删。
- socket-address self-bypass 增加可选 release 清理；进程跟踪在 socket 关闭时同时删除归属与 UID 策略元数据。清理钩子不可用时继续使用有界 LRU。
- 绑定网卡的 cgroup 重定向连接增加按接口的本地路由和源地址选择，接口或地址变化后重新对账；未绑定网卡的 IPv4 socket 保持回环源地址。对账接入现有失败重试和定期修复，并放在 UDP 生命周期锁外；已有的非本后端路由不接管、不删除。
- self-bypass 自动标记只允许当前进程的 TGID，避免之后进入同一 cgroup 的子进程绕过代理；挂载后用真实 socket 检查标记。PID 命名空间无法安全对应、内核缺少 helper 或探测失败时，撤销自动标记并保留用户态注册及可选 release 清理。
- self-bypass 在配置校验后、启动拦截前创建 map；提前登记 socket 时也会按需创建并共享同一张表，关闭后不再重建。TC/cgroup 创建后即被共享表替换的占位 map 只分配最小容量，减少启动和重建时的临时内存占用。
- 旧内核的 verifier 日志缓冲区若因过大被拒绝，加载器会关闭日志重试以获取真实错误；保留原始错误链，并区分内核限制、缺少 BPF capability、用户命名空间和旧内核 memlock 预算。权限信息仅在实际失败时采集，原因无法确定时保留原错误。

对应上游的 `3bef0db`、`5f2244f`、`ee73db6`、`bec24de`、`1816695`、`a5433b6`，以及 `f35ef23` 中的部分修复。测试包含私有网络命名空间内携带 offload 元数据的 veth 实际投递、绑定网卡的 IPv4/IPv6 TCP/UDP 收发、地址变化和路由丢失恢复、已有路由保护，以及子进程隔离和标记失败回退。WSL 内用测试专用 BPF 探针读取内核 TGID 验证进程过滤，生产代码仍保留 PID 命名空间检查；这不代表已验证实体网卡或全部旧 Android 内核。

TC assignment 的有界回收和诊断暂未移植：上游的新清扫器依赖内核活动时间、存活引用和回程路由状态，本分支仍使用宿主命名空间以及按 generation 退休的 UDP 元数据，不能直接套用删除策略。后续可先补各张 map 的容量、扫描进度和回收错误诊断，再适配 TC 活动时间及安全回收。上游的 socket-assignment 私有命名空间、多实例 slot/TCX 排序和 sysctl 租约也涉及资源所有权及回程设计，需单独适配；不能直接套用整个 `f35ef23`。新增的旧内核错误路径通过模拟 verifier 和权限错误验证，WSL 运行结果不代表已覆盖 4.19 或实体 Android 设备。

2026-10-07 更新：原 `testing-ebpf-tc-rewrite` 分支已不存在，后续开发转到
[CHIZI-0618/sing-ebpf](https://github.com/CHIZI-0618/sing-ebpf)。本分支继续保留内置后端。下文的 `4af7ae48`
是初始移植基线，并非当前后端完整同步的版本号。

eBPF 后端以 [CHIZI-0618/sing-box](https://github.com/CHIZI-0618/sing-box) 的 `testing-ebpf-tc-rewrite` 分支为准。该分支会 force-push 重写历史，所以同步时按 `common/ebpf/internal/bpfgen/manifest.txt` 里的源文件哈希和目录树对比，不看 commit 祖先。当前已同步到 `4af7ae48`，比 TanakaLun 分支多出这几个修复：

- **自身流量误判**（`58cd212d`）：开启进程跟踪后 UID 策略位也写进 cookie 表，原来任何被跟踪的 socket 都会被当成 mihomo 自身而绕过；现在必须带 `SELF_BYPASS` 位才算，exclude 模式下的元数据取反也一并修正。
- **cgroup token 分配**（`9f798e09`）：按协议走两条静态 map 路径，避开部分内核 verifier 对动态 map 指针的拒绝。
- **Android netd 刷 clsact 后的 EINVAL**（`1820f646`）：删 filter 返回 EINVAL 时复查一次，确认已不存在就当删除成功，否则 TC 数据面会静默失效再也不重挂。
- **fwmark 位被占满**（`4a8b08be`）：mark 位从 bit30 一路扫到 bit0，带 FRA_FWMASK 的规则只算 mask 位；解决 Android 上 netd 规则把高位占满导致分配失败。
- **热点网卡重配置事务化**（`aaf7146b`）：先建候选挂载再提交，失败整体回滚，不再出现"旧的拆了新的没挂上"的半残状态。
- 启动日志里打印解析后的 UID 区间（`4af7ae48`）。

## Tailscale

上游的 `type: tailscale` 只有出站。这里把 tsnet 的 fallback TCP/UDP 流处理接到了 mihomo 的 tunnel 上，从 tailnet 进来的流量因此会走规则引擎。netstack 本身就处理 subnet 流量，所以 Subnet Router 和 Exit Node 是顺带就有的。

还修了一个 TUN 模式下的直连问题：上游把 magicsock 的 UDP socket 交给 outbound dialer，于是被 `auto-detect-interface` 用 `SO_BINDTODEVICE` 绑到了默认出口网卡上。绑了网卡的 socket 收不到从其他本地网卡（比如自家 LAN）到达的 disco 包，同一个局域网里的两台设备也只能走 DERP 中继，实测从 4 ms 恶化到 250 ms。现在默认不绑，只有显式配了 `interface-name` / `routing-mark` 或存在 socket hook（CMFA）时才保留原行为。

## WebUI 控制面与转发隔离

- `/tailscale` 状态只读取独立的小快照，不等待 tsnet 启动锁，也不调用会扫描 WireGuard 状态的 LocalAPI Status。快照复用 IPN watcher：首次收取 NetMap，此后请求 self 变更而非反复序列化全部 peers。打开状态页不会启动或唤醒未使用的 Tailscale 出站；登录/退出才进行控制操作，启动等待有超时并共享同一个在途任务。
- 账号按本机 `Self.User` 匹配 `UserProfile.ID`，不会取 Tailnet 用户表中的第一项。它代表设备注册属主，不是查看网页的浏览器账号；身份缺失时留空，不猜测团队成员。进入 NeedsLogin 时清除旧账号。
- 首页改用 `/connections/summary`、`/overview`、`/ebpf/summary`。连接摘要读原子计数和连接数，RSS 最多每秒按需采样；出口链最多 32 层，概览不为展示而选择 Smart/LoadBalance 节点，不展开所有代理、连接与规则。
- `/connections/sources` 按来源 IP 汇总经内核的流量（含已关闭连接，启动或重置统计后清零），供模块的设备页显示每台共享设备的累计流量，速率由前端两次采样相减得出。连接建立时查一次所属来源的计数器（最多记 4096 个来源），之后每次读写只多一次原子加；只统计计入总流量的连接，链式代理与内核自身 DNS 的连接不重复计。读接口只读计数器，不遍历连接表；关闭连接只释放一次计数器引用，没人读取时没有任何后台任务。没有连接在用、且最后一条连接关闭超过 1 小时的来源会被清掉（离开的设备、轮换掉的 IPv6 临时地址），之后再出现时从零计起；清理不用定时器，读接口时或计数表满时顺带进行，最多每分钟一次。重置统计时没有连接的来源立即清掉。
- `/ebpf` 仍保留手动详细诊断：只允许一个在途扫描，跨表共享 100 ms 检查预算，每表最多检查 16,384 个 key，定期响应取消，不持数据面锁遍历全部 map。它不是硬实时保证，单次系统调用和调度仍可能延迟。
- 实时日志消费者满载时丢弃该消费者的新事件，不反压代理流量；普通 Observable 的可靠传递语义不变。info 订阅不再隐式启用所有 debug 格式化。本地日志输出仍遵循所设日志等级。

相关竞态测试、慢日志回归、启动锁竞争测试及 Android arm64 交叉编译已验证。桌面微基准与模拟 WebUI 只能说明调用开销和隔离行为，不能替代实体设备的温度、电流、吞吐或续航测量；升级时须同时更新模块与内核，旧内核缺摘要接口时首页提示升级，不退回高频全量扫描。

## 其他

**内核自更新指向本分支。** `POST /upgrade` 的 alpha 通道原本从上游拉，下载到的版本不含这些改动，用了新配置项的 config 会直接启动失败。现在指向本仓库的 `Prerelease-Alpha`。

**`cmd/tcclean`。** 通过 netlink 列出并清除指定网卡上 TC BPF filter 与 clsact qdisc 的小工具，用于 Android 上 `/system/bin/tc` 缺失、异常退出留下残留的场景。仅 Linux 可用。注意它是删除工具不是查看工具，Android 的 tethering offload 程序也挂在同一位置，误删会中断内核转发加速（netd 重启后会重建）。
