# sing-box eBPF inbound backend

This directory contains the native eBPF backend used by the sing-box eBPF
inbound. It is a maintainer document; user-facing configuration and platform
requirements live in [`docs/configuration/inbound/ebpf.md`](../../docs/configuration/inbound/ebpf.md).

## Responsibilities

The Go side owns object loading, map lifetime, cgroup and TC attachments, policy
compilation, and listener integration. The native C side is the packet and
socket data path. The runtime uses `github.com/cilium/ebpf` and has no cgo
boundary or process-global probe.

| Area | Files | Responsibility |
|------|-------|----------------|
| cgroup path | `cgroup_*.go`, `redirect_address*.go` | Local socket hooks, redirect maps, UID policy, cgroup discovery, and original-destination state |
| shared path | `shared_network_*.go` | TC links, interface lifecycle, source/MAC policy, flow state, and host-address bypass maps |
| common runtime | `loader.go`, `backend_runtime.go`, `map.go`, `kernel_*.go` | cilium object loading, direct map syscalls, feature probes, memlock, and `tools ebpf status` |
| native data path | `native/cgroup.bpf.c`, `native/shared_network.bpf.c`, `native/*.h` | Verifier-friendly socket and packet programs plus explicit map ABI |
| generated objects | `internal/bpfgen/` | `bpf2go` bindings, endian-specific BPF objects, and the generation manifest |

The native sources are intentionally split into policy, packet parsing, flow,
and checksum helpers, but are compiled as one verifier-visible translation unit
per entry point. Shared ingress and egress have separate entry points so each
loaded program remains below the Linux 4.19 4096-instruction limit.

## Data paths

### Local cgroup path

The local backend attaches socket-address programs to cgroup v2. Connect and
sendmsg hooks apply protocol, UID, DNS, private-address, host-address, FakeIP,
and CIDR policy before replacing the destination with an internal listener
token. recvmsg hooks restore connected UDP peer addresses. The userspace
listener uses the token to recover the original destination and then enters the
normal sing-box routing pipeline.

One sing-box process supports one local backend owner, including hybrid mode,
because protection for sing-box-created sockets is registered process-wide.

TCP state is short-lived bounded LRU state removed by the listener when the
original destination is consumed, or by the stale-state janitor. UDP redirect,
token, and peer state also use bounded LRU maps, with two capability-selected
cleanup paths:

- `socket_release`: an attached `cgroup/sock_release` program performs exact
  socket-cookie cleanup; the LRU policy remains as a last-resort guard for
  unconnected sendmsg flows that have no token to clean up.
- `lru_fallback`: kernels without a usable release hook rely on the LRU policy,
  connected-peer recovery, and conservative userspace cleanup.

The BPF hot path uses direct helpers. Go hot-path map access uses fixed ABI
structs and raw typed `bpf(2)` calls to avoid reflection and allocation.
Cilium APIs are used for object loading, probes, links, metadata, and cold-path
batch operations.

TCP splice programs prefer fd-owned BPF link attachments when the kernel
supports them. Older kernels transparently retain raw `BPF_PROG_ATTACH`, and
runtime status reports which attachment mode was selected.

The peer lookup value also accumulates directional byte counts without another
map lookup. Counts are reconciled with the existing traffic-control tracker
when a splice pair closes, so kernel-relayed DIRECT traffic is included in
Clash/API totals. Active splice connections therefore report their final byte
count at close rather than on every userspace refresh.

### Shared TC path

The shared backend attaches ingress and egress classifiers to each selected
downstream interface. Ingress parses Ethernet/VLAN and IPv4/IPv6 and applies
source and destination policy. For TCP, `shared.advanced.data_plane: auto`
first tries a modern socket-assignment path: `bpf_skc_lookup_tcp` locates an
established transparent socket, and `bpf_sk_assign` sends a new flow to the
listener through a SOCKMAP. The selected route uses a dedicated fwmark and
local policy-routing table. Assignment metadata preserves the ingress source
MAC for the userspace routing context.

The assignment path is an optimization, not a compatibility requirement. If
the SOCKMAP, helpers, program verifier, listener registration, or policy route
is unavailable, `auto` attaches the destination-rewrite path described below.
`socket_assign` makes assignment mandatory, while `rewrite` skips its probes.
TCP or UDP parsing, helper, or assignment failure inside the modern classifier also
continues through the rewrite classifier in the same program instead of
silently bypassing the proxy. UDP assignment is experimental and attempted only
when `data_plane: socket_assign` is explicit. It is independently
verifier-probed; when `bpf_sk_lookup_udp` is unavailable, TCP keeps its
assignment path while UDP alone uses rewrite state. The default `auto` mode
continues to use UDP rewrite.

The rewrite ingress path reserves a token address and rewrites the destination
to the internal listener. Egress finds the same flow by client and token,
restores the original source, and updates checksums. Fragment state is kept
separately in a bounded LRU map. The rewrite programs retain the Linux 4.19
4096-instruction ceiling; the optional assignment classifier has a separate
8192-instruction ceiling and is verifier-probed before fallback.

Proxy flow state has two authoritative lookup directions:

| Map | Key | Value | Reader |
|-----|-----|-------|--------|
| `shared_flow_by_original` | interface, family, protocol, client, original destination | token, generation, last activity | ingress and janitor |
| `shared_flow_by_token` | family, protocol, listener port, token, client | original destination, interface, source MAC, generation | userspace listener and egress |

The old layout stored the same logical flow in original, listener, and reply
maps. Independent publication and deletion could expose a partially built flow
under short-connection churn. The two-map layout uses this lifecycle:

1. Generate a token and a 64-bit generation from monotonic time and the flow
   hash.
2. Insert `flow_by_token` with `BPF_NOEXIST`.
3. Publish `flow_by_original` last with `BPF_NOEXIST`.
4. On cleanup, verify the generation and unpublish `flow_by_original` first.
5. Delete `flow_by_token` only when its generation still matches.

Publication therefore never makes ingress use a token before reverse lookup is
ready. Cleanup for an old connection cannot delete a newer generation, even if
the original tuple or token key is reused. Userspace validates both directions
once when accepting a flow; established packets retain one Hash lookup in each
direction and do not pay for a second generation lookup.

Compared with the former three-map layout, a proxy entry now uses two map
elements instead of three, a new flow performs two successful updates instead
of three, and cleanup performs two conditional deletes instead of three. The
reverse value is slightly larger because it contains all userspace and egress
metadata plus the generation. Total key/value payload per logical flow falls
from 224 to 164 bytes before allocator and bucket overhead. The per-CPU shared
scratch value also falls from 352 to 272 bytes.

### Experimental DIRECT TCP splice

`tcp_splice: true` prepares an independent SOCKHASH and attaches one
`SK_SKB` stream parser and verdict program. After normal routing selects the
built-in DIRECT outbound and both endpoints are established plain TCP sockets,
userspace flushes sniff buffers and currently queued bytes, publishes the two
peer keys, and inserts both sockets. `bpf_sk_redirect_hash` then moves stream
data directly between the sockets without the ordinary pair of Go copy
goroutines.

This path is deliberately narrower than the interception paths. It never
handles UDP, proxy or encrypted outbounds, multiplexing, TLS transformation,
or another inbound type. Preparation and pre-activation errors fall back to Go
copy. An active upstream power-report recorder also forces userspace copy
because kernel relay would bypass its attribution wrapper. An epoll watcher
releases both map directions and sockets on RDHUP, HUP,
or socket error; backend close also releases every active pair. No BPF state is
pinned. Because bytes moved in SOCKHASH bypass userspace wrappers, ordinary
per-connection traffic accounting is not updated in real time. The peer value
accumulates directional bytes without another map lookup, and pair release
reconciles them with the existing per-connection and global counters. Active
splice connections therefore expose their final accounted total only at close.

The splice runtime status separates kernel `redirect_successes`,
`redirect_failures`, `peer_misses`, and key parsing errors from fixed userspace
fallback reasons. Kernel counters use a per-CPU array so observation does not
add a shared atomic operation to stream redirection. Fallback reason names are
an ABI-like diagnostics surface; add a bounded enum instead of logging or
exporting arbitrary error strings.

## Policy maps

Exact host addresses use Hash maps. UID ranges, destination bypass CIDRs, and
shared source CIDRs use LPM tries because longest-prefix matching is required.
Source MAC policy uses Hash maps. Large rule sets are compiled and updated in
userspace; packet processing performs a bounded number of map lookups rather
than iterating rules.

Hash maps with `BPF_F_NO_PREALLOC` allocate elements on demand, although their
bucket array still scales with `max_entries`. LRU maps are reserved for bounded
cache or recovery state where eviction is semantically acceptable. Authoritative
shared proxy state uses non-LRU Hash maps and an explicit janitor so the kernel
cannot independently evict one lookup direction.

## Runtime lifecycle

Shared programs and maps are prepared lazily when the first configured
interface appears, then retained across temporary interface loss. TCX is used
at the default priority when available; clsact is the compatibility fallback.
Cgroup BPF links are preferred over legacy `BPF_PROG_ATTACH`. Neither path pins
runtime state in bpffs, so closing the owning process releases all kernel
objects.

Correctness maintenance remains enabled in release builds:

| Task | Normal trigger | Purpose |
|------|----------------|---------|
| Shared pressure poll | 5 seconds | Detect reservation failures and sustained proxy-map pressure. |
| Shared TCP grace cleanup | Earliest queued deadline | Reclaim closed TCP generations without periodic idle wakeups. |
| Shared orphan sweep | Reservation pressure or 5-minute fallback | Reclaim unreferenced proxy generations. |
| Shared attachment reconciliation | Network change or 2-minute watchdog | Attach new interfaces and repair TCX/clsact and `route_localnet`. |
| Local TCP cleanup | Redirect failure or 5-minute fallback | Remove state from failed or abandoned accepts. |
| Local IPv6 probe | Debounced network change | Implement `local.ipv6_mode: auto`. |

Normal Debug logging reports lightweight status every ten minutes without
walking large maps. `ebpf_debug` collects full occupancy, Go runtime, task
timing, and optional kernel program runtime statistics at startup, shutdown,
and after coalesced failure events. It does not add instrumentation to the
packet path.

## Generated objects

`internal/bpfgen/*_bpf{el,eb}.o` and their Go bindings are checked in. They are
architecture-neutral BPF bytecode, not Android or host-native objects. Both byte
orders are shipped so a big-endian OpenWrt target does not silently load a
little-endian object. Normal builds consume these files and do not invoke a C
compiler:

```sh
CGO_ENABLED=0 TAGS=with_ebpf make build
```

Regeneration is a maintainer operation. It uses Android NDK r29 Clang 21 and
the NDK Linux UAPI sysroot, even when the final binary targets Linux:

```sh
ANDROID_NDK_HOME=/usr/share/android-ndk-r29 make ebpf_generate
make ebpf_check
```

The Makefile clears ambient include-path variables, passes `-nostdinc`, and
allows only Clang resource headers, `native`, and the pinned NDK sysroot. The
`bpf2go` Go generator always runs as the build-host platform; `BPF_CLANG` still
controls the compiler used for the BPF C sources. `manifest.txt` records the
normalized flags, tool versions, source hashes, and object hashes.

## Compatibility invariants

- Shared mode and TCP-only local mode target Linux 4.19. Local UDP needs the
  upstream 5.2 cgroup UDP recvmsg attach types or a vendor backport.
- Android GKI 5.10+ and standard Linux/OpenWrt are the primary validation
  targets. Capability probes are authoritative because vendor kernels backport
  features independently.
- Programs use the BPF v1 instruction set and do not require BTF, CO-RE,
  bounded-loop verification, BPF timers, dynptrs, kfuncs, or pinned bpffs state.
  Default-priority shared-network attachment uses TCX when available and
  otherwise falls back to clsact.
- Shared host addresses use exact-match hash maps. They are not prefixes, and
  this avoids the Linux 6.6.0 through 6.6.46 LPM-trie UBSAN issue. UID/package
  filters and prefix-based CIDR policies still use LPM tries and are rejected
  on a known-unfixed kernel.
- IPv4 and native IPv6 sections are selected independently. When native IPv6 is
  disabled, smaller IPv4-mapped cgroup sections are loaded.

## Tests and diagnostics

Run the focused tests without cgo:

```sh
CGO_ENABLED=0 go test -tags with_ebpf \
  ./common/ebpf ./protocol/ebpf ./include ./option
```

An Android cross-test checks build tags and generated ABI without running the
test binary on Android:

```sh
GOOS=android GOARCH=arm64 CGO_ENABLED=0 \
  go test -c -tags with_ebpf -o /tmp/sing-box-ebpf-android.test ./protocol/ebpf
```

Privileged integration tests are opt-in. The load test exercises the cgroup and
standalone shared program matrix; the datapath test creates a temporary network
namespace and veth pair:

```sh
sudo -E SING_BOX_EBPF_INTEGRATION=1 \
  go test -count=1 -tags with_ebpf,ebpf_integration \
  -run 'Test(CgroupBackend|SharedNetwork).*Integration' ./common/ebpf

sudo -E SING_BOX_EBPF_SHARED_INTEGRATION=1 \
  go test -count=1 -tags with_ebpf,ebpf_integration \
  -run 'TestSharedNetwork(DataPath|TCPChurn)Integration' ./protocol/ebpf
```

`TestSharedNetworkProgramRunIntegration` executes the loaded sched_cls ingress
program through kernel `BPF_PROG_TEST_RUN`. It validates policy priority,
address/port rewriting, IPv4 and TCP checksums, first/later fragment state, and
fail-closed handling for missing fragment state and truncated selected packets.
The verifier workflow runs this test with root privileges.

`TestSharedNetworkTCPChurnIntegration` creates 5000 short TCP connections with
128 workers and validates lookup, generation retention, reply, and cleanup for
every accepted connection. The common-package generation cleanup test also
simulates a stale userspace handle against a newer map generation.

The maintenance benchmarks compare a full batch scan with one bounded legacy
fallback janitor tick over a populated 65536-entry hash map, and compare batch
and legacy connected-UDP recovery scans at the current default redirect
capacity:

```sh
sudo -E SING_BOX_EBPF_INTEGRATION=1 \
  go test -run '^$' -tags with_ebpf,ebpf_integration \
  -bench 'Benchmark(MapScanMaintenance|ConnectedUDPTokenRecoveryScan)' \
  -benchmem ./common/ebpf
```

For end-to-end comparisons against Redirect, TProxy, route-based TUN, and TUN
auto-redirect, use the isolated namespace harness described in
[`../../.github/benchmark/README.md`](../../.github/benchmark/README.md). It
measures local and shared eBPF separately, validates that tested flows do not
silently use the direct path, and includes long-lived UDP plus per-socket UDP
churn. Keep this cross-inbound harness separate from microbenchmarks: its
results include the complete sing-box routing and listener pipeline.

An opt-in end-to-end stress test attaches only to a temporary child cgroup. It
measures short TCP connections plus connected-UDP request/reply restoration and
socket-release cleanup. Counts and concurrency can be changed with
`SING_BOX_EBPF_STRESS_TCP_COUNT`, `SING_BOX_EBPF_STRESS_UDP_CONNECTED_COUNT`,
`SING_BOX_EBPF_STRESS_UDP_UNCONNECTED_COUNT`, and
`SING_BOX_EBPF_STRESS_WORKERS`. An `ebpf_debug` test binary can additionally
set `SING_BOX_EBPF_STRESS_STATS=1` to report per-program kernel runtime; keep
that system-wide instrumentation out of throughput baselines. Raise one UDP
count at a time for socket-churn limits: combining very large TCP, connected
UDP, and unconnected UDP counts can measure the host's ephemeral-port reuse
instead of the eBPF data path.

```sh
sudo -E SING_BOX_EBPF_INTEGRATION=1 SING_BOX_EBPF_STRESS=1 \
  go test -count=1 -v -tags with_ebpf,ebpf_integration \
  -run TestCgroupBackendTrafficStressIntegration ./common/ebpf
```

Use an empty, dedicated cgroup when testing attachment. On a target device,
capture the non-disruptive capability report before debugging traffic:

```sh
sing-box tools ebpf status --mode local --network tcp,udp
sing-box tools ebpf status --mode shared-network --interface br-lan
```

The status command creates transient probe objects and closes them immediately;
it does not attach programs or change routes, qdiscs, sysctls, cgroups, or
traffic.

For a temporary diagnostic build, add the `ebpf_debug` tag together with
`with_ebpf`. It adds runtime snapshots with Go heap, RSS, GC, goroutine, and
maintenance-task timing counters, and temporarily enables kernel
`BPF_STATS_RUN_TIME` for per-program run counts and runtime. The latter has
system-wide measurement overhead, so keep it out of release builds. It does
not add probes to the packet hot path. Use sing-box's
`experimental.debug.listen` option for Go pprof. See the
[troubleshooting guide](../../docs/manual/misc/ebpf-troubleshooting.md) for
collection commands and scope limitations.

## Configuration and policy mapping

The public configuration is decoded in `option/ebpf.go`, normalized by
`protocol/ebpf/config.go`, and compiled into the small ABI records consumed by
the native programs. Keep this flow explicit when adding a field; a field that
only changes Go listener behavior must not be added to the BPF ABI.

| User field | Go owner | Native control | Effect |
|------------|----------|----------------|--------|
| `mode: local` | `protocol/ebpf/inbound.go` | cgroup section selection | Redirect sockets created by the sing-box cgroup. |
| `mode: shared` | `protocol/ebpf/shared_network.go` | TC ingress/egress flags | Redirect traffic arriving from selected interfaces. |
| `network` | `config.go` | per-program enable flags | Load only TCP/UDP sections requested by the user. |
| `uid` / `package` include/exclude | `inbound_policy.go` | UID LPM maps and ranges | Match the creating process UID; see the limitation below. |
| `bypass_private_address` | policy compilers | private/host exact maps | Skip proxying private destinations while preserving mandatory local safety exceptions. |
| `bypass_rule_set` | policy compiler | destination LPM maps | Skip destinations in the resolved CIDR rule set. |
| `local.dns_mode` / `shared.dns_mode` | `config.go` | per-path DNS mode enum | `hijack` precedes user policy, `respect_policy` follows the complete path policy, and `off` bypasses port 53. |
| `local.ipv6_mode` / `shared.ipv6_mode` | `ipv6.go` | IPv6 section and route gate | Local `auto` follows usable native routes; `always` and shared mode do not use that gate; `off` bypasses native IPv6. |
| `shared.interface` | `shared_network.go` | TC attachment set | Only named, currently present interfaces are attached; no dynamic “wlan0” guessing is performed. |
| `tcp_splice` | `protocol/ebpf/splice.go` | SOCKHASH + `SK_SKB` | Explicitly offloads eligible DIRECT plain-TCP relay; all other connections keep Go copy. |
| `shared.advanced.data_plane` | `shared_network.go` | assignment/rewrite section selection | `auto` prefers TCP assignment with UDP rewrite; explicit `socket_assign` also probes experimental UDP assignment; `rewrite` selects the compatibility path. |
| `shared.advanced.routing_mark` / `routing_table` | `shared_network_route.go` | policy routing for assignment | Optional mark and table overrides; ignored by rewrite. |

The include/exclude UID ranges are logged after normalization in diagnostic
builds (and as a compact summary at startup in release builds). This is the
authoritative view of what the configuration became, including Android package
resolution and range coalescing.

### UID and package boundary

Package policy is a socket-creator policy. It guarantees decisions for sockets
created directly by the selected UID. It cannot identify a package when the
kernel or another service creates the socket on its behalf. In particular, the
policy is not a guarantee for system DNS proxies, `DownloadManager`, VPN or
connectivity services, isolated processes, or sockets handed across a Binder
boundary. Do not infer package ownership from the UID of a later relay.

Local and shared compile independent DNS modes. `hijack` forces enabled TCP/UDP
port-53 traffic into the inbound before UID/package, shared source, host,
private-address, and rule-set policy. `respect_policy` applies the complete
policy of that data path first. `off` bypasses port 53 before user policy.
Self/internal-loop prevention, protocol selection, DHCP safety, packet parsing,
and the relevant IPv6-off gate always remain authoritative. The native ABI uses
a three-state enum whose zero value is `hijack`, so zero-initialized control maps
preserve the default without an invalid boolean combination.

`local` and `shared` compile separate host-address and private-address maps.
Host addresses are exact local `/32` or `/128` entries; an interface's entire
prefix is never inserted. Configured FakeIP ranges are forced into interception
before private-address and destination rule-set bypass; overlap with mandatory
safety ranges is rejected. Shared mode additionally keeps multicast, unspecified,
and the complete loopback ranges as unconditional local safety exceptions when
private bypass is disabled.

## Map inventory and sizing

The exact key/value structs are declared in `common/ebpf/*_abi.go` and mirrored
byte-for-byte in `native/abi.h` and the generated object metadata. The principal
maps are:

| Map family | Kind | Default bound | Allocation policy |
|------------|------|---------------|-------------------|
| UID include/exclude | LPM trie | normalized range count | Pre-sized policy map, replaced atomically. |
| Destination bypass | LPM trie | configured rule count | Updated on rule-set changes; no packet-path iteration. |
| Local host/private | Hash | 4096 per address family | `BPF_F_NO_PREALLOC`; buckets still scale with `max_entries`. |
| Local TCP redirect | LRU hash | bounded redirect capacity | Delete on accept/close; eviction is the final guard for abandoned connects. |
| Local UDP redirect/token/peer | LRU hash | bounded UDP capacity | Cookie/recovery state; release hook is preferred and userspace recovery validates both directions. |
| Shared flow by original/token | Hash | configured shared capacity | Two authoritative directions and generation checks. |
| Shared source/MAC | LPM/Hash | sized from configured inputs | Prepared only when shared interfaces are active. |
| Fragment/rewrite scratch | LRU/array | small fixed bound | Eviction is acceptable; never authoritative flow state. |

On kernels which accept `BPF_F_NO_COMMON_LRU`, the shared bypass-flow and
fragment caches use per-CPU LRU eviction lists to reduce global LRU lock
contention. A transient map-creation probe selects this mode; ordinary LRU is
the complete fallback. Authoritative original/token maps and socket-assignment
metadata never use this flag. Runtime status exposes the selected mode as
`non_common_lru`.

`NO_PREALLOC` makes hash elements grow on demand but does not make the bucket
array dynamic. Therefore increasing `max_entries` is a real kernel memory
decision even when a map is empty. Capacity changes should be justified with a
pressure benchmark and an estimate of bucket plus value memory. Never use an
LRU map for one side of an authoritative pair without an explicit generation or
recovery protocol: independent eviction can otherwise create a redirect that
cannot be resolved.

Map values are intentionally fixed-size and allocation-free on the packet path.
Changing a struct field order, width, alignment, or map pinning/type is an ABI
change, even when Go still compiles. Regenerate both endian objects and run the
manifest/check target after every native change.

## Capability-driven compatibility

`kernel_probe.go` performs feature probes by attempting the relevant map,
program, helper, link, or batch operation and then closes the temporary object.
Kernel version strings are informational only. The loader chooses, in order:

1. BPF link attachment, then legacy `BPF_PROG_ATTACH`.
2. TCX, then clsact/netlink TC attachment.
3. Batch lookup/update/delete, then bounded one-entry syscalls.
4. Socket-release cleanup, then LRU plus userspace janitor recovery.
5. Native IPv6 sections, then IPv4-only sections when the probe or address set
   says IPv6 is unavailable.
6. Per-CPU eviction lists for disposable shared LRU caches, then common LRU.

Every fallback must remain functional on Linux 4.19 where the selected feature
exists. Do not gate a path solely on `uname -r`, and do not make a probe attach
to a production cgroup or interface. New native instructions must stay within
the v1 ISA and the 4096-instruction verifier budget used by the oldest target.

## Maintenance and performance rules

The packet programs must remain bounded, branch-conscious, and free of loops,
allocations, timers, kfuncs, dynptrs, BTF/CO-RE assumptions, or global mutable
state. A new policy check belongs in a map lookup or a compact helper, not in a
periodic userspace scan. Cold-path batch APIs are allowed for maintenance and
rule updates; data-path lookups must continue using typed raw syscalls.

Release builds keep only correctness maintenance and lightweight counters.
Full map occupancy walks, per-task timing, and `BPF_STATS_RUN_TIME` belong to
`ebpf_debug`; they must never be enabled merely because the log level is
`debug`. Go pprof is exposed through sing-box's shared
`experimental.debug.listen` endpoint and is useful for userspace CPU/heap
hotspots, while BPF runtime stats measure kernel program cost. Neither should be
enabled in throughput baselines without recording the overhead.

When changing a janitor interval, map capacity, or fallback threshold, record
the expected short-connection and UDP-churn effect. Validate with both a
steady-state test and a network-change/restart test; a map that is “usually
empty” can still consume bucket memory or retain stale generations during a
connectivity transition.

## Handoff checklist for maintainers and AI agents

Before modifying this directory:

1. Read the user-facing inbound document and the relevant tests, then identify
   whether the change is policy, data path, lifecycle, compatibility, or
   diagnostics.
2. Preserve the Go/C ABI, generated object manifest, old-kernel fallback, and
   allocation-free hot path unless the change explicitly updates all of them.
3. Add a focused unit or privileged integration test for map lifecycle and
   network churn. Keep debug-only observability behind `ebpf_debug`.
4. Run `make -C common/ebpf check` and the focused Go tests. For native changes,
   verify both endian objects and inspect the instruction count for the Linux
   4.19 target.
5. Review the final diff for unrelated sing-box changes. This backend should
   not change behavior outside eBPF inbound integration points.

Do not remove a fallback, raise a map bound, or alter a default merely to make a
new kernel test pass. Document the capability being probed, the minimum
semantic guarantee, and the measured memory/CPU trade-off in the same change.

## Credits

The native interception implementation is based on
[Asterisk4Magisk/bpf2socks](https://github.com/Asterisk4Magisk/bpf2socks) and is
adapted for direct integration as a sing-box inbound without a SOCKS bridge.
The derived native source remains available under GPL-3.0; see
[`native/LICENSE`](native/LICENSE).
