# eBPF transparent inbound

This document covers the Linux/Android eBPF transparent inbound: a local role
that intercepts the host's own sockets (cgroup socket-address programs by
default, or a TC egress program on the default interface) and a shared role
that intercepts traffic forwarded from downstream interfaces (TC packet rewrite
by default, or socket assignment). The feature is enabled only in builds with
the `with_ebpf` build tag on Linux or Android; cgo is not required because the
BPF objects are shipped pre-compiled. Other platforms compile with a stub that
returns an explicit unsupported error.

## Supported environments

- Operating systems: Linux, Android.
- Architectures built by CI: linux/amd64, linux/arm64, android/arm64.
- Make targets: `linux-amd64-ebpf`, `linux-arm64-ebpf`, `android-arm64-ebpf`, `all-ebpf`.
- Kernel: cgroup v2 with BPF support. The loader does not assume a fixed
  minimum kernel version; run the capability probe below on the target device.
- cgroup mode: v2 only. cgroup v1 is rejected with a clear error.

Required kernel features are detected at runtime:

- cgroup/sockaddr program types: connect4/connect6, sendmsg4/6, recvmsg4/6.
- BPF maps: hash, lpm_trie, array, and prog_array as used by the loader.
- Optional: cgroup inet sock release attach type and
  `BPF_MAP_LOOKUP_AND_DELETE_ELEM`. When either is missing the loader uses a
  compatibility path automatically.

## Capabilities and kernel configuration

The process must be privileged or hold the following effective capabilities:

- `CAP_BPF` or `CAP_SYS_ADMIN` for BPF syscalls and cgroup attach.
- `CAP_NET_ADMIN` for shared-network TC qdisc attachment and route/sysctl setup.
- `CAP_NET_RAW` for raw socket operations used by the data path.
- The ability to raise `RLIMIT_MEMLOCK` enough for configured BPF maps.

The kernel needs at least `CONFIG_BPF`, `CONFIG_BPF_SYSCALL`, and
`CONFIG_CGROUP_BPF`. `CONFIG_BPF_JIT` is strongly recommended for throughput.
The shared-network path additionally needs `CONFIG_NET_CLS_BPF`.

## Capability probe

Run the bundled probe before starting mihomo:

```bash
bash common/ebpf/check-kernel.sh --mode all
```

For a specific cgroup path and a shared-network downstream interface:

```bash
bash common/ebpf/check-kernel.sh --mode all --cgroup /sys/fs/cgroup --interface wlan0
```

The probe does not attach programs or change routes. With `bpftool` installed
it performs transient feature probes; without `bpftool` it reports
`UNKNOWN` for features that cannot be proven safely.

## Build

The repository ships the BPF objects. Building the core does not require
clang, the NDK, or cgo:

```bash
CGO_ENABLED=0 go build -tags "with_gvisor with_ebpf" -o mihomo-ebpf .
CGO_ENABLED=0 GOOS=android GOARCH=arm64 go build -tags "with_gvisor with_ebpf" -o mihomo-android-arm64 .
```

Only regenerating the BPF objects requires the pinned Android NDK r29
Clang 21 toolchain:

```bash
make -C common/ebpf generate ANDROID_NDK_HOME=/path/to/android-ndk-r29
make -C common/ebpf check ANDROID_NDK_HOME=/path/to/android-ndk-r29
```

See [validation results](ebpf-validation.md) for the tested kernels and limits.

## Configuration

Add an `ebpf` listener to the `listeners` section. `mode` selects which roles
run; each role then carries its own policy block:

```yaml
listeners:
  - name: ebpf-inbound
    type: ebpf
    mode: hybrid              # local | shared | hybrid, default local
    network: [tcp, udp]
    udp-timeout: 300          # seconds
    tc-priority: 1            # TC filter priority; 1 also enables TCX
    bypass-rule-set: []       # rule providers (behavior: ipcidr) bypassed by every role
    bypass-tun-direct: true   # see "Coexisting with TUN"
    fakeip-icmp: off          # off (default) | reply, see "FakeIP"
    local:
      data-plane: cgroup      # cgroup (default) | tc
      cgroup-path: ""         # cgroup v2 directory, empty = auto-detect (cgroup only)
      dns-mode: hijack        # hijack (default) | respect_policy | off
      ipv6: true
      bypass-private-address: true
      bypass-rule-set: []     # bypassed by the local role only, on top of the list above
      bypass-exclude: []      # CIDRs forced through interception, e.g. [100.64.0.0/10]
      include-uid: []
      include-uid-range: []   # "start:end"
      exclude-uid: []
      exclude-uid-range: []
      include-android-user: []  # Android only
      include-package: []       # Android only
      exclude-package: []       # Android only
      bypass-port: []
      bypass-port-range: []   # "start:end"
    shared:
      data-plane: packet_rewrite  # packet_rewrite (default) | socket_assign
      dns-mode: hijack
      interface: [br0]        # downstream interfaces, required when shared runs
      allow-default-upstream: false # keep a single-armed interface (default upstream AND downstream) attached
      ipv6: true
      bypass-private-address: true
      bypass-rule-set: []     # bypassed by the shared role only, on top of the list above
      bypass-exclude: []      # independent of local exclusions and DNS fake-IP ranges
      include-source-cidr: []
      exclude-source-cidr: []
      include-mac-address: []
      exclude-mac-address: []
      bypass-port: []
      bypass-port-range: []
```

The same listener can also be written the way sing-box and the upstream eBPF
listener spell it, with per-role switches and rule sets and no `mode`:

```yaml
listeners:
  - name: ebpf-inbound
    type: ebpf
    local:
      enable: true
      bypass-rule-set: [geoip-cn]
    shared:
      enable: true
      interface: [wlan0]
```

Field behavior:

- `mode`: `local` intercepts sockets created on this host, `shared` intercepts
  traffic forwarded from the `shared.interface` list, `hybrid` runs both. The
  explicit `local.enable` / `shared.enable` booleans are accepted instead of
  `mode`, not together with it: set either, and a role left unset is off; set
  neither, and only local runs. `local.enabled` / `shared.enabled` is an older
  spelling of the same key. When a scope is disabled, its settings other than
  the enablement selector are ignored, including during rule-set updates.
- `network`: `tcp`, `udp`, or both. Defaults to both when omitted.
- `udp-timeout`: UDP session timeout in seconds. Defaults to 300, floor 5.
- `tc-priority`: priority of the TC filters. With the default `1` the inbound
  attaches through TCX on kernels that support it and falls back to clsact
  filters otherwise; any other value always uses clsact filters.
- `local.bypass-exclude` / `shared.bypass-exclude`: destination CIDRs that force
  interception ahead of configurable DNS, UID/source, port, private-address
  and rule-set bypasses. The feature does not choose an outbound; normal mihomo
  rules still decide where intercepted traffic goes. Protocol/address-family
  enablement, self-socket and mandatory safety guards still apply. Each enabled
  role has independent IPv4/IPv6 LPM tables (up to 4096 normalized entries per
  family), so multiple CIDRs and DNS fake-IP ranges can coexist. IPv4-mapped
  IPv6 prefixes at `/96` or longer are normalized to IPv4. Disabled scopes
  ignore this option. Changing the list rebuilds the inbound; fake-IP range
  updates continue to apply in place. Exclusions from either enabled role are
  removed from this inbound's global DNS/TUN bypass publication to avoid sending
  forced destinations directly when traffic crosses TUN.
- `bypass-rule-set`: rule provider tags whose CIDRs populate the bypass LPM
  maps. Only `behavior: ipcidr` providers contribute; others are skipped. The
  top-level list is bypassed by every role. `local.bypass-rule-set` and
  `shared.bypass-rule-set` add rule sets for one role, so a phone can, say,
  keep its own domestic traffic off the proxy while its hotspot clients go
  through it. While both roles bypass the same rule sets they share one set of
  kernel tables. Once they differ, each data plane gets its own: the shared
  packet-rewrite plane stops borrowing the cgroup's table, and with
  `local.data-plane: tc` and `shared.data-plane: socket_assign` the shared TC
  path reads a table of its own. The DNS fake-ip exemption and the TUN
  coexistence policy use every role's rule sets together.
- `bypass-tun-direct`: whether a destination this inbound bypasses is
  connected directly when a TUN listener claims it anyway. Defaults to true.
- `fakeip-icmp`: `off` (default) leaves ICMP alone, `reply` answers ICMP Echo
  Requests addressed to a fake-ip address in the kernel. See "FakeIP" for what
  it costs and which data planes can carry it.
- `local.data-plane`: `cgroup` attaches connect/sendmsg/recvmsg programs to the
  cgroup and rewrites destinations to an internal redirect address on
  loopback. `tc` attaches an egress program to the default interface and
  delivers selected packets to the internal listeners over a veth pair with
  `bpf_sk_assign` (introduced in upstream Linux 5.7) and policy routing.
  Availability is checked at runtime.
- `local.cgroup-path`: absolute cgroup v2 directory for the cgroup data plane.
  Empty means auto-detect.
- `dns-mode` (per role): `hijack` intercepts every port-53 flow before any
  bypass policy, `respect_policy` applies the UID/source policy first, `off`
  leaves DNS alone. `respect_bypass` is accepted as an alias of
  `respect_policy`.
- `ipv6` (per role): whether IPv6 flows are intercepted. Defaults to true.
- `bypass-private-address` (per role): let private destinations (10/8,
  172.16/12, 192.168/16, 100.64/10, 169.254/16, fc00::/7, fe80::/10) past the
  redirect. Defaults to true. Turn it off on a gateway that should see LAN
  traffic in its connection list.
- `include-uid`, `include-uid-range`, `exclude-uid`, `exclude-uid-range`:
  UID-based interception policy for the local role. Ranges use `start:end`.
- Android only: `include-android-user`, `include-package`, `exclude-package`.
- `bypass-port`, `bypass-port-range` (per role): destination ports that are
  never intercepted.
- `shared.data-plane`: `packet_rewrite` rewrites the destination at ingress
  and restores it at egress and needs Ethernet framing; `socket_assign`
  preserves the original tuple and assigns packets to the listener with
  `bpf_sk_assign` (upstream Linux 5.7+, subject to runtime helper support)
  plus policy routing, and also works on raw-IP links.
- `shared.interface`: downstream interfaces. An interface that is currently
  the default upstream is skipped until it returns to a downstream role.
- `shared.allow-default-upstream`: keep `shared.interface` entries attached
  even while one of them is the default upstream. Meant for the single-armed
  gateway whose only NIC is downstream and upstream at once; with it a listed
  interface is never skipped, so a later WAN appearing on the same name keeps
  being intercepted until the operator says otherwise. Changes to this key
  rebuild the inbound.
- `include-source-cidr`, `exclude-source-cidr`, `include-mac-address`,
  `exclude-mac-address`: shared source policy. MAC policy needs Ethernet
  framing.

Keys from the previous configuration surface are still accepted and mapped to
the fields above: a top-level `dns-mode` or `bypass-private-address` applies
to every enabled role that does not set its own; `local.ipv6-mode` and
`shared.ipv6-mode` (`always`/`off`, and `auto` for local, which now means
enabled) map to `ipv6`; `local.state-capacity` and `shared.state-capacity`
size the kernel state maps; `shared.advanced.tc-priority` becomes
`tc-priority`, and known `shared.advanced.data-plane` values map to
`shared.data-plane`. `tcp-splice` and `shared.advanced.routing-mark` /
`routing-table` no longer do anything and are reported once at startup.

### What a config reload can change in place

Rebuilding this inbound destroys every kernel map it owns -- the cgroup
redirect table, the shared flow table, the TC assignment map, the UDP recovery
table -- so every established redirect on the host and every tethered client
breaks at once. Three options avoid that and are applied to the running
inbound:

- `udp-timeout`. The kernel compares it against each session's last-seen
  stamp rather than storing a deadline, so a change reaches the sessions that
  already exist, and the userspace sweep re-paces itself on the next round.
- `bypass-rule-set`, including the per-role lists, with two limits. The shared
  role's list must not become empty or stop being empty: the shared
  packet-rewrite backend sizes its bypass flow cache to a single entry when
  nothing is bypassed, and that is fixed when the map is created. And the two
  roles must not move between bypassing the same rule sets and different ones,
  which decides whether they share kernel tables. Crossing either line needs a
  rebuild.
- `bypass-tun-direct`, which only republishes what a TUN listener reads.

Changing anything else in the section -- or changing one of the three
alongside something else -- rebuilds the inbound exactly as before. The split
fails closed: an option added later forces a rebuild until it is explicitly
classified.

Rule-set *contents* never needed a reload at all. The listener resolves its
`bypass-rule-set` tags by name each time it recompiles, so a provider that
refreshes on its own interval reaches the kernel policy without anything else
happening.

## Resource limits

The recent performance changes add no required configuration keys. They reuse
`udp-timeout` to expire idle UDP clients and transparent reply sockets. Each
pass examines at most 1024 clients per table, releasing the ingress/reply
lifecycle lock after batches of at most 32. A resumable cursor continues large
rounds once per second, then returns to the normal idle-sweep interval. Active
destination bindings are not hard-capped. Outstanding packets, DNS work and
replies retain activity.

DNS relays have separate per-inbound budgets, because a TCP relay holds its slot
for the whole connection while a UDP relay holds one for a single datagram: 256
concurrent UDP queries and 128 hijacked TCP connections, of which no single
source may hold more than 8 once the TCP budget is more than half spent. Excess
UDP queries are dropped; excess TCP connections are closed. Both are logged at a
limited rate. Transparent UDP reply
sockets have 16 shards with a limit of 64 live sockets each, including retired
sockets still leased by writers. A full shard with every socket leased rejects
the reply. These limits are internal constants, not YAML options.

## IPv4 and IPv6 behavior

The internal TCP and UDP listeners are created with explicit address families
(`tcp4`, `tcp6`, `udp4`, `udp6`) and IPv6 listeners set `IPV6_V6ONLY`. This
avoids implicit dual-stack listener behavior and keeps the BPF lookup keys
deterministic. `local.ipv6` and `shared.ipv6` decide per role whether IPv6
flows are intercepted at all; both default to on.

The cgroup and packet-rewrite data planes redirect to an internal address the
inbound picks itself: `127.128.0.0/9` (falling back to `127.64.0.0/10`) for
IPv4 and `fd53:696e:672d:626f::/64` (falling back to `fd53:696e:672d:6270::/64`)
for IPv6. A candidate that overlaps a local route, an interface address, or a
fake-ip range is skipped, and the routes the inbound adds for the chosen prefix
are removed again on shutdown.

## Android differences

Android uses the same cgroup v2 mechanism but the effective cgroup hierarchy
and permission model differ by vendor. The auto-detected cgroup path can be
overridden with `cgroup-path`. Package policy is resolved to Android UIDs and
`include-android-user` maps a user ID to its per-user UID range. The DNS
tethering UID is always excluded.

From Android 15, netd attaches its own connect, sendmsg and recvmsg programs to
the cgroup v2 root exclusively, and nothing can attach beside them or below
them. The cgroup data plane then takes those hooks over, logs which ones, and
hands them back to netd's programs when the inbound stops. If mihomo is killed
instead, its programs stay attached until it starts again and removes them, and
netd's come back only when netd attaches again, normally at the next boot.
`local.data-plane: tc` leaves the hooks alone.

SELinux must permit BPF map/program creation, cgroup attach, and socket
operations for the mihomo domain. On restricted Android builds the feature is
usually only usable from a root or Magisk-provided service context. Run
`common/ebpf/check-kernel.sh` on the device before debugging startup failures.

## Containers

A container running the eBPF inbound needs:

- `/sys/fs/cgroup` mounted read-write and containing the target cgroup v2 hierarchy.
- `CAP_BPF` (or `CAP_SYS_ADMIN`) and `CAP_NET_ADMIN`.
- `RLIMIT_MEMLOCK` not blocked by the container runtime.
- No seccomp profile that filters `bpf`, `setsockopt`, `netlink`, or `tc`.

For shared-network TC mode the container also needs the downstream interface
inside its network namespace and the `net.ipv4.conf.<iface>.route_localnet`
sysctl set on that interface.

## Diagnostics

Start with the capability probe and the startup log line that lists the cgroup,
listener port, DNS mode, programs, and bypass CIDR counts.

- Verifier failure: the log includes the program name, errno, and verifier log.
  Check kernel config/helpers, map capacity, and `RLIMIT_MEMLOCK`.
- Permission denied: verify root or `CAP_BPF`/`CAP_SYS_ADMIN`/`CAP_NET_ADMIN`,
  seccomp, Android SELinux, and container device policy.
- Attach failed: verify the configured path is a cgroup v2 mount, is writable,
  and is not already attached by another instance.
- Port conflict: the internal listener set binds an ephemeral port shared
  across the enabled protocol/family listeners. Startup rolls back all
  listeners if any bind fails; check `ss -lntup` for the reported port.
- `cgroup_path` errors: the path must be absolute and inside the cgroup2 mount.

## Shutdown and cleanup

`Close()` is idempotent. It stops UDP sweeps, detaches BPF links, closes map and
program file descriptors, closes the internal listeners, removes shared-network
TC attachments and local routes, and unregisters the socket protect function.
No BPF objects are pinned by the implementation, so stopping mihomo should
leave no persistent program or map names. Verify with:

```bash
bpftool prog show
bpftool map show
bpftool link show
```

If an old process crashed, restart mihomo; it creates new file descriptors and
does not depend on stale pinned objects.

## Privileged integration tests

The `privileged-integration` job in `.github/workflows/ebpf.yml` probes
the runner with `common/ebpf/check-kernel.sh` and marks the job SKIP when
required BPF/cgroup features cannot be proven. GitHub-hosted runners are
expected to SKIP because the probe cannot distinguish cgroup sockaddr attach
subtypes without a real load. Run the real suite on a self-hosted Linux
runner with cgroup v2, root access, and bpftool:

```bash
bash common/ebpf/check-kernel.sh --mode all --cgroup /sys/fs/cgroup
SING_BOX_EBPF_INTEGRATION=1 CGO_ENABLED=0 go test -count=1 \
  -tags "with_gvisor with_ebpf ebpf_integration" \
  ./common/ebpf/... -run Integration
```

The suite creates temporary cgroups, loads programs, attaches traffic
helpers, and cleans up all state on completion. After stopping mihomo on the
same host, verify `bpftool prog show`, `bpftool map show`, and
`bpftool link show` report no leftover objects.

## Keeping the generated objects honest

The kernel programs are compiled ahead of time and their objects are committed
under `common/ebpf/internal/bpfgen`. Nothing that consumes them recompiles
them: `go test -tags with_ebpf` and the release `go build` both embed whatever
is in the tree. A `.bpf.c` edited without a regenerate therefore produces a
binary running the previous kernel program while the source says otherwise.

`make ebpf_check` is what catches that. It regenerates into a scratch
directory and diffs, including `manifest.txt`, which records the exact Clang
build the committed objects came from -- so a toolchain that drifts fails
loudly rather than silently producing different programs. The `generate-check`
job in `.github/workflows/ebpf.yml` runs it whenever `common/ebpf/**` changes.

Regenerating locally needs that same toolchain:

```bash
ANDROID_NDK_HOME=/path/to/android-ndk-r29 make ebpf_generate
```

## Repository automation prerequisites

The sync workflow creates PRs and failure Issues. The target repository must
have:

- Issues enabled, otherwise the failure notification step exits with an
  actionable error instead of creating an Issue.
- GitHub Actions permitted to create and approve pull requests.
- The sync workflow present on the repository default branch so the
  `schedule` trigger is active.

## Relationship with TUN, TProxy, and Redir

The eBPF inbound intercepts sockets inside the selected cgroup; it is not a
full TUN device and does not route all host traffic by itself. The shared-network
mode uses TC on named downstream interfaces and can be used for hotspot
forwarding while the cgroup path handles local apps.

### Coexisting with TUN

A bypass decision and a route exclusion live at different layers. Bypassing a
destination here only means the socket keeps its original destination; the packet
still follows the routing table, and TUN `auto-route` points that table at the
TUN device. A bypassed destination TUN claims is therefore not direct: it enters
the TUN stack and is routed by the rule engine, which black-holes it whenever no
rule sends it direct and the matched proxy cannot reach the address.

`auto-route` is not the whole story on Linux: sing-tun gates only the IPv4 route
set on it, and builds the IPv6 route set for any device that has IPv6 addresses,
which `setRoute` then installs along with a matching `ip rule`. A device
configured with `auto-route: false` therefore still claims IPv6 destinations, and
the overlap report covers them.

Two mechanisms keep the bypass meaningful, split by set size:

| Bypass source | Mechanism | Where |
|---------------|-----------|-------|
| `bypass-private-address` | the fixed private prefixes are published for route exclusion, so `auto-route` never claims them | `listener/sing_tun` reads `resolver.EBPFRouteExcludePrefixes` while building `tun.Options` |
| `bypass-rule-set` | the destination is connected directly on arrival instead of being matched against the rules (`bypass-tun-direct`, default true) | `tunnel.resolveMetadata` consults `resolver.EBPFBypassedDirect` for `C.TUN` flows in rule mode |

A rule set cannot use route exclusion: it resolves after the TUN device already
baked its route set, and excluding a country-sized IP set would install tens of
thousands of routes. The fake-ip ranges and the TUN device's own addresses are
always kept on the routes.

With `bypass-tun-direct: false` the overlap is only reported, not handled. Both
listeners report it, because either one can be the second to start.

The exclusion is baked into the device's route set at build time, so a TUN
device that already exists has to be rebuilt when it changes -- an eBPF inbound
starting, stopping, or changing its bypass policy, none of which the `tun`
section describes. Both entry points handle it: `ReCreateTun` compares the
exclusion alongside the config, and a TUN declared under `listeners:` is
restarted by `rebuildStaleListeners`, which runs after every inbound has been
started. That ordering matters on startup as much as on reload, because the
patch loop walks a map and can otherwise build the device before the eBPF
inbound has published anything at all. A restart logs:

```
Listener tun-in restarting: the eBPF route exclusion changed under it
```

Direct handling applies in rule mode only. Global and direct mode are standing
instructions about where every flow goes, so the bypass leaves them to decide --
under global mode the connection would otherwise be dialled through `DIRECT`
while the log still named `GLOBAL`. Route exclusion is unaffected: it keeps the
destinations off the TUN device in every mode.

The gate governs this one handler, not the feature. Traffic that takes the eBPF
fast path never reaches the tunnel to be gated, so the kernel keeps bypassing it
under global mode, and the DNS middleware still answers a bypassed destination
with its real address rather than a fake one in every mode. What the gate buys is
that a flow arriving through TUN is routed by the mode the user selected.

Several eBPF inbounds can run at once -- the listener parser only rejects
duplicate names -- so the published state is a union keyed by publishing
inbound, and `bypass-tun-direct` stays per inbound: only the prefixes of the
inbounds that asked for it are connected directly. Closing one inbound removes
only its own contribution, which matters because an inbound whose start fails
closes itself.

Beyond that, avoid attaching multiple transparent inbound mechanisms to the same
cgroup or interface unless you intentionally split traffic with UID, CIDR, and
`bypass-rule-set` policies. In particular do not enable shared mode and TUN
`auto-redirect` on the same interface: TC ingress rewrites the destination
before netfilter sees the packet. `strict-route` is best left off, since it
reorders the policy routing the redirect address depends on.

### FakeIP

The fake-ip ranges are pushed into the kernel policy so a fake destination is
intercepted even when it would otherwise be bypassed, UID policy included --
the address only regains meaning once the tunnel maps it back to its domain.
A bypassed app still gets fake-ip answers wherever its lookups go through a
resolver that is not bypassed, as they do through netd on Android. This also
matters when the configured range sits inside a bypassed range, as
`fake-ip-range: 100.64.0.0/10` does. The ranges follow `dns.fake-ip-range`/`fake-ip-range6` at runtime, so a
config reload that changes them reaches a running inbound.

A fake-ip address answers nothing on its own, so `ping` against a fake-ip
destination times out even while the same domain is proxied fine. With
`fakeip-icmp: reply` a separate eBPF object is attached beside the interception
programs and turns an ICMP Echo Request addressed to a fake-ip address into an
Echo Reply in the kernel, without the packet ever reaching the core. Nothing
about reachability is being measured: the reply says only that the address is a
fake-ip one, not that the domain behind it resolves or that its proxy is up.

The reply programs run on a TC hook, so `reply` is rejected unless a fake-ip
range is configured and at least one attachment can carry them --
`local.data-plane: tc`, or shared interception under either `shared.data-plane`.
In particular `local.data-plane: cgroup` with no shared interception cannot:
its `connect()`/`sendmsg()` hooks never see ICMP.

### UDP recovery lifecycle

Connected UDP recovery uses a reverse token index instead of scanning socket
cookies. Optional socket-release ring-buffer events schedule recovery expiry;
unsupported maps/helpers or notification overflow retain the bounded deadline
sweeper. Both paths follow the current `udp-timeout`. Recovery payloads are keyed
by socket cookie and monotonic release time, so delayed cleanup cannot delete a
new record under a reused token. Token indexes remain bounded LRUs.

TC UDP cleanup marks the observed assignment generation retired. A later packet
rebuilds its metadata; cleanup never compare/deletes a concurrently replaced
assignment. Assignment and retirement storage remain bounded LRUs. Startup logs
show the actual UDP release/cleanup path and fallback reason, and the existing
30-second datapath report includes `cgroup_udp_release_drops` for kernel-ring or
userspace-queue overflow.
