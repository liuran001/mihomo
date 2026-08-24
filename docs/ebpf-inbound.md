# eBPF transparent inbound

This document covers the Linux/Android cgroup eBPF transparent inbound and the
optional shared-network TC data path. The feature is enabled only in builds
with cgo and the `with_ebpf` build tag on Linux or Android. Other platforms
compile with a stub that returns an explicit unsupported error.

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

The eBPF build requires a Linux build host (or Android NDK for Android) and
clang for the BPF object:

```bash
make ebpf_generate
CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -tags "with_gvisor with_ebpf" -o mihomo-ebpf .
```

Android ARM64 uses the NDK clang as `CC`; see
`.github/workflows/androidarm64.yml` and `.github/workflows/build-ebpf.yml`.

## Configuration

Add an `ebpf` listener to the `listeners` section:

```yaml
listeners:
  - name: ebpf-inbound
    type: ebpf
    network: [tcp, udp]
    cgroup-path: /sys/fs/cgroup
    redirect-address:
      - 127.128.0.0/9
    dns-mode: hijack
    cgroup-ipv6-mode: auto
    udp-timeout: 300
    map-capacity:
      tcp-redirect: 65536
      udp-redirect: 65536
      socket-bypass: 65536
    bypass-rule-set: []
    include-uid: []
    exclude-uid: []
    shared-network:
      enabled: false
```

Field behavior:

- `network`: `tcp`, `udp`, or both. Defaults to both when omitted.
- `cgroup-path`: absolute cgroup v2 directory. Empty means auto-detect.
- `redirect-address`: at most one IPv4 prefix and one IPv6 prefix. The default
  is IPv4 `127.128.0.0/9` with IPv6 disabled.
- `dns-mode`: `hijack` or `off`. Defaults to `hijack`.
- `cgroup-ipv6-mode`: `always`, `auto`, or `off`. Defaults to `always`.
- `udp-timeout`: UDP NAT mapping timeout in seconds. Defaults to 300.
- `map-capacity`: maximum entries for the redirect and bypass maps. Values are
  capped at `1 << 20`; zero uses the built-in default.
- `bypass-rule-set`: rule provider tags whose CIDRs populate the bypass map.
- `include-uid`, `include-uid-range`, `exclude-uid`, `exclude-uid-range`:
  UID-based interception policy. Ranges use `start:end` syntax.
- Android only: `include-android-user`, `include-package`, `exclude-package`.
- `shared-network`: enables hotspot/TC forwarding on the named interfaces.

## IPv4 and IPv6 behavior

The internal TCP and UDP listeners are created with explicit address families
(`tcp4`, `tcp6`, `udp4`, `udp6`) and IPv6 listeners set `IPV6_V6ONLY`. This
avoids implicit dual-stack listener behavior and keeps the BPF lookup keys
deterministic. With `cgroup-ipv6-mode: auto`, IPv6 interception is enabled only
when the host appears to provide IPv6 connectivity; the probe result is logged.

The redirect address must not overlap routable local traffic. For IPv4 the
default `127.128.0.0/9` is a loopback range that is not normally used by
clients. For IPv6 supply a ULA or local-use prefix such as
`fd00:ebpf::/64`; the IPv6 mode must not be `off` when an IPv6 prefix is
configured.

## Android differences

Android uses the same cgroup v2 mechanism but the effective cgroup hierarchy
and permission model differ by vendor. The auto-detected cgroup path can be
overridden with `cgroup-path`. Package policy is resolved to Android UIDs and
`include-android-user` maps a user ID to its per-user UID range. The DNS
tethering UID is always excluded.

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

The `privileged-integration` job in `.github/workflows/build-ebpf.yml` probes
the runner with `common/ebpf/check-kernel.sh` and marks the job SKIP when
required BPF/cgroup features cannot be proven. GitHub-hosted runners are
expected to SKIP because the probe cannot distinguish cgroup sockaddr attach
subtypes without a real load. Run the real suite on a self-hosted Linux
runner with cgroup v2, root access, and bpftool:

```bash
bash common/ebpf/check-kernel.sh --mode all --cgroup /sys/fs/cgroup
SING_BOX_EBPF_INTEGRATION=1 CGO_ENABLED=1 go test -count=1 \
  -tags "with_gvisor with_ebpf ebpf_integration" \
  ./common/ebpf/... -run Integration
```

The suite creates temporary cgroups, loads programs, attaches traffic
helpers, and cleans up all state on completion. After stopping mihomo on the
same host, verify `bpftool prog show`, `bpftool map show`, and
`bpftool link show` report no leftover objects.

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

Two mechanisms keep the bypass meaningful, split by set size:

| Bypass source | Mechanism | Where |
|---------------|-----------|-------|
| `bypass-private-address` | the fixed private prefixes are published for route exclusion, so `auto-route` never claims them | `listener/sing_tun` reads `resolver.EBPFRouteExcludePrefixes` while building `tun.Options` |
| `bypass-rule-set` | the destination is connected directly on arrival instead of being matched against the rules (`bypass-tun-direct`, default true) | `tunnel.resolveMetadata` consults `resolver.EBPFBypassedDirect` for `C.TUN` flows |

A rule set cannot use route exclusion: it resolves after the TUN device already
baked its route set, and excluding a country-sized IP set would install tens of
thousands of routes. The fake-ip ranges and the TUN device's own addresses are
always kept on the routes.

With `bypass-tun-direct: false` the overlap is only reported, not handled. Both
listeners report it, because either one can be the second to start.

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
intercepted even when it would otherwise be bypassed -- the address only regains
meaning once the tunnel maps it back to its domain. This matters when the
configured range sits inside a bypassed range, as `fake-ip-range: 100.64.0.0/10`
does. The ranges follow `dns.fake-ip-range`/`fake-ip-range6` at runtime, so a
config reload that changes them reaches a running inbound.
