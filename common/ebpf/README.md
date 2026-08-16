# eBPF inbound backend

This package implements the native eBPF backend used by the sing-box eBPF
inbound.

## Package layout

The Go implementation is grouped by data path and responsibility:

- `cgroup_abi.go`, `cgroup_policy.go`, and `cgroup_mount.go` contain portable
  ABI, policy compilation, and cgroup discovery logic.
- `cgroup_backend.go`, `cgroup_socket.go`, and `cgroup_policy_runtime.go`
  manage the cgroup runtime, socket redirect
  maps, and live policy maps.
- `shared_network_abi.go` and `shared_network_policy.go` contain the portable
  TC map ABI and host-address policy compilation.
- `shared_network_backend.go`, `shared_network_flow.go`, and
  `shared_network_policy_runtime.go` manage the TC runtime, flow maps, and live
  host-address maps.
- `generate.go` drives `bpf2go`; `internal/bpfgen` isolates the tracked objects,
  generated bindings, and their provenance manifest from handwritten code.
- `loader.go` uses `github.com/cilium/ebpf` to derive maps from that spec, load
  selected programs, query stale cgroup programs, and manage attachments.
- `backend_runtime.go` uses a targeted cilium feature probe plus on-demand
  memlock and shared load-error handling. It intentionally avoids the
  `rlimit` package's process-init probe on vendor Android kernels.
- `map.go` contains the small BPF map syscall boundary shared by both data
  paths. The runtime does not require cgo.

## Native layout

- `native/cgroup.bpf.c` and `native/shared_network.bpf.c` are compiled to the
  embedded cgroup and TC ingress/egress objects.
- `native/bpf_compat.h` keeps the non-CO-RE map ABI explicit, while
  `native/shared_network_packet.h` contains packet layouts and bounded parser
  constants shared by the TC classifier.
- `native/shared_network_policy.h`, `native/shared_network_flow.h`, and
  `native/shared_network_rewrite.h` split policy, state, and checksum/rewrite
  helpers while remaining part of one verifier-friendly translation unit.
- `native/abi.h` contains the cgroup map ABI, `native/shared_network.h` contains
  the TC map ABI, and `native/private_address.h` is shared data-plane policy.

There is no userspace C loader or cgo runtime boundary. The BPF C sources are
the data plane; the Go runtime owns map and program handles through
`cilium/ebpf`.

## Embedded eBPF objects

`internal/bpfgen/*_bpf{el,eb}.o`, together with their Go bindings, are generated
by `bpf2go` and tracked. They are architecture-neutral
BPF bytecode, not Android or Linux native objects. Shipping both byte orders
also avoids silently using a little-endian object on a big-endian OpenWrt
target. Their GPL sources are `native/cgroup.bpf.c` and
`native/shared_network.bpf.c`.

Normal builds consume the committed output and do not invoke a C compiler:

```sh
CGO_ENABLED=0 TAGS=with_ebpf make build
```

Regeneration after a BPF C change uses the pinned Android NDK r29 Clang 21
toolchain and its Linux UAPI sysroot. It intentionally does not read host
`/usr/local/include` or `/usr/include`: generation clears include-path
environment variables, uses `-nostdinc`, and admits only Clang resource
headers, `native`, and the pinned NDK sysroot.
The NDK arm64 UAPI `asm` directory supplies architecture typedefs while
bpf2go still emits architecture-neutral little- and big-endian BPF objects.

```sh
ANDROID_NDK_HOME=/usr/share/android-ndk-r29 make ebpf_generate
```

`make ebpf_check` verifies that the committed output and
`internal/bpfgen/manifest.txt` are current. The manifest records the generator,
targets, normalized compiler flags, compiler, C/header hashes, and object
hashes. Generation
targets the baseline BPF v1 instruction set and strips BTF/CO-RE metadata, so
runtime loading does not depend on kernel BTF and remains suitable for the
Linux 5.10 compatibility baseline.

When native IPv6 interception is disabled, the cgroup loader selects smaller
IPv4-mapped `connect6`, `sendmsg6`, and `recvmsg6` sections. These preserve
IPv4 traffic from dual-stack applications without loading the unused native
IPv6 policy and redirect path. Dual-stack configurations continue to select
the complete IPv6 sections.

## Compatibility boundary

Linux 5.10 is the mandatory kernel baseline. The implementation therefore
keeps cgroup sock-address hooks for local traffic and clsact TC filters for
shared-network traffic. It does not require kernel BTF, CO-RE, TCX, BPF timers,
dynptrs, kfuncs, or pinned bpffs objects. Newer attachment mechanisms may be
added only as optional fast paths with the current cgroup and TC mechanisms as
fallbacks.

Android arm64 GKI and Linux amd64/arm64 are the production validation targets.
The generated objects also cover both byte orders, and other 64-bit OpenWrt
architectures may work, but cilium/ebpf treats architectures other than amd64
and arm64 as best effort. A successful cross-build is not a substitute for a
verifier, attach/detach, and traffic test on the target kernel. 32-bit targets
are not a production compatibility promise.

The hot original-destination and policy map operations retain a narrow direct
syscall boundary. This avoids reflection or serialization on every accepted
flow while cilium/ebpf owns ELF parsing, map/program construction, verifier
logs, object lifetime, feature queries, and attachment helpers. Any migration
of the hot operations to generic map methods must be allocation-benchmarked
first.

## Testing

Run the focused Linux tests and the race detector:

```sh
CGO_ENABLED=0 go test -tags with_ebpf ./common/ebpf ./protocol/ebpf ./include
CGO_ENABLED=1 go test -race -tags with_ebpf ./common/ebpf ./protocol/ebpf ./include
```

An Android cross-build validates build tags, syscall types, and the embedded
object ABI without requiring an NDK:

```sh
GOOS=android GOARCH=arm64 CGO_ENABLED=0 \
go test -c -tags with_ebpf -o /tmp/sing-box-ebpf-android.test ./protocol/ebpf
```
The complete sing-box tag set may use `CGO_ENABLED=1` and an NDK when other
features require cgo; the eBPF runtime itself is unaffected.

The root integration tests are excluded from normal test builds and require
the `ebpf_integration` build tag. The program-load test creates the maps and
asks the kernel verifier to load the IPv4 and dual-stack program matrix with
TCP, UDP, or both protocols, DNS hijack enabled or disabled, automatic IPv6
availability enabled or disabled, and TGID or socket-cookie self bypass. It
also covers the socket-release program when the kernel supports it and the UDP
LRU fallback otherwise, then closes everything without attaching. The traffic
test creates a temporary child cgroup and verifies IPv4
TCP redirection, original destination and UID recovery, and DNS-priority UDP
redirection through a configured private CIDR bypass. It also passes protected
TCP and UDP sockets into the child cgroup and verifies that socket-cookie self
bypass prevents them from returning to the redirect listeners. The program-load
target cgroup is auto-detected unless `SING_BOX_EBPF_INTEGRATION_CGROUP` is set.
The standalone shared-network load test verifies that the TC backend can create
and populate its own bypass maps without a cgroup backend:

```sh
sudo -E SING_BOX_EBPF_INTEGRATION=1 \
go test -count=1 \
  -run 'Test(CgroupBackend(ProgramLoad|Traffic)|SharedNetwork(SharedMap|Standalone)ProgramLoad)Integration' \
  -tags with_ebpf,ebpf_integration ./common/ebpf
```

The shared-network integration test additionally creates a temporary network
namespace and veth pair. It verifies IPv4 and IPv6 public TCP interception,
a large TCP payload through the TC/GSO path, dual-stack fragmented UDP round
trips, dual-stack DNS capture to the gateway in the default hijack mode, DHCP
bypass, fail-closed behavior at map capacity, reply source restoration, TC
cleanup, local redirect routes, and
`route_localnet` restoration. It requires `ip` and `nc`:

```sh
sudo -E SING_BOX_EBPF_SHARED_INTEGRATION=1 \
go test -count=1 -run TestSharedNetworkDataPathIntegration \
  -tags with_ebpf,ebpf_integration ./protocol/ebpf
```

Setting `SING_BOX_EBPF_INTEGRATION_ATTACH=1` also attaches each program before
cleanup. Use that mode only with an empty, dedicated cgroup passed through
`SING_BOX_EBPF_INTEGRATION_CGROUP`; attaching to a populated root cgroup can
briefly affect unrelated traffic. Preparing the target also removes stale
programs whose names start with `sb_ebpf_`.

For Android soak tests, record the startup program list and monitor the Clash
API connection view while exercising repeated short TCP connections, UDP
session expiry, and connected UDP socket churn. Traffic should continue to use
the correct original destination without persistent lookup or map operation
errors in the log.

## Credits

The native interception implementation is based on
[Asterisk4Magisk/bpf2socks](https://github.com/Asterisk4Magisk/bpf2socks) and
has been adapted for direct integration as a sing-box inbound, without a SOCKS
bridge.

The derived native source remains available under GPL-3.0. See
[`native/LICENSE`](native/LICENSE).
