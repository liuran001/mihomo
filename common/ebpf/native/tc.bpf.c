// Copyright 2026, sing-box contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include "abi.h"
#include "bpf_compat.h"
#include "fakeip_policy.h"
#include "private_address.h"

#include <linux/bpf.h>

#define BPF_ANY 0U
#define BPF_NOEXIST 1U
#define TCP_FLAGS_OFFSET 13U
#define TCP_FLAG_SYN 0x02U
#define BPF_F_CURRENT_NETNS (-1ULL)
#define BPF_F_INGRESS (1ULL << 0)
#define BPF_TCP_LISTEN 10U
#define TC_ACT_OK 0
#define TC_ACT_SHOT 2
#define TC_ACT_UNSPEC (-1)

#define ETH_P_IP_VALUE 0x0800U
#define ETH_P_IPV6_VALUE 0x86ddU
#define ETH_P_8021Q_VALUE 0x8100U
#define ETH_P_8021AD_VALUE 0x88a8U
#define AF_INET_VALUE 2U
#define AF_INET6_VALUE 10U
#define IPPROTO_TCP_VALUE 6U
#define IPPROTO_UDP_VALUE 17U
#define IPPROTO_HOPOPTS_VALUE 0U
#define IPPROTO_ROUTING_VALUE 43U
#define IPPROTO_FRAGMENT_VALUE 44U
#define IPPROTO_AH_VALUE 51U
#define IPPROTO_DSTOPTS_VALUE 60U
#define IPV4_FRAGMENT_OFFSET_MASK 0x1fffU
#define IPV4_FRAGMENT_MORE 0x2000U
#define IPV6_FRAGMENT_OFFSET_MASK 0xfff8U
#define IPV6_FRAGMENT_MORE 0x0001U

#define SB_TC_FLAG_IPV4 (1U << 0)
#define SB_TC_FLAG_LOCAL_IPV6 (1U << 1)
#define SB_TC_FLAG_TCP (1U << 2)
#define SB_TC_FLAG_UDP (1U << 3)
#define SB_TC_FLAG_UID_POLICY (1U << 4)
#define SB_TC_FLAG_UID_DEFAULT_BYPASS (1U << 5)
#define SB_TC_FLAG_LOCAL_BYPASS_PRIVATE (1U << 6)
#define SB_TC_FLAG_SHARED_BYPASS_PRIVATE (1U << 7)
#define SB_TC_FLAG_BYPASS_IPV4 (1U << 8)
#define SB_TC_FLAG_BYPASS_IPV6 (1U << 9)
#define SB_TC_FLAG_FAKEIP_IPV4 (1U << 10)
#define SB_TC_FLAG_FAKEIP_IPV6 (1U << 11)
#define SB_TC_FLAG_INCLUDE_SOURCE (1U << 12)
#define SB_TC_FLAG_EXCLUDE_SOURCE (1U << 13)
#define SB_TC_FLAG_INCLUDE_SOURCE_MAC (1U << 14)
#define SB_TC_FLAG_EXCLUDE_SOURCE_MAC (1U << 15)
#define SB_TC_FLAG_HOST_IPV4 (1U << 16)
#define SB_TC_FLAG_HOST_IPV6 (1U << 17)
#define SB_TC_FLAG_SHARED_IPV6 (1U << 18)
#define SB_TC_FLAG_ISOLATED (1U << 19)
#define SB_TC_FLAG_LOCAL_BYPASS_PORT (1U << 20)
#define SB_TC_FLAG_SHARED_BYPASS_PORT (1U << 21)
// The shared path reads a destination bypass table of its own only once
// SB_TC_FLAG_SHARED_BYPASS_SEPARATE is set, which userspace does when the local
// and shared scopes bypass different rule sets. Until then both paths read
// tc_bypass_ipv4/6, gated by SB_TC_FLAG_BYPASS_IPV4/6.
#define SB_TC_FLAG_SHARED_BYPASS_IPV4 (1U << 22)
#define SB_TC_FLAG_SHARED_BYPASS_IPV6 (1U << 23)
#define SB_TC_FLAG_SHARED_BYPASS_SEPARATE (1U << 24)

#define SB_TC_SOCKET_POLICY_BYPASS 1U
#define SB_TC_SOCKET_POLICY_INTERCEPT 2U

#define SB_TC_DNS_HIJACK 0U
#define SB_TC_DNS_RESPECT_POLICY 1U
#define SB_TC_DNS_OFF 2U

#define SB_TC_LISTENER_TCP4 0U
#define SB_TC_LISTENER_TCP6 1U
#define SB_TC_LISTENER_COUNT 2U

#define SB_TC_PATH_SHARED 1U
#define SB_TC_PATH_DELIVERY 2U
#define SB_TC_PATH_SOURCE_MAC_VALID 0x80U

static long (*skb_pull_data)(void *ctx, __u32 len) = (void *)BPF_FUNC_skb_pull_data;

struct sb_tc_control {
    __u32 enabled;
    __u32 flags;
    __u32 delivery_ifindex;
    __u32 routing_mark;
    __u16 listener_port;
    __u16 local_dns_mode;
    __u16 shared_dns_mode;
    __u8 delivery_mac[6];
    __u16 reserved;
    __u8 fakeip_ipv4_prefix[4];
    __u8 fakeip_ipv4_mask[4];
    __u8 fakeip_ipv6_prefix[16];
    __u8 fakeip_ipv6_mask[16];
};

struct sb_tc_uid_key {
    __u32 prefixlen;
    __u8 uid[4];
};

struct sb_tc_ipv4_lpm_key {
    __u32 prefixlen;
    __u8 address[4];
};

struct sb_tc_ipv6_lpm_key {
    __u32 prefixlen;
    __u8 address[16];
};

struct sb_tc_ipv4_key {
    __u8 address[4];
};

struct sb_tc_ipv6_key {
    __u8 address[16];
};

struct sb_tc_mac_key {
    __u8 address[6];
    __u8 reserved[2];
};

struct sb_tc_port_key {
    __u8 protocol;
    __u8 reserved;
    __u16 port;
};

struct sb_tc_assign_key {
    __u8 family;
    __u8 protocol;
    __u16 source_port;
    __u16 destination_port;
    __u16 reserved;
    __u32 interface_index;
    __u8 source_addr[16];
    __u8 destination_addr[16];
};

struct sb_tc_assign_value {
    __u64 socket_cookie;
    __u32 ifindex;
    __u8 source_mac[6];
    __u8 path;
    __u8 source_mac_valid;
    __u64 generation;
    __u64 last_seen_ns;
};

struct sb_tc_retired_key {
    struct sb_tc_assign_key flow;
    __u32 reserved;
    __u64 generation;
};
_Static_assert(sizeof(struct sb_tc_retired_key) == 56, "TC retirement key ABI");

_Static_assert(sizeof(struct sb_tc_control) == 72, "sb_tc_control ABI size");
_Static_assert(__builtin_offsetof(struct sb_tc_control, delivery_ifindex) == 8,
    "sb_tc_control delivery_ifindex ABI offset");
_Static_assert(__builtin_offsetof(struct sb_tc_control, routing_mark) == 12,
    "sb_tc_control routing_mark ABI offset");
_Static_assert(__builtin_offsetof(struct sb_tc_control, listener_port) == 16,
    "sb_tc_control listener_port ABI offset");
_Static_assert(__builtin_offsetof(struct sb_tc_control, fakeip_ipv6_mask) == 54,
    "sb_tc_control fakeip_ipv6_mask ABI offset");
_Static_assert(sizeof(struct sb_tc_assign_key) == 44, "sb_tc_assign_key ABI size");
_Static_assert(sizeof(struct sb_tc_assign_value) == 40, "sb_tc_assign_value ABI size");
_Static_assert(__builtin_offsetof(struct sb_tc_assign_value, socket_cookie) == 0,
    "sb_tc_assign_value socket_cookie ABI offset");

struct ethernet_header {
    __u8 destination[6];
    __u8 source[6];
    __be16 protocol;
};

struct vlan_header {
    __be16 tci;
    __be16 protocol;
};

struct ipv4_header {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    __u8 ihl : 4;
    __u8 version : 4;
#else
    __u8 version : 4;
    __u8 ihl : 4;
#endif
    __u8 tos;
    __be16 total_length;
    __be16 id;
    __be16 fragment_offset;
    __u8 ttl;
    __u8 protocol;
    __sum16 checksum;
    __be32 source;
    __be32 destination;
};

struct ipv6_header {
    __be32 version_flow;
    __be16 payload_length;
    __u8 next_header;
    __u8 hop_limit;
    __u8 source[16];
    __u8 destination[16];
};

struct transport_ports {
    __be16 source;
    __be16 destination;
};

struct ipv6_extension_header {
    __u8 next_header;
    __u8 length;
};

struct ipv6_fragment_header {
    __u8 next_header;
    __u8 reserved;
    __be16 offset_flags;
    __be32 identification;
};

#define MAP(name, key, value, map_type, entries) \
    struct bpf_map_def SEC("maps") name = { \
        .type = map_type, .key_size = sizeof(key), .value_size = sizeof(value), \
        .max_entries = entries, \
    }

MAP(tc_local_force_ipv4, struct sb_tc_ipv4_lpm_key, __u8, BPF_MAP_TYPE_LPM_TRIE, 4096U);
MAP(tc_local_force_ipv6, struct sb_tc_ipv6_lpm_key, __u8, BPF_MAP_TYPE_LPM_TRIE, 4096U);
MAP(tc_shared_force_ipv4, struct sb_tc_ipv4_lpm_key, __u8, BPF_MAP_TYPE_LPM_TRIE, 4096U);
MAP(tc_shared_force_ipv6, struct sb_tc_ipv6_lpm_key, __u8, BPF_MAP_TYPE_LPM_TRIE, 4096U);
MAP(tc_control, __u32, struct sb_tc_control, BPF_MAP_TYPE_ARRAY, 1U);
MAP(tc_listener_sockets, __u32, __u32, BPF_MAP_TYPE_SOCKMAP, SB_TC_LISTENER_COUNT);
MAP(tc_retired_assignment, struct sb_tc_retired_key, __u8, BPF_MAP_TYPE_LRU_HASH, 65536U);
MAP(tc_assignment, struct sb_tc_assign_key, struct sb_tc_assign_value, BPF_MAP_TYPE_LRU_HASH, 65536U);
MAP(tc_self_sockets, __u64, __u32, BPF_MAP_TYPE_LRU_HASH, 65536U);
MAP(tc_uid_policy, struct sb_tc_uid_key, __u8, BPF_MAP_TYPE_LPM_TRIE, 4096U);
MAP(tc_bypass_ipv4, struct sb_tc_ipv4_lpm_key, __u8, BPF_MAP_TYPE_LPM_TRIE, 65536U);
MAP(tc_bypass_ipv6, struct sb_tc_ipv6_lpm_key, __u8, BPF_MAP_TYPE_LPM_TRIE, 65536U);
MAP(tc_shared_bypass_ipv4, struct sb_tc_ipv4_lpm_key, __u8, BPF_MAP_TYPE_LPM_TRIE, 65536U);
MAP(tc_shared_bypass_ipv6, struct sb_tc_ipv6_lpm_key, __u8, BPF_MAP_TYPE_LPM_TRIE, 65536U);
MAP(tc_include_source_ipv4, struct sb_tc_ipv4_lpm_key, __u8, BPF_MAP_TYPE_LPM_TRIE, 4096U);
MAP(tc_include_source_ipv6, struct sb_tc_ipv6_lpm_key, __u8, BPF_MAP_TYPE_LPM_TRIE, 4096U);
MAP(tc_exclude_source_ipv4, struct sb_tc_ipv4_lpm_key, __u8, BPF_MAP_TYPE_LPM_TRIE, 4096U);
MAP(tc_exclude_source_ipv6, struct sb_tc_ipv6_lpm_key, __u8, BPF_MAP_TYPE_LPM_TRIE, 4096U);
MAP(tc_include_source_mac, struct sb_tc_mac_key, __u8, BPF_MAP_TYPE_HASH, 1024U);
MAP(tc_exclude_source_mac, struct sb_tc_mac_key, __u8, BPF_MAP_TYPE_HASH, 1024U);
MAP(tc_host_ipv4, struct sb_tc_ipv4_key, __u8, BPF_MAP_TYPE_HASH, 4096U);
MAP(tc_host_ipv6, struct sb_tc_ipv6_key, __u8, BPF_MAP_TYPE_HASH, 4096U);
MAP(tc_local_bypass_port, struct sb_tc_port_key, __u8, BPF_MAP_TYPE_HASH, 4096U);
MAP(tc_shared_bypass_port, struct sb_tc_port_key, __u8, BPF_MAP_TYPE_HASH, 4096U);
// Degradation counters for the paths below that give up on a packet without
// saying so. Indexed by SB_TC_STAT_* (native/abi.h, where each key's
// operational meaning is written down); same shape as shared_network.bpf.c's
// shared_stats, and read the same way from Go -- summed across CPUs.
MAP(tc_stats, __u32, __u64, BPF_MAP_TYPE_PERCPU_ARRAY, SB_TC_STAT_COUNT);

static __u64 (*ktime_get_ns)(void) = (void *)BPF_FUNC_ktime_get_ns;
static void *(*map_lookup)(void *map, const void *key) = (void *)BPF_FUNC_map_lookup_elem;
static long (*map_update)(void *map, const void *key, const void *value, __u64 flags) =
    (void *)BPF_FUNC_map_update_elem;
static long (*map_delete)(void *map, const void *key) = (void *)BPF_FUNC_map_delete_elem;
static __u32 (*get_socket_uid)(void *ctx) = (void *)BPF_FUNC_get_socket_uid;
static __u64 (*get_socket_cookie)(void *ctx) = (void *)BPF_FUNC_get_socket_cookie;
static long (*redirect)(int ifindex, __u64 flags) = (void *)BPF_FUNC_redirect;
static long (*skb_store_bytes)(void *ctx, __u32 offset, const void *from, __u32 length, __u64 flags) =
    (void *)BPF_FUNC_skb_store_bytes;
static long (*skb_change_head)(void *ctx, __u32 length, __u64 flags) =
    (void *)BPF_FUNC_skb_change_head;
static struct bpf_sock *(*skc_lookup_tcp)(void *ctx, struct bpf_sock_tuple *tuple,
    __u32 tuple_size, __u64 netns, __u64 flags) = (void *)BPF_FUNC_skc_lookup_tcp;
static struct bpf_sock *(*sk_lookup_udp)(void *ctx, struct bpf_sock_tuple *tuple,
    __u32 tuple_size, __u64 netns, __u64 flags) = (void *)BPF_FUNC_sk_lookup_udp;
static long (*sk_assign)(void *ctx, struct bpf_sock *socket, __u64 flags) =
    (void *)BPF_FUNC_sk_assign;
static void (*sk_release)(struct bpf_sock *socket) = (void *)BPF_FUNC_sk_release;

// record_tc_stat advances one SB_TC_STAT_* counter, mirroring
// shared_network.bpf.c's record_shared_stat exactly: a plain lookup and a
// non-atomic increment, which is safe only because tc_stats is a PERCPU_ARRAY
// and each CPU owns its own slot. Every caller is a path that has already
// decided to stop handling the packet, so the extra lookup is never on a
// forwarding hot path.
INLINE void record_tc_stat(__u32 key) {
    __u64 *counter = map_lookup(&tc_stats, &key);
    if (counter != 0) *counter += 1U;
}

INLINE __u16 network_order16(__u16 value) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return __builtin_bswap16(value);
#else
    return value;
#endif
}

INLINE __u32 network_order32(__u32 value) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return __builtin_bswap32(value);
#else
    return value;
#endif
}

INLINE void copy_address(__u8 destination[16], const __u8 source[16], __u32 size) {
#pragma clang loop unroll(full)
    for (__u32 index = 0U; index < 16U; ++index) {
        destination[index] = index < size ? source[index] : 0U;
    }
}

INLINE const struct sb_tc_control *load_control(void) {
    __u32 zero = 0U;
    return map_lookup(&tc_control, &zero);
}

INLINE bool protocol_enabled(const struct sb_tc_control *control, __u8 protocol) {
    if (protocol == IPPROTO_TCP_VALUE) return (control->flags & SB_TC_FLAG_TCP) != 0U;
    if (protocol == IPPROTO_UDP_VALUE) return (control->flags & SB_TC_FLAG_UDP) != 0U;
    return false;
}

INLINE bool service_port(__u8 protocol, __u16 source, __u16 destination) {
    if (protocol != IPPROTO_UDP_VALUE) return false;
    return source == 67U || source == 68U || source == 546U || source == 547U ||
        destination == 67U || destination == 68U || destination == 546U || destination == 547U;
}

INLINE bool uid_bypassed(struct __sk_buff *skb, const struct sb_tc_control *control) {
    if ((control->flags & SB_TC_FLAG_UID_POLICY) == 0U) return false;
    __u32 uid = network_order32(get_socket_uid(skb));
    struct sb_tc_uid_key key = {.prefixlen = 32U};
    __builtin_memcpy(key.uid, &uid, sizeof(uid));
    bool matched = map_lookup(&tc_uid_policy, &key) != 0;
    return (control->flags & SB_TC_FLAG_UID_DEFAULT_BYPASS) != 0U ? !matched : matched;
}

INLINE __u32 socket_metadata(__u64 socket_cookie) {
    if (socket_cookie == 0U) return 0U;
    __u32 *metadata = map_lookup(&tc_self_sockets, &socket_cookie);
    return metadata != 0 ? *metadata : 0U;
}

INLINE bool port_bypassed(const struct sb_tc_control *control,
    const struct sb_tc_assign_key *flow, bool shared) {
    __u32 flag = shared ? SB_TC_FLAG_SHARED_BYPASS_PORT : SB_TC_FLAG_LOCAL_BYPASS_PORT;
    if ((control->flags & flag) == 0U) return false;
    struct sb_tc_port_key key = {.protocol = flow->protocol, .port = flow->destination_port};
    if (shared) return map_lookup(&tc_shared_bypass_port, &key) != 0;
    return map_lookup(&tc_local_bypass_port, &key) != 0;
}

INLINE bool dns_selected(__u8 protocol, __u16 destination_port, __u16 mode) {
    if ((protocol != IPPROTO_TCP_VALUE && protocol != IPPROTO_UDP_VALUE) || destination_port != 53U) return false;
    return mode == SB_TC_DNS_HIJACK;
}

INLINE bool dns_bypassed(__u8 protocol, __u16 destination_port, __u16 mode) {
    return (protocol == IPPROTO_TCP_VALUE || protocol == IPPROTO_UDP_VALUE) &&
        destination_port == 53U && mode == SB_TC_DNS_OFF;
}

INLINE bool private_destination(const struct sb_tc_assign_key *key) {
    if (key->family == AF_INET_VALUE) return sb_ebpf_ipv4_private_address(key->destination_addr);
    return sb_ebpf_ipv6_private_address(key->destination_addr);
}

INLINE bool local_force_v4(const __u8 destination[4]) {
    struct sb_tc_ipv4_lpm_key key = {.prefixlen = 32U};
    __builtin_memcpy(key.address, destination, 4U);
    return map_lookup(&tc_local_force_ipv4, &key) != 0;
}

INLINE bool local_force_v6(const __u8 destination[16]) {
    struct sb_tc_ipv6_lpm_key key = {.prefixlen = 128U};
    __builtin_memcpy(key.address, destination, 16U);
    return map_lookup(&tc_local_force_ipv6, &key) != 0;
}

INLINE bool shared_force_v4(const __u8 destination[4]) {
    struct sb_tc_ipv4_lpm_key key = {.prefixlen = 32U};
    __builtin_memcpy(key.address, destination, 4U);
    return map_lookup(&tc_shared_force_ipv4, &key) != 0;
}

INLINE bool shared_force_v6(const __u8 destination[16]) {
    struct sb_tc_ipv6_lpm_key key = {.prefixlen = 128U};
    __builtin_memcpy(key.address, destination, 16U);
    return map_lookup(&tc_shared_force_ipv6, &key) != 0;
}

INLINE bool must_intercept_fakeip(const struct sb_tc_control *control,
    const struct sb_tc_assign_key *key) {
    if (key->family == AF_INET_VALUE) {
        return sb_ebpf_must_intercept_fakeip_ipv4(
            key->destination_addr,
            control->flags,
            SB_TC_FLAG_FAKEIP_IPV4,
            control->fakeip_ipv4_prefix,
            control->fakeip_ipv4_mask);
    }
    return sb_ebpf_must_intercept_fakeip_ipv6(
        key->destination_addr,
        control->flags,
        SB_TC_FLAG_FAKEIP_IPV6,
        control->fakeip_ipv6_prefix,
        control->fakeip_ipv6_mask);
}

INLINE bool bypass_destination(const struct sb_tc_control *control,
    const struct sb_tc_assign_key *flow, bool shared) {
    bool own_table = shared && (control->flags & SB_TC_FLAG_SHARED_BYPASS_SEPARATE) != 0U;
    if (flow->family == AF_INET_VALUE) {
        __u32 gate = own_table ? SB_TC_FLAG_SHARED_BYPASS_IPV4 : SB_TC_FLAG_BYPASS_IPV4;
        if ((control->flags & gate) == 0U) return false;
        struct sb_tc_ipv4_lpm_key key = {.prefixlen = 32U};
        __builtin_memcpy(key.address, flow->destination_addr, 4U);
        if (own_table) return map_lookup(&tc_shared_bypass_ipv4, &key) != 0;
        return map_lookup(&tc_bypass_ipv4, &key) != 0;
    }
    __u32 gate = own_table ? SB_TC_FLAG_SHARED_BYPASS_IPV6 : SB_TC_FLAG_BYPASS_IPV6;
    if ((control->flags & gate) == 0U) return false;
    struct sb_tc_ipv6_lpm_key key = {.prefixlen = 128U};
    __builtin_memcpy(key.address, flow->destination_addr, 16U);
    if (own_table) return map_lookup(&tc_shared_bypass_ipv6, &key) != 0;
    return map_lookup(&tc_bypass_ipv6, &key) != 0;
}

// Source policy for shared clients, see shared_network_policy.h: exclusion
// wins, and with any include list configured a client is selected when its MAC
// OR its source address is included. Reports membership in one list; false
// when that list is not configured.
INLINE bool source_address_matches(const struct sb_tc_control *control,
    const struct sb_tc_assign_key *flow, bool include) {
    if ((control->flags & (include ? SB_TC_FLAG_INCLUDE_SOURCE : SB_TC_FLAG_EXCLUDE_SOURCE)) == 0U) return false;
    if (flow->family == AF_INET_VALUE) {
        struct sb_tc_ipv4_lpm_key key = {.prefixlen = 32U};
        __builtin_memcpy(key.address, flow->source_addr, 4U);
        if (include) return map_lookup(&tc_include_source_ipv4, &key) != 0;
        return map_lookup(&tc_exclude_source_ipv4, &key) != 0;
    }
    struct sb_tc_ipv6_lpm_key key = {.prefixlen = 128U};
    __builtin_memcpy(key.address, flow->source_addr, 16U);
    if (include) return map_lookup(&tc_include_source_ipv6, &key) != 0;
    return map_lookup(&tc_exclude_source_ipv6, &key) != 0;
}

INLINE bool host_destination(const struct sb_tc_control *control,
    const struct sb_tc_assign_key *flow) {
    if (flow->family == AF_INET_VALUE) {
        if ((control->flags & SB_TC_FLAG_HOST_IPV4) == 0U) return false;
        struct sb_tc_ipv4_key key = {};
        __builtin_memcpy(key.address, flow->destination_addr, 4U);
        return map_lookup(&tc_host_ipv4, &key) != 0;
    }
    if ((control->flags & SB_TC_FLAG_HOST_IPV6) == 0U) return false;
    struct sb_tc_ipv6_key key = {};
    __builtin_memcpy(key.address, flow->destination_addr, 16U);
    return map_lookup(&tc_host_ipv6, &key) != 0;
}

INLINE bool source_mac_matches(const struct sb_tc_control *control, const __u8 source_mac[6], bool include) {
    if ((control->flags & (include ? SB_TC_FLAG_INCLUDE_SOURCE_MAC : SB_TC_FLAG_EXCLUDE_SOURCE_MAC)) == 0U) return false;
    struct sb_tc_mac_key key = {};
    __builtin_memcpy(key.address, source_mac, 6U);
    if (include) return map_lookup(&tc_include_source_mac, &key) != 0;
    return map_lookup(&tc_exclude_source_mac, &key) != 0;
}

INLINE bool shared_source_selected(const struct sb_tc_control *control,
    const struct sb_tc_assign_key *flow, const __u8 source_mac[6]) {
    if (source_address_matches(control, flow, false) || source_mac_matches(control, source_mac, false)) return false;
    if ((control->flags & (SB_TC_FLAG_INCLUDE_SOURCE | SB_TC_FLAG_INCLUDE_SOURCE_MAC)) == 0U) return true;
    return source_address_matches(control, flow, true) || source_mac_matches(control, source_mac, true);
}

INLINE bool local_selected(struct __sk_buff *skb, const struct sb_tc_control *control,
    const struct sb_tc_assign_key *key, __u32 socket_metadata_value) {
    if (key->family == AF_INET_VALUE ? local_force_v4(key->destination_addr) : local_force_v6(key->destination_addr)) return true;
    if (must_intercept_fakeip(control, key)) return true;
    if (dns_bypassed(key->protocol, key->destination_port, control->local_dns_mode)) return false;
    if (dns_selected(key->protocol, key->destination_port, control->local_dns_mode)) return true;
    if ((socket_metadata_value & SB_EBPF_SOCKET_METADATA_POLICY_BYPASS) != 0U) return false;
    if ((socket_metadata_value & SB_EBPF_SOCKET_METADATA_POLICY_INTERCEPT) == 0U && uid_bypassed(skb, control)) return false;
    if (key->destination_port == 53U && control->local_dns_mode == SB_TC_DNS_RESPECT_POLICY) return true;
    if (port_bypassed(control, key, false)) return false;
    if (host_destination(control, key)) return false;
    if ((control->flags & SB_TC_FLAG_LOCAL_BYPASS_PRIVATE) != 0U && private_destination(key)) return false;
    return !bypass_destination(control, key, false);
}

INLINE bool shared_selected(const struct sb_tc_control *control,
    const struct sb_tc_assign_key *key, const __u8 source_mac[6]) {
    if (key->family == AF_INET_VALUE ? shared_force_v4(key->destination_addr) : shared_force_v6(key->destination_addr)) return true;
    if (must_intercept_fakeip(control, key)) return true;
    if (dns_bypassed(key->protocol, key->destination_port, control->shared_dns_mode)) return false;
    if (dns_selected(key->protocol, key->destination_port, control->shared_dns_mode)) return true;
    if (!shared_source_selected(control, key, source_mac)) return false;
    if (key->destination_port == 53U && control->shared_dns_mode == SB_TC_DNS_RESPECT_POLICY) return true;
    if (port_bypassed(control, key, true)) return false;
    if (host_destination(control, key)) return false;
    if ((control->flags & SB_TC_FLAG_SHARED_BYPASS_PRIVATE) != 0U && private_destination(key)) return false;
    return !bypass_destination(control, key, true);
}

INLINE bool parse_ethernet(void *data, void *data_end, __u16 *protocol, __u32 *l3_offset, __u8 source_mac[6]) {
    struct ethernet_header *ethernet = data;
    if ((void *)(ethernet + 1) > data_end) return false;
    *protocol = network_order16(ethernet->protocol);
    *l3_offset = sizeof(*ethernet);
    __builtin_memcpy(source_mac, ethernet->source, 6U);
#pragma clang loop unroll(full)
    for (__u32 depth = 0U; depth < 2U; ++depth) {
        if (*protocol != ETH_P_8021Q_VALUE && *protocol != ETH_P_8021AD_VALUE) break;
        struct vlan_header *vlan = data + *l3_offset;
        if ((void *)(vlan + 1) > data_end) return false;
        *protocol = network_order16(vlan->protocol);
        *l3_offset += sizeof(*vlan);
    }
    return true;
}

#define SB_TC_PARSE_PASS 0
#define SB_TC_PARSE_FLOW 1
#define SB_TC_PARSE_FRAGMENT 2

// Fragment parsing is enabled only for replies generated in our private netns.
// External fragments continue to follow the existing pass-through policy.
struct sb_tc_fragment { __u32 id; __u32 state; }; // 0=whole, 1=first, 2=tail

// tcp_flags returns the TCP flag byte. A header that cannot be read is
// reported as a SYN so that callers which act only on connection setup stay
// conservative.
INLINE __u8 tcp_flags(void *transport, void *data_end, __u8 protocol) {
    if (protocol != IPPROTO_TCP_VALUE) return 0U;
    __u8 *flags = transport + TCP_FLAGS_OFFSET;
    if ((void *)(flags + 1) > data_end) return TCP_FLAG_SYN;
    return *flags;
}

// The key fillers report a fragment they do not parse separately, so that
// each caller decides whether and where to count it. flags, when given,
// receives the TCP flag byte of a parsed flow.
INLINE int fill_ipv4_key_extended(void *data, void *data_end, __u32 l3_offset,
    const struct sb_tc_control *control, struct sb_tc_assign_key *key,
    struct sb_tc_fragment *fragment, __u8 *flags) {
    struct ipv4_header *ip = data + l3_offset;
    if ((void *)(ip + 1) > data_end || ip->version != 4U || ip->ihl < 5U ||
        !protocol_enabled(control, ip->protocol)) return SB_TC_PARSE_PASS;
    if ((network_order16(ip->fragment_offset) & (IPV4_FRAGMENT_OFFSET_MASK | IPV4_FRAGMENT_MORE)) != 0U) {
        if (fragment == 0) return SB_TC_PARSE_FRAGMENT;
        fragment->id = network_order16(ip->id);
        fragment->state = (network_order16(ip->fragment_offset) & IPV4_FRAGMENT_OFFSET_MASK) != 0U ? 2U : 1U;
    }
    __u32 header_length = (__u32)ip->ihl * 4U;
    struct transport_ports *ports = (void *)ip + header_length;
    __u16 source_port = 0U, destination_port = 0U;
    if (fragment == 0 || fragment->state != 2U) {
        if ((void *)(ports + 1) > data_end) return SB_TC_PARSE_PASS;
        source_port = network_order16(ports->source);
        destination_port = network_order16(ports->destination);
    }
    if (service_port(ip->protocol, source_port, destination_port)) return SB_TC_PARSE_PASS;
    __u8 destination[4];
    __builtin_memcpy(destination, &ip->destination, 4U);
    if (sb_ebpf_ipv4_safety_bypass(destination)) return SB_TC_PARSE_PASS;
    if (flags != 0) *flags = tcp_flags(ports, data_end, ip->protocol);
    __builtin_memset(key, 0, sizeof(*key));
    key->family = AF_INET_VALUE;
    key->protocol = ip->protocol;
    key->source_port = source_port;
    key->destination_port = destination_port;
    __builtin_memcpy(key->source_addr, &ip->source, 4U);
    __builtin_memcpy(key->destination_addr, &ip->destination, 4U);
    return SB_TC_PARSE_FLOW;
}

INLINE int fill_ipv6_key_extended(void *data, void *data_end, __u32 l3_offset,
    const struct sb_tc_control *control, struct sb_tc_assign_key *key,
    struct sb_tc_fragment *fragment_info, __u8 *flags) {
    struct ipv6_header *ip = data + l3_offset;
    if ((void *)(ip + 1) > data_end || (network_order32(ip->version_flow) >> 28U) != 6U) return SB_TC_PARSE_PASS;
    __u8 protocol = ip->next_header;
    __u32 transport_offset = l3_offset + sizeof(*ip);
#pragma clang loop unroll(full)
    for (__u32 depth = 0U; depth < 4U; ++depth) {
        if (protocol == IPPROTO_FRAGMENT_VALUE) {
            struct ipv6_fragment_header *fragment = data + transport_offset;
            if ((void *)(fragment + 1) > data_end) return SB_TC_PARSE_PASS;
            if ((network_order16(fragment->offset_flags) &
                    (IPV6_FRAGMENT_OFFSET_MASK | IPV6_FRAGMENT_MORE)) != 0U) {
                if (fragment_info == 0 || !protocol_enabled(control, fragment->next_header))
                    return SB_TC_PARSE_FRAGMENT;
                fragment_info->id = network_order32(fragment->identification);
                fragment_info->state = (network_order16(fragment->offset_flags) & IPV6_FRAGMENT_OFFSET_MASK) != 0U ? 2U : 1U;
            }
            protocol = fragment->next_header;
            transport_offset += sizeof(*fragment);
            continue;
        }
        if (protocol != IPPROTO_HOPOPTS_VALUE && protocol != IPPROTO_ROUTING_VALUE &&
            protocol != IPPROTO_DSTOPTS_VALUE && protocol != IPPROTO_AH_VALUE) break;
        struct ipv6_extension_header *extension = data + transport_offset;
        if ((void *)(extension + 1) > data_end) return SB_TC_PARSE_PASS;
        __u32 extension_length = protocol == IPPROTO_AH_VALUE
            ? ((__u32)extension->length + 2U) * 4U
            : ((__u32)extension->length + 1U) * 8U;
        if (extension_length < 8U || data + transport_offset + extension_length > data_end) return SB_TC_PARSE_PASS;
        protocol = extension->next_header;
        transport_offset += extension_length;
    }
    if (!protocol_enabled(control, protocol)) return SB_TC_PARSE_PASS;
    struct transport_ports *ports = data + transport_offset;
    __u16 source_port = 0U, destination_port = 0U;
    if (fragment_info == 0 || fragment_info->state != 2U) {
        if ((void *)(ports + 1) > data_end) return SB_TC_PARSE_PASS;
        source_port = network_order16(ports->source);
        destination_port = network_order16(ports->destination);
    }
    if (service_port(protocol, source_port, destination_port) ||
        sb_ebpf_ipv6_safety_bypass(ip->destination)) return SB_TC_PARSE_PASS;
    if (flags != 0) *flags = tcp_flags(ports, data_end, protocol);
    __builtin_memset(key, 0, sizeof(*key));
    key->family = AF_INET6_VALUE;
    key->protocol = protocol;
    key->source_port = source_port;
    key->destination_port = destination_port;
    copy_address(key->source_addr, ip->source, 16U);
    copy_address(key->destination_addr, ip->destination, 16U);
    return SB_TC_PARSE_FLOW;
}

// Volatile so that both sides of the pull load the pointers again after it
// and reach the parser in the same verifier state.
#define SKB_DATA(skb) ((void *)(long)*(volatile __u32 *)&(skb)->data)
#define SKB_DATA_END(skb) ((void *)(long)*(volatile __u32 *)&(skb)->data_end)

// Drivers that build received packets in page fragments (napi_gro_frags users
// such as mlx4, sfc and gve, or any device with GRO off) can leave headers GRO
// did not parse, such as a UDP header, outside the linear area that direct
// packet access reads, and the packet would bypass its assignment. The pull
// covers the longest header layout parsed before the transport ports and
// happens before anything is parsed: a packet value kept across the helper
// call loses its bounds on older verifiers, which then walk the rest of the
// program once per side of the pull. A packet whose first bytes are linear,
// including every short linear packet, only pays the compare.
#define SB_TC_PULL_LENGTH_ETHERNET (sizeof(struct ethernet_header) + 2U * sizeof(struct vlan_header) + \
    sizeof(struct ipv6_header) + 8U)
#define SB_TC_PULL_LENGTH_RAW_IP (sizeof(struct ipv6_header) + 8U)

INLINE void pull_headers(struct __sk_buff *skb, __u32 length) {
    __u32 available = skb->len;
    if (available < length) length = available;
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    if (data + length <= data_end) return;
    (void)skb_pull_data(skb, length);
}

// parse_flow fills key for a TCP/UDP flow the data planes may select. A
// fragment is reported separately so that each caller decides whether and
// where to count it. Ingress callers pull headers a driver left in page
// fragments; locally built egress packets always have them linear, and the
// isolated delivery receives packets a selecting program already pulled.
INLINE int parse_flow_extended(struct __sk_buff *skb, const struct sb_tc_control *control,
    __u32 ipv6_flag, bool ethernet, bool pull, struct sb_tc_assign_key *key, __u8 source_mac[6], __u8 *flags) {
    void *data;
    void *data_end;
    if (pull) {
        pull_headers(skb, ethernet ? SB_TC_PULL_LENGTH_ETHERNET : SB_TC_PULL_LENGTH_RAW_IP);
        data = SKB_DATA(skb);
        data_end = SKB_DATA_END(skb);
    } else {
        data = (void *)(long)skb->data;
        data_end = (void *)(long)skb->data_end;
    }
    __u16 ether_type;
    __u32 l3_offset;
    if (ethernet) {
        if (!parse_ethernet(data, data_end, &ether_type, &l3_offset, source_mac)) return SB_TC_PARSE_PASS;
    } else {
        ether_type = network_order16(skb->protocol);
        l3_offset = 0U;
        __builtin_memset(source_mac, 0, 6U);
    }
    if (ether_type == ETH_P_IP_VALUE && (control->flags & SB_TC_FLAG_IPV4) != 0U) {
        return fill_ipv4_key_extended(data, data_end, l3_offset, control, key, 0, flags);
    }
    if (ether_type == ETH_P_IPV6_VALUE && (control->flags & ipv6_flag) != 0U) {
        return fill_ipv6_key_extended(data, data_end, l3_offset, control, key, 0, flags);
    }
    return SB_TC_PARSE_PASS;
}

INLINE bool fill_ipv4_key(void *data, void *data_end, __u32 l3_offset,
    const struct sb_tc_control *control, struct sb_tc_assign_key *key) {
    struct ipv4_header *ip = data + l3_offset;
    if ((void *)(ip + 1) > data_end || ip->version != 4U || ip->ihl < 5U ||
        !protocol_enabled(control, ip->protocol) ||
        (network_order16(ip->fragment_offset) & (IPV4_FRAGMENT_OFFSET_MASK | IPV4_FRAGMENT_MORE)) != 0U) return false;
    __u32 header_length = (__u32)ip->ihl * 4U;
    struct transport_ports *ports = (void *)ip + header_length;
    if ((void *)(ports + 1) > data_end) return false;
    __u16 source_port = network_order16(ports->source);
    __u16 destination_port = network_order16(ports->destination);
    if (service_port(ip->protocol, source_port, destination_port)) return false;
    __u8 destination[4];
    __builtin_memcpy(destination, &ip->destination, 4U);
    if (sb_ebpf_ipv4_safety_bypass(destination)) return false;
    __builtin_memset(key, 0, sizeof(*key));
    key->family = AF_INET_VALUE;
    key->protocol = ip->protocol;
    key->source_port = source_port;
    key->destination_port = destination_port;
    __builtin_memcpy(key->source_addr, &ip->source, 4U);
    __builtin_memcpy(key->destination_addr, &ip->destination, 4U);
    return true;
}

/* Keep extension-header pointer bounds local for Linux 5.4 verifiers. */
NOINLINE bool fill_ipv6_key(void *data, void *data_end, __u32 l3_offset,
    const struct sb_tc_control *control, struct sb_tc_assign_key *key) {
    struct ipv6_header *ip = data + l3_offset;
    if ((void *)(ip + 1) > data_end || (network_order32(ip->version_flow) >> 28U) != 6U) return false;
    __u8 protocol = ip->next_header;
    __u32 transport_offset = l3_offset + sizeof(*ip);
#pragma clang loop unroll(full)
    for (__u32 depth = 0U; depth < 4U; ++depth) {
        if (protocol == IPPROTO_FRAGMENT_VALUE) {
            struct ipv6_fragment_header *fragment = data + transport_offset;
            if ((void *)(fragment + 1) > data_end ||
                (network_order16(fragment->offset_flags) &
                    (IPV6_FRAGMENT_OFFSET_MASK | IPV6_FRAGMENT_MORE)) != 0U) return false;
            protocol = fragment->next_header;
            transport_offset += sizeof(*fragment);
            continue;
        }
        if (protocol != IPPROTO_HOPOPTS_VALUE && protocol != IPPROTO_ROUTING_VALUE &&
            protocol != IPPROTO_DSTOPTS_VALUE && protocol != IPPROTO_AH_VALUE) break;
        struct ipv6_extension_header *extension = data + transport_offset;
        if ((void *)(extension + 1) > data_end) return false;
        __u32 extension_length = protocol == IPPROTO_AH_VALUE
            ? ((__u32)extension->length + 2U) * 4U
            : ((__u32)extension->length + 1U) * 8U;
        if (extension_length < 8U || data + transport_offset + extension_length > data_end) return false;
        protocol = extension->next_header;
        transport_offset += extension_length;
    }
    if (!protocol_enabled(control, protocol)) return false;
    struct transport_ports *ports = data + transport_offset;
    if ((void *)(ports + 1) > data_end) return false;
    __u16 source_port = network_order16(ports->source);
    __u16 destination_port = network_order16(ports->destination);
    if (service_port(protocol, source_port, destination_port) ||
        sb_ebpf_ipv6_safety_bypass(ip->destination)) return false;
    __builtin_memset(key, 0, sizeof(*key));
    key->family = AF_INET6_VALUE;
    key->protocol = protocol;
    key->source_port = source_port;
    key->destination_port = destination_port;
    copy_address(key->source_addr, ip->source, 16U);
    copy_address(key->destination_addr, ip->destination, 16U);
    return true;
}

INLINE bool parse_flow(struct __sk_buff *skb, const struct sb_tc_control *control,
    __u32 ipv6_flag, bool ethernet, struct sb_tc_assign_key *key, __u8 source_mac[6]) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    __u16 ether_type;
    __u32 l3_offset;
    if (ethernet) {
        if (!parse_ethernet(data, data_end, &ether_type, &l3_offset, source_mac)) return false;
    } else {
        ether_type = network_order16(skb->protocol);
        l3_offset = 0U;
        __builtin_memset(source_mac, 0, 6U);
    }
    if (ether_type == ETH_P_IP_VALUE && (control->flags & SB_TC_FLAG_IPV4) != 0U) {
        return fill_ipv4_key(data, data_end, l3_offset, control, key);
    }
    if (ether_type == ETH_P_IPV6_VALUE && (control->flags & ipv6_flag) != 0U) {
        return fill_ipv6_key(data, data_end, l3_offset, control, key);
    }
    return false;
}

NOINLINE struct bpf_sock *lookup_tcp_socket(struct __sk_buff *skb,
    const struct sb_tc_assign_key *key) {
    struct bpf_sock_tuple tuple = {};
    __u32 tuple_size;
    if (key->family == AF_INET_VALUE) {
        __builtin_memcpy(&tuple.ipv4.saddr, key->source_addr, 4U);
        __builtin_memcpy(&tuple.ipv4.daddr, key->destination_addr, 4U);
        tuple.ipv4.sport = network_order16(key->source_port);
        tuple.ipv4.dport = network_order16(key->destination_port);
        tuple_size = sizeof(tuple.ipv4);
    } else {
        copy_address((__u8 *)&tuple.ipv6.saddr, key->source_addr, 16U);
        copy_address((__u8 *)&tuple.ipv6.daddr, key->destination_addr, 16U);
        tuple.ipv6.sport = network_order16(key->source_port);
        tuple.ipv6.dport = network_order16(key->destination_port);
        tuple_size = sizeof(tuple.ipv6);
    }
    struct bpf_sock *socket = skc_lookup_tcp(skb, &tuple, tuple_size, BPF_F_CURRENT_NETNS, 0U);
    if (socket != 0 && socket->state != BPF_TCP_LISTEN) return socket;
    if (socket != 0) sk_release(socket);
    __u32 listener = key->family == AF_INET_VALUE ? SB_TC_LISTENER_TCP4 : SB_TC_LISTENER_TCP6;
    return map_lookup(&tc_listener_sockets, &listener);
}

NOINLINE struct bpf_sock *lookup_tcp_socket_legacy(struct __sk_buff *skb,
    const struct sb_tc_control *control, const struct sb_tc_assign_key *key) {
    struct bpf_sock_tuple tuple = {};
    __u32 tuple_size;
    if (key->family == AF_INET_VALUE) {
        __builtin_memcpy(&tuple.ipv4.saddr, key->source_addr, 4U);
        __builtin_memcpy(&tuple.ipv4.daddr, key->destination_addr, 4U);
        tuple.ipv4.sport = network_order16(key->source_port);
        tuple.ipv4.dport = network_order16(key->destination_port);
        tuple_size = sizeof(tuple.ipv4);
    } else {
        copy_address((__u8 *)&tuple.ipv6.saddr, key->source_addr, 16U);
        copy_address((__u8 *)&tuple.ipv6.daddr, key->destination_addr, 16U);
        tuple.ipv6.sport = network_order16(key->source_port);
        tuple.ipv6.dport = network_order16(key->destination_port);
        tuple_size = sizeof(tuple.ipv6);
    }
    struct bpf_sock *socket = skc_lookup_tcp(skb, &tuple, tuple_size, BPF_F_CURRENT_NETNS, 0U);
    if (socket != 0 && socket->state != BPF_TCP_LISTEN) return socket;
    if (socket != 0) sk_release(socket);

    // The legacy path has no SOCKMAP. Query the actual transparent listener
    // port after the established-socket lookup so wildcard listeners remain
    // usable on kernels that reject SOCKMAP or map-backed sk_assign.
    if (key->family == AF_INET_VALUE) {
        tuple.ipv4.dport = network_order16(control->listener_port);
    } else {
        tuple.ipv6.dport = network_order16(control->listener_port);
    }
    return skc_lookup_tcp(skb, &tuple, tuple_size, BPF_F_CURRENT_NETNS, 0U);
}

NOINLINE struct bpf_sock *lookup_udp_socket(struct __sk_buff *skb,
    const struct sb_tc_control *control, const struct sb_tc_assign_key *key) {
    struct bpf_sock_tuple tuple = {};
    __u32 tuple_size;
    if (key->family == AF_INET_VALUE) {
        __builtin_memcpy(&tuple.ipv4.saddr, key->source_addr, 4U);
        __builtin_memcpy(&tuple.ipv4.daddr, key->destination_addr, 4U);
        tuple.ipv4.sport = network_order16(key->source_port);
        tuple.ipv4.dport = network_order16(control->listener_port);
        tuple_size = sizeof(tuple.ipv4);
    } else {
        copy_address((__u8 *)&tuple.ipv6.saddr, key->source_addr, 16U);
        copy_address((__u8 *)&tuple.ipv6.daddr, key->destination_addr, 16U);
        tuple.ipv6.sport = network_order16(key->source_port);
        tuple.ipv6.dport = network_order16(control->listener_port);
        tuple_size = sizeof(tuple.ipv6);
    }
    return sk_lookup_udp(skb, &tuple, tuple_size, BPF_F_CURRENT_NETNS, 0U);
}

INLINE bool source_mac_equal(const __u8 left[6], const __u8 right[6]) {
    __u32 left_low, right_low;
    __u16 left_high, right_high;
    __builtin_memcpy(&left_low, left, 4U);
    __builtin_memcpy(&right_low, right, 4U);
    __builtin_memcpy(&left_high, left + 4U, 2U);
    __builtin_memcpy(&right_high, right + 4U, 2U);
    return left_low == right_low && left_high == right_high;
}

// The assign functions below steer a packet with sk_assign first and record its
// assignment after. A failed sk_assign drops only that packet, so it must leave
// the table alone: deleting the entry, as recording first then undoing did, took
// an unchanged assignment from a live flow on one transient failure, costing a
// pending TCP accept its original destination and a delivery flow its socket
// cookie. The packet reaches the socket only after the program returns, so the
// entry is still in place before anything reads it.
// Retire only a particular observed generation. New packets rebuild retired
// metadata; userspace never compare/deletes the kernel's current assignment.
INLINE bool assignment_retired(const struct sb_tc_assign_key *key, const struct sb_tc_assign_value *value) {
    if (value == 0 || value->generation == 0U) return false;
    struct sb_tc_retired_key identity = {.flow = *key, .generation = value->generation};
    return map_lookup(&tc_retired_assignment, &identity) != 0;
}

INLINE long store_assignment(const struct sb_tc_assign_key *key, struct sb_tc_assign_value *value) {
    value->generation = ktime_get_ns();
    value->last_seen_ns = value->generation;
    return map_update(&tc_assignment, key, value, BPF_ANY);
}

INLINE __u64 next_assignment_generation(const struct sb_tc_assign_value *previous) {
    __u64 now = ktime_get_ns();
    return previous != 0 && now <= previous->generation ? previous->generation + 1U : now;
}

#include "tc_isolation.h"

NOINLINE int assign_socket(struct __sk_buff *skb, const struct sb_tc_control *control,
    const struct sb_tc_assign_key *key, const __u8 source_mac[6], __u8 path) {
    bool source_mac_valid = (path & SB_TC_PATH_SOURCE_MAC_VALID) != 0U;
    path &= ~SB_TC_PATH_SOURCE_MAC_VALID;
    struct bpf_sock *socket = key->protocol == IPPROTO_TCP_VALUE
        ? lookup_tcp_socket(skb, key)
        : lookup_udp_socket(skb, control, key);
    if (socket == 0) {
        record_tc_stat(SB_TC_STAT_LISTENER_SOCKET_MISSING);
        return TC_ACT_SHOT;
    }
    struct sb_tc_assign_key assignment_key = *key;
    if (key->protocol == IPPROTO_UDP_VALUE && path == SB_TC_PATH_SHARED)
        assignment_key.interface_index = skb->ifindex;
    struct sb_tc_assign_value *existing = map_lookup(&tc_assignment, &assignment_key);
    struct sb_tc_assign_value value = {
        .socket_cookie = path == SB_TC_PATH_DELIVERY && existing != 0 ? existing->socket_cookie : 0U,
        .ifindex = skb->ifindex,
        .path = path,
        .source_mac_valid = source_mac_valid,
    };
    __builtin_memcpy(value.source_mac, source_mac, 6U);
    bool assignment_changed = existing == 0 || assignment_retired(&assignment_key, existing) || existing->socket_cookie != value.socket_cookie ||
        existing->ifindex != value.ifindex ||
        existing->path != value.path || existing->source_mac_valid != value.source_mac_valid;
    if (!assignment_changed && source_mac_valid) assignment_changed = !source_mac_equal(existing->source_mac, value.source_mac);
    long result = sk_assign(skb, socket, 0U);
    sk_release(socket);
    if (result != 0) {
        record_tc_stat(SB_TC_STAT_SK_ASSIGN_FAILED);
        return TC_ACT_SHOT;
    }
    if (assignment_changed && store_assignment(&assignment_key, &value) != 0) {
        record_tc_stat(SB_TC_STAT_ASSIGNMENT_UPDATE_FAILED);
        return TC_ACT_SHOT;
    }
    return TC_ACT_OK;
}

NOINLINE int assign_socket_legacy(struct __sk_buff *skb, const struct sb_tc_control *control,
    const struct sb_tc_assign_key *key, const __u8 source_mac[6], __u8 path) {
    bool source_mac_valid = (path & SB_TC_PATH_SOURCE_MAC_VALID) != 0U;
    path &= ~SB_TC_PATH_SOURCE_MAC_VALID;
    struct bpf_sock *socket = key->protocol == IPPROTO_TCP_VALUE
        ? lookup_tcp_socket_legacy(skb, control, key)
        : lookup_udp_socket(skb, control, key);
    if (socket == 0) {
        record_tc_stat(SB_TC_STAT_LISTENER_SOCKET_MISSING);
        return TC_ACT_SHOT;
    }
    struct sb_tc_assign_key assignment_key = *key;
    if (key->protocol == IPPROTO_UDP_VALUE && path == SB_TC_PATH_SHARED)
        assignment_key.interface_index = skb->ifindex;
    struct sb_tc_assign_value *existing = map_lookup(&tc_assignment, &assignment_key);
    struct sb_tc_assign_value value = {
        .socket_cookie = path == SB_TC_PATH_DELIVERY && existing != 0 ? existing->socket_cookie : 0U,
        .ifindex = skb->ifindex,
        .path = path,
        .source_mac_valid = source_mac_valid,
    };
    __builtin_memcpy(value.source_mac, source_mac, 6U);
    bool assignment_changed = existing == 0 || assignment_retired(&assignment_key, existing) || existing->socket_cookie != value.socket_cookie ||
        existing->ifindex != value.ifindex ||
        existing->path != value.path || existing->source_mac_valid != value.source_mac_valid;
    if (!assignment_changed && source_mac_valid) assignment_changed = !source_mac_equal(existing->source_mac, value.source_mac);
    long result = sk_assign(skb, socket, 0U);
    sk_release(socket);
    if (result != 0) {
        record_tc_stat(SB_TC_STAT_SK_ASSIGN_FAILED);
        return TC_ACT_SHOT;
    }
    if (assignment_changed && store_assignment(&assignment_key, &value) != 0) {
        record_tc_stat(SB_TC_STAT_ASSIGNMENT_UPDATE_FAILED);
        return TC_ACT_SHOT;
    }
    return TC_ACT_OK;
}

NOINLINE int assign_udp_socket(struct __sk_buff *skb, const struct sb_tc_control *control,
    const struct sb_tc_assign_key *key, const __u8 source_mac[6], __u8 path) {
    bool source_mac_valid = (path & SB_TC_PATH_SOURCE_MAC_VALID) != 0U;
    path &= ~SB_TC_PATH_SOURCE_MAC_VALID;
    struct bpf_sock *socket = lookup_udp_socket(skb, control, key);
    if (socket == 0) {
        record_tc_stat(SB_TC_STAT_LISTENER_SOCKET_MISSING);
        return TC_ACT_SHOT;
    }
    struct sb_tc_assign_key assignment_key = *key;
    assignment_key.interface_index = path == SB_TC_PATH_SHARED ? skb->ifindex : 0U;
    struct sb_tc_assign_value *existing = map_lookup(&tc_assignment, &assignment_key);
    struct sb_tc_assign_value value = {
        .socket_cookie = path == SB_TC_PATH_DELIVERY && existing != 0 ? existing->socket_cookie : 0U,
        .ifindex = skb->ifindex,
        .path = path,
        .source_mac_valid = source_mac_valid,
    };
    __builtin_memcpy(value.source_mac, source_mac, 6U);
    bool assignment_changed = existing == 0 || assignment_retired(&assignment_key, existing) || existing->socket_cookie != value.socket_cookie ||
        existing->ifindex != value.ifindex || existing->path != value.path ||
        existing->source_mac_valid != value.source_mac_valid;
    if (!assignment_changed && source_mac_valid) assignment_changed = !source_mac_equal(existing->source_mac, value.source_mac);
    long result = sk_assign(skb, socket, 0U);
    sk_release(socket);
    if (result != 0) {
        record_tc_stat(SB_TC_STAT_SK_ASSIGN_FAILED);
        return TC_ACT_SHOT;
    }
    if (assignment_changed && store_assignment(&assignment_key, &value) != 0) {
        record_tc_stat(SB_TC_STAT_ASSIGNMENT_UPDATE_FAILED);
        return TC_ACT_SHOT;
    }
    return TC_ACT_OK;
}

INLINE void record_local_socket_cookie(const struct sb_tc_assign_key *key, __u64 socket_cookie) {
    if (socket_cookie == 0U) return;
    struct sb_tc_assign_value *existing = map_lookup(&tc_assignment, key);
    if (existing != 0 && existing->socket_cookie == socket_cookie && !assignment_retired(key, existing)) return;
    struct sb_tc_assign_value value = {.socket_cookie = socket_cookie};
    store_assignment(key, &value);
}

INLINE int redirect_local(struct __sk_buff *skb, const struct sb_tc_control *control, bool ethernet) {
    if (ethernet) {
        if (skb_store_bytes(skb, 0U, control->delivery_mac, 6U, 0U) != 0) {
            record_tc_stat(SB_TC_STAT_DELIVERY_REWRITE_FAILED);
            return TC_ACT_UNSPEC;
        }
    } else {
        __be16 protocol = skb->protocol;
        if (skb_change_head(skb, sizeof(struct ethernet_header), 0U) != 0) {
            record_tc_stat(SB_TC_STAT_DELIVERY_REWRITE_FAILED);
            return TC_ACT_UNSPEC;
        }
        struct ethernet_header header = {.protocol = protocol};
        __builtin_memcpy(header.destination, control->delivery_mac, 6U);
        if (skb_store_bytes(skb, 0U, &header, sizeof(header), 0U) != 0) {
            record_tc_stat(SB_TC_STAT_DELIVERY_REWRITE_FAILED);
            return TC_ACT_SHOT;
        }
    }
    return redirect((int)control->delivery_ifindex, 0U);
}

INLINE int local_egress_mark(struct __sk_buff *skb, bool ethernet, bool track_process, bool isolated) {
    const struct sb_tc_control *control = load_control();
    if (control == 0 || control->enabled == 0U || control->delivery_ifindex == 0U) return TC_ACT_UNSPEC;
    if (skb->ingress_ifindex != 0U) return TC_ACT_UNSPEC;
    __u64 socket_cookie = get_socket_cookie(skb);
    __u32 socket_metadata_value = socket_metadata(socket_cookie);
    if ((socket_metadata_value & SB_EBPF_SOCKET_METADATA_SELF_BYPASS) != 0U) return TC_ACT_UNSPEC;
    struct sb_tc_assign_key key;
    __u8 source_mac[6];
    __u8 tcp_flag_byte = 0U;
    if (isolated) {
        if (parse_flow_extended(skb, control, SB_TC_FLAG_LOCAL_IPV6, ethernet, false, &key, source_mac, &tcp_flag_byte) != SB_TC_PARSE_FLOW) return TC_ACT_UNSPEC;
    } else if (!parse_flow(skb, control, SB_TC_FLAG_LOCAL_IPV6, ethernet, &key, source_mac)) {
        return TC_ACT_UNSPEC;
    }
    if (!local_selected(skb, control, &key, socket_metadata_value)) return TC_ACT_UNSPEC;
    if (isolated)
        return redirect_isolated(skb, control, &key, track_process ? socket_cookie : 0U,
            SB_TC_PATH_DELIVERY | (ethernet ? SB_TC_RETURN_ETHERNET : 0U) | assignment_record(&key, tcp_flag_byte));
    if (track_process) record_local_socket_cookie(&key, socket_cookie);
    return redirect_local(skb, control, ethernet);
}

SEC("classifier/local_egress_ethernet_mark")
int singbox_tc_local_egress_ethernet_mark(struct __sk_buff *skb) {
	return local_egress_mark(skb, true, false, false);
}

SEC("classifier/local_egress_raw_ip_mark")
int singbox_tc_local_egress_raw_ip_mark(struct __sk_buff *skb) {
	return local_egress_mark(skb, false, false, false);
}

SEC("classifier/local_egress_ethernet_process")
int singbox_tc_local_egress_ethernet_process(struct __sk_buff *skb) {
	return local_egress_mark(skb, true, true, false);
}

SEC("classifier/local_egress_raw_ip_process")
int singbox_tc_local_egress_raw_ip_process(struct __sk_buff *skb) {
	return local_egress_mark(skb, false, true, false);
}

INLINE int shared_ingress(struct __sk_buff *skb, bool ethernet, bool isolated) {
    const struct sb_tc_control *control = load_control();
    if (control == 0 || control->enabled == 0U) return TC_ACT_UNSPEC;
    struct sb_tc_assign_key key;
    __u8 source_mac[6];
    __u8 tcp_flag_byte = 0U;
    if (isolated) {
        if (parse_flow_extended(skb, control, SB_TC_FLAG_SHARED_IPV6, ethernet, true, &key, source_mac, &tcp_flag_byte) != SB_TC_PARSE_FLOW) return TC_ACT_UNSPEC;
    } else if (!parse_flow(skb, control, SB_TC_FLAG_SHARED_IPV6, ethernet, &key, source_mac)) {
        return TC_ACT_UNSPEC;
    }
    if (!ethernet &&
        (control->flags & (SB_TC_FLAG_INCLUDE_SOURCE_MAC | SB_TC_FLAG_EXCLUDE_SOURCE_MAC)) != 0U) {
        return TC_ACT_UNSPEC;
    }
    if (!shared_selected(control, &key, source_mac)) return TC_ACT_UNSPEC;
    if (isolated)
        return redirect_isolated(skb, control, &key, 0U, SB_TC_PATH_SHARED |
            (ethernet ? SB_TC_RETURN_ETHERNET : 0U) | assignment_record(&key, tcp_flag_byte));
    skb->mark |= control->routing_mark;
    __u8 path = SB_TC_PATH_SHARED;
    if (ethernet) path |= SB_TC_PATH_SOURCE_MAC_VALID;
    return assign_socket(skb, control, &key, source_mac, path);
}

SEC("classifier/shared_ingress_ethernet")
int singbox_tc_shared_ingress_ethernet(struct __sk_buff *skb) {
    return shared_ingress(skb, true, false);
}

SEC("classifier/shared_ingress_raw_ip")
int singbox_tc_shared_ingress_raw_ip(struct __sk_buff *skb) {
    return shared_ingress(skb, false, false);
}

INLINE int shared_ingress_legacy(struct __sk_buff *skb, bool ethernet, bool isolated) {
    const struct sb_tc_control *control = load_control();
    if (control == 0 || control->enabled == 0U) return TC_ACT_UNSPEC;
    struct sb_tc_assign_key key;
    __u8 source_mac[6];
    __u8 tcp_flag_byte = 0U;
    if (isolated) {
        if (parse_flow_extended(skb, control, SB_TC_FLAG_SHARED_IPV6, ethernet, true, &key, source_mac, &tcp_flag_byte) != SB_TC_PARSE_FLOW) return TC_ACT_UNSPEC;
    } else if (!parse_flow(skb, control, SB_TC_FLAG_SHARED_IPV6, ethernet, &key, source_mac)) {
        return TC_ACT_UNSPEC;
    }
    if (!ethernet &&
        (control->flags & (SB_TC_FLAG_INCLUDE_SOURCE_MAC | SB_TC_FLAG_EXCLUDE_SOURCE_MAC)) != 0U) {
        return TC_ACT_UNSPEC;
    }
    if (!shared_selected(control, &key, source_mac)) return TC_ACT_UNSPEC;
    if (isolated)
        return redirect_isolated(skb, control, &key, 0U, SB_TC_PATH_SHARED |
            (ethernet ? SB_TC_RETURN_ETHERNET : 0U) | assignment_record(&key, tcp_flag_byte));
    skb->mark |= control->routing_mark;
    __u8 path = SB_TC_PATH_SHARED;
    if (ethernet) path |= SB_TC_PATH_SOURCE_MAC_VALID;
    return assign_socket_legacy(skb, control, &key, source_mac, path);
}

SEC("classifier/shared_ingress_ethernet_legacy")
int singbox_tc_shared_ingress_ethernet_legacy(struct __sk_buff *skb) {
    return shared_ingress_legacy(skb, true, false);
}

SEC("classifier/shared_ingress_raw_ip_legacy")
int singbox_tc_shared_ingress_raw_ip_legacy(struct __sk_buff *skb) {
    return shared_ingress_legacy(skb, false, false);
}

INLINE int shared_ingress_udp(struct __sk_buff *skb, bool ethernet, bool isolated) {
    const struct sb_tc_control *control = load_control();
    if (control == 0 || control->enabled == 0U) return TC_ACT_UNSPEC;
    struct sb_tc_assign_key key;
    __u8 source_mac[6];
    __u8 tcp_flag_byte = 0U;
    if (isolated) {
        if (parse_flow_extended(skb, control, SB_TC_FLAG_SHARED_IPV6, ethernet, true, &key, source_mac, &tcp_flag_byte) != SB_TC_PARSE_FLOW) return TC_ACT_UNSPEC;
    } else if (!parse_flow(skb, control, SB_TC_FLAG_SHARED_IPV6, ethernet, &key, source_mac)) {
        return TC_ACT_UNSPEC;
    }
    if (!ethernet &&
        (control->flags & (SB_TC_FLAG_INCLUDE_SOURCE_MAC | SB_TC_FLAG_EXCLUDE_SOURCE_MAC)) != 0U) {
        return TC_ACT_UNSPEC;
    }
    if (!shared_selected(control, &key, source_mac)) return TC_ACT_UNSPEC;
    if (isolated)
        return redirect_isolated(skb, control, &key, 0U, SB_TC_PATH_SHARED |
            (ethernet ? SB_TC_RETURN_ETHERNET : 0U) | assignment_record(&key, tcp_flag_byte));
    skb->mark |= control->routing_mark;
    __u8 path = SB_TC_PATH_SHARED;
    if (ethernet) path |= SB_TC_PATH_SOURCE_MAC_VALID;
    return assign_udp_socket(skb, control, &key, source_mac, path);
}

SEC("classifier/shared_ingress_ethernet_udp")
int singbox_tc_shared_ingress_ethernet_udp(struct __sk_buff *skb) {
    return shared_ingress_udp(skb, true, false);
}

SEC("classifier/shared_ingress_raw_ip_udp")
int singbox_tc_shared_ingress_raw_ip_udp(struct __sk_buff *skb) {
    return shared_ingress_udp(skb, false, false);
}

SEC("classifier/delivery_ingress")
int singbox_tc_delivery_ingress(struct __sk_buff *skb) {
    const struct sb_tc_control *control = load_control();
    if (control == 0 || control->enabled == 0U) return TC_ACT_UNSPEC;
    struct sb_tc_assign_key key;
    __u8 source_mac[6];
    if (!parse_flow(skb, control, SB_TC_FLAG_LOCAL_IPV6, true, &key, source_mac)) return TC_ACT_UNSPEC;
    skb->mark |= control->routing_mark;
    return assign_socket(skb, control, &key, source_mac, SB_TC_PATH_DELIVERY);
}

SEC("classifier/delivery_ingress_legacy")
int singbox_tc_delivery_ingress_legacy(struct __sk_buff *skb) {
    const struct sb_tc_control *control = load_control();
    if (control == 0 || control->enabled == 0U) return TC_ACT_UNSPEC;
    struct sb_tc_assign_key key;
    __u8 source_mac[6];
    if (!parse_flow(skb, control, SB_TC_FLAG_LOCAL_IPV6, true, &key, source_mac)) return TC_ACT_UNSPEC;
    skb->mark |= control->routing_mark;
    return assign_socket_legacy(skb, control, &key, source_mac, SB_TC_PATH_DELIVERY);
}

SEC("classifier/delivery_ingress_udp")
int singbox_tc_delivery_ingress_udp(struct __sk_buff *skb) {
    const struct sb_tc_control *control = load_control();
    if (control == 0 || control->enabled == 0U) return TC_ACT_UNSPEC;
    struct sb_tc_assign_key key;
    __u8 source_mac[6];
    if (!parse_flow(skb, control, SB_TC_FLAG_LOCAL_IPV6, true, &key, source_mac)) return TC_ACT_UNSPEC;
    skb->mark |= control->routing_mark;
    return assign_udp_socket(skb, control, &key, source_mac, SB_TC_PATH_DELIVERY);
}

SEC("classifier/local_egress_ethernet_mark_isolated")
int sing_ebpf_local_egress_ethernet_mark_isolated(struct __sk_buff *skb) { return local_egress_mark(skb,true,false,true); }
SEC("classifier/local_egress_ethernet_process_isolated")
int sing_ebpf_local_egress_ethernet_process_isolated(struct __sk_buff *skb) { return local_egress_mark(skb,true,true,true); }
SEC("classifier/shared_ingress_ethernet_isolated")
int sing_ebpf_shared_ingress_ethernet_isolated(struct __sk_buff *skb) { return shared_ingress(skb,true,true); }
SEC("classifier/local_egress_raw_ip_mark_isolated")
int sing_ebpf_local_egress_raw_ip_mark_isolated(struct __sk_buff *skb) { return local_egress_mark(skb,false,false,true); }
SEC("classifier/local_egress_raw_ip_process_isolated")
int sing_ebpf_local_egress_raw_ip_process_isolated(struct __sk_buff *skb) { return local_egress_mark(skb,false,true,true); }
SEC("classifier/shared_ingress_raw_ip_isolated")
int sing_ebpf_shared_ingress_raw_ip_isolated(struct __sk_buff *skb) { return shared_ingress(skb,false,true); }

char _license[] SEC("license") = "GPL";
