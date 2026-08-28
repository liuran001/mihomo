#include "bpf_compat.h"

#include <linux/bpf.h>

#define AF_INET_VALUE 2U
#define AF_INET6_VALUE 10U
#define IPPROTO_TCP_VALUE 6U
#define SK_PASS 1

#define SB_SPLICE_STAT_REDIRECT_OK 0U
#define SB_SPLICE_STAT_REDIRECT_FAIL 1U
#define SB_SPLICE_STAT_PEER_MISS 2U
#define SB_SPLICE_STAT_KEY_ERROR 3U
#define SB_SPLICE_STAT_COUNT 4U

struct sb_splice_key {
    __u8 family;
    __u8 protocol;
    __u16 local_port;
    __u16 remote_port;
    __u16 reserved;
    __u8 local_addr[16];
    __u8 remote_addr[16];
};

struct sb_splice_peer {
    struct sb_splice_key key;
    __u64 bytes;
};

struct bpf_map_def SEC("maps") splice_sockets = {
    .type = BPF_MAP_TYPE_SOCKHASH,
    .key_size = sizeof(struct sb_splice_key),
    .value_size = sizeof(__u32),
    .max_entries = 8192U,
};

struct bpf_map_def SEC("maps") splice_peers = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct sb_splice_key),
    .value_size = sizeof(struct sb_splice_peer),
    .max_entries = 8192U,
};

struct bpf_map_def SEC("maps") splice_stats = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = SB_SPLICE_STAT_COUNT,
};

static void *(*map_lookup)(void *map, const void *key) = (void *)BPF_FUNC_map_lookup_elem;
static long (*sk_redirect_hash)(struct __sk_buff *skb, void *map, void *key, __u64 flags) =
    (void *)BPF_FUNC_sk_redirect_hash;

INLINE void record_splice_stat(__u32 key) {
    __u64 *counter = map_lookup(&splice_stats, &key);
    if (counter != 0) *counter += 1U;
}

INLINE __u16 network16_to_host(__u16 value) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return __builtin_bswap16(value);
#else
    return value;
#endif
}

INLINE int fill_splice_key(struct __sk_buff *skb, struct sb_splice_key *key) {
    __u32 family = skb->family;
    key->protocol = IPPROTO_TCP_VALUE;
    key->local_port = (__u16)skb->local_port;
    key->remote_port = network16_to_host((__u16)(skb->remote_port >> 16U));
    if (family == AF_INET_VALUE) {
        __u32 local = skb->local_ip4;
        __u32 remote = skb->remote_ip4;
        key->family = AF_INET_VALUE;
        __builtin_memcpy(key->local_addr, &local, 4U);
        __builtin_memcpy(key->remote_addr, &remote, 4U);
        return 0;
    }
    if (family == AF_INET6_VALUE) {
        key->family = AF_INET6_VALUE;
        __u32 local0 = skb->local_ip6[0];
        __u32 local1 = skb->local_ip6[1];
        __u32 local2 = skb->local_ip6[2];
        __u32 local3 = skb->local_ip6[3];
        __u32 remote0 = skb->remote_ip6[0];
        __u32 remote1 = skb->remote_ip6[1];
        __u32 remote2 = skb->remote_ip6[2];
        __u32 remote3 = skb->remote_ip6[3];
        __builtin_memcpy(key->local_addr, &local0, 4U);
        __builtin_memcpy(key->local_addr + 4U, &local1, 4U);
        __builtin_memcpy(key->local_addr + 8U, &local2, 4U);
        __builtin_memcpy(key->local_addr + 12U, &local3, 4U);
        __builtin_memcpy(key->remote_addr, &remote0, 4U);
        __builtin_memcpy(key->remote_addr + 4U, &remote1, 4U);
        __builtin_memcpy(key->remote_addr + 8U, &remote2, 4U);
        __builtin_memcpy(key->remote_addr + 12U, &remote3, 4U);
        return 0;
    }
    return -1;
}

SEC("sk_skb/stream_parser")
int singbox_splice_parser(struct __sk_buff *skb) {
    return skb->len;
}

SEC("sk_skb/stream_verdict")
int singbox_splice_verdict(struct __sk_buff *skb) {
    struct sb_splice_key self = {};
    if (fill_splice_key(skb, &self) != 0) {
        record_splice_stat(SB_SPLICE_STAT_KEY_ERROR);
        return SK_PASS;
    }
    struct sb_splice_peer *peer = map_lookup(&splice_peers, &self);
    if (peer == 0) {
        record_splice_stat(SB_SPLICE_STAT_PEER_MISS);
        return SK_PASS;
    }
    __sync_fetch_and_add(&peer->bytes, skb->len);
    long result = sk_redirect_hash(skb, &splice_sockets, &peer->key, 0U);
    record_splice_stat(result == SK_PASS ? SB_SPLICE_STAT_REDIRECT_OK : SB_SPLICE_STAT_REDIRECT_FAIL);
    return (int)result;
}

char _license[] SEC("license") = "GPL";
