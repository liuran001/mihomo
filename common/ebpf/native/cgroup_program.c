// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

// Included by cgroup.c to keep the native cgroup backend in one translation unit.

struct sb_ebpf_cgroup_program_maps {
    int include_uid;
    int exclude_uid;
    int tcp_redirect;
    int udp_redirect;
    int udp_token;
    int udp_flow;
    int udp_peer;
    int bypass_socket_cookie;
    int bypass_ipv4_cidr;
    int bypass_ipv6_cidr;
    int ipv6_available;
};

#include "cgroup_program_emit.c"
#include "cgroup_program_udp.c"
#include "cgroup_program_redirect.c"
#include "cgroup_program_sockaddr.c"
#include "cgroup_program_recvmsg.c"

enum sb_ebpf_cgroup_program_kind {
    SB_EBPF_CGROUP_PROGRAM_IPV4_SOCK_ADDR,
    SB_EBPF_CGROUP_PROGRAM_IPV6_SOCK_ADDR,
    SB_EBPF_CGROUP_PROGRAM_IPV4_MAPPED_SOCK_ADDR,
    SB_EBPF_CGROUP_PROGRAM_UDP4_RECVMSG,
    SB_EBPF_CGROUP_PROGRAM_UDP6_RECVMSG,
};

struct sb_ebpf_cgroup_program_spec {
    enum sb_ebpf_cgroup_program_kind kind;
    bool enabled;
    uint8_t protocol;
    bool protocol_from_context;
    struct sb_ebpf_program_descriptor program;
};

static int build_cgroup_program(
    const struct sb_ebpf_cgroup_program_spec *spec,
    const struct sb_ebpf_cgroup_config *config,
    const struct sb_ebpf_cgroup_program_maps *maps,
    uint32_t self_tgid,
    uint16_t listen_port,
    bool log_error) {
    switch (spec->kind) {
    case SB_EBPF_CGROUP_PROGRAM_IPV4_SOCK_ADDR:
        return build_ipv4_sock_addr_prog(
            config,
            self_tgid,
            maps,
            spec->protocol,
            spec->protocol_from_context,
            listen_port,
            spec->program.attach_type,
            spec->program.name,
            log_error);
    case SB_EBPF_CGROUP_PROGRAM_IPV6_SOCK_ADDR:
        return build_ipv6_sock_addr_prog(
            config,
            self_tgid,
            maps,
            spec->protocol,
            spec->protocol_from_context,
            listen_port,
            spec->program.attach_type,
            spec->program.name,
            log_error);
    case SB_EBPF_CGROUP_PROGRAM_IPV4_MAPPED_SOCK_ADDR:
        return build_ipv4_mapped_ipv6_sock_addr_prog(
            config,
            self_tgid,
            maps,
            spec->protocol,
            spec->protocol_from_context,
            listen_port,
            spec->program.attach_type,
            spec->program.name,
            log_error);
    case SB_EBPF_CGROUP_PROGRAM_UDP4_RECVMSG:
        return build_udp4_recvmsg_prog(config, maps->udp_redirect, spec->program.name);
    case SB_EBPF_CGROUP_PROGRAM_UDP6_RECVMSG:
        return build_udp6_recvmsg_prog(config, maps->udp_redirect, spec->program.name);
    default:
        errno = EINVAL;
        return -1;
    }
}

static bool runtime_has_programs(const struct sb_ebpf_cgroup_runtime *runtime) {
    return runtime->connect4_prog_fd >= 0 || runtime->connect6_prog_fd >= 0 ||
        runtime->connect6_v4mapped_prog_fd >= 0 || runtime->udp4_sendmsg_prog_fd >= 0 ||
        runtime->udp6_sendmsg_prog_fd >= 0 || runtime->udp6_v4mapped_sendmsg_prog_fd >= 0 ||
        runtime->udp4_recvmsg_prog_fd >= 0 || runtime->udp6_recvmsg_prog_fd >= 0 ||
        runtime->udp6_v4mapped_recvmsg_prog_fd >= 0 || runtime->socket_release_prog_fd >= 0;
}

static void close_runtime_programs(struct sb_ebpf_cgroup_runtime *runtime) {
    int *program_fds[] = {
        &runtime->socket_release_prog_fd,
        &runtime->udp6_v4mapped_recvmsg_prog_fd,
        &runtime->udp6_recvmsg_prog_fd,
        &runtime->udp4_recvmsg_prog_fd,
        &runtime->udp6_v4mapped_sendmsg_prog_fd,
        &runtime->udp6_sendmsg_prog_fd,
        &runtime->udp4_sendmsg_prog_fd,
        &runtime->connect6_v4mapped_prog_fd,
        &runtime->connect6_prog_fd,
        &runtime->connect4_prog_fd,
    };
    (void)sb_ebpf_close_fds(program_fds, ARRAY_SIZE(program_fds));
}

static int load_cgroup_program_set(
    struct sb_ebpf_cgroup_runtime *runtime,
    uint16_t listen_port,
    uint32_t self_tgid,
    bool enable_ipv4,
    bool hijack_dns,
    uint32_t udp_timeout_seconds,
    const uint8_t redirect_ipv4[4],
    uint32_t redirect_ipv4_prefix_bits,
    bool enable_ipv6,
    const uint8_t redirect_ipv6[16],
    uint32_t redirect_ipv6_prefix_bits,
    bool log_error) {
    if (runtime == NULL || runtime->cgroup_fd < 0 || listen_port == 0U ||
        (!enable_ipv4 && !enable_ipv6) ||
        (enable_ipv4 && (redirect_ipv4 == NULL ||
                         redirect_ipv4_prefix_bits < 8U ||
                         redirect_ipv4_prefix_bits > 10U)) ||
        (enable_ipv6 && (redirect_ipv6 == NULL || redirect_ipv6_prefix_bits != 64U))) {
        errno = EINVAL;
        return -1;
    }
    if (runtime_has_programs(runtime)) {
        errno = EALREADY;
        return -1;
    }

    bool enable_tcp = runtime->tcp_redirect_map_fd >= 0;
    bool enable_udp = runtime->udp_redirect_map_fd >= 0;
    if (enable_udp && udp_timeout_seconds == 0U) {
        errno = EINVAL;
        return -1;
    }
    int sockaddr_bypass_socket_cookie_map_fd = self_tgid == 0U
        ? runtime->bypass_socket_cookie_map_fd
        : -1;
    const struct sb_ebpf_cgroup_program_maps maps = {
        .include_uid = runtime->include_uid_map_fd,
        .exclude_uid = runtime->exclude_uid_map_fd,
        .tcp_redirect = runtime->tcp_redirect_map_fd,
        .udp_redirect = runtime->udp_redirect_map_fd,
        .udp_token = runtime->udp_token_map_fd,
        .udp_flow = runtime->udp_flow_map_fd,
        .udp_peer = runtime->udp_peer_map_fd,
        .bypass_socket_cookie = sockaddr_bypass_socket_cookie_map_fd,
        .bypass_ipv4_cidr = runtime->bypass_ipv4_cidr_map_fd,
        .bypass_ipv6_cidr = runtime->bypass_ipv6_cidr_map_fd,
        .ipv6_available = runtime->ipv6_available_map_fd,
    };
    struct sb_ebpf_cgroup_config config;
    memset(&config, 0, sizeof(config));
    config.inbound_network =
        (enable_tcp ? SB_EBPF_NETWORK_TCP : 0U) |
        (enable_udp ? SB_EBPF_NETWORK_UDP : 0U);
    config.disable_ipv4 = !enable_ipv4;
    config.hijack_dns = hijack_dns;
    config.udp_timeout_seconds = udp_timeout_seconds;
    if (enable_ipv4) {
        memcpy(config.redirect_ipv4_prefix, redirect_ipv4, sizeof(config.redirect_ipv4_prefix));
        config.redirect_ipv4_prefix_bits = redirect_ipv4_prefix_bits;
    }
    if (enable_ipv6) {
        memcpy(config.redirect_ipv6_prefix, redirect_ipv6, sizeof(config.redirect_ipv6_prefix));
        config.redirect_ipv6_prefix_bits = redirect_ipv6_prefix_bits;
    }

    struct sb_ebpf_cgroup_program_spec programs[] = {
        {SB_EBPF_CGROUP_PROGRAM_IPV4_SOCK_ADDR, enable_ipv4, SB_EBPF_PROTO_TCP, true,
         {"sb_ebpf_conn4", BPF_PROG_TYPE_CGROUP_SOCK_ADDR, BPF_CGROUP_INET4_CONNECT,
          &runtime->connect4_prog_fd}},
        {SB_EBPF_CGROUP_PROGRAM_IPV4_SOCK_ADDR, enable_ipv4 && enable_udp, SB_EBPF_PROTO_UDP, false,
         {"sb_ebpf_udp4", BPF_PROG_TYPE_CGROUP_SOCK_ADDR, BPF_CGROUP_UDP4_SENDMSG,
          &runtime->udp4_sendmsg_prog_fd}},
        {SB_EBPF_CGROUP_PROGRAM_UDP4_RECVMSG, enable_ipv4 && enable_udp, 0U, false,
         {"sb_ebpf_urcv4", BPF_PROG_TYPE_CGROUP_SOCK_ADDR, BPF_CGROUP_UDP4_RECVMSG,
          &runtime->udp4_recvmsg_prog_fd}},
        {SB_EBPF_CGROUP_PROGRAM_IPV6_SOCK_ADDR, enable_ipv6, SB_EBPF_PROTO_TCP, true,
         {"sb_ebpf_conn6", BPF_PROG_TYPE_CGROUP_SOCK_ADDR, BPF_CGROUP_INET6_CONNECT,
          &runtime->connect6_prog_fd}},
        {SB_EBPF_CGROUP_PROGRAM_IPV6_SOCK_ADDR, enable_ipv6 && enable_udp, SB_EBPF_PROTO_UDP, false,
         {"sb_ebpf_udp6", BPF_PROG_TYPE_CGROUP_SOCK_ADDR, BPF_CGROUP_UDP6_SENDMSG,
          &runtime->udp6_sendmsg_prog_fd}},
        {SB_EBPF_CGROUP_PROGRAM_UDP6_RECVMSG, enable_ipv6 && enable_udp, 0U, false,
         {"sb_ebpf_urcv6", BPF_PROG_TYPE_CGROUP_SOCK_ADDR, BPF_CGROUP_UDP6_RECVMSG,
          &runtime->udp6_recvmsg_prog_fd}},
        {SB_EBPF_CGROUP_PROGRAM_IPV4_MAPPED_SOCK_ADDR, !enable_ipv6, SB_EBPF_PROTO_TCP, true,
         {"sb_ebpf_c6v4m", BPF_PROG_TYPE_CGROUP_SOCK_ADDR, BPF_CGROUP_INET6_CONNECT,
          &runtime->connect6_v4mapped_prog_fd}},
        {SB_EBPF_CGROUP_PROGRAM_IPV4_MAPPED_SOCK_ADDR, !enable_ipv6 && enable_udp,
         SB_EBPF_PROTO_UDP, false,
         {"sb_ebpf_u6v4m", BPF_PROG_TYPE_CGROUP_SOCK_ADDR, BPF_CGROUP_UDP6_SENDMSG,
          &runtime->udp6_v4mapped_sendmsg_prog_fd}},
        {SB_EBPF_CGROUP_PROGRAM_UDP6_RECVMSG, !enable_ipv6 && enable_udp, 0U, false,
         {"sb_ebpf_ur6v4m", BPF_PROG_TYPE_CGROUP_SOCK_ADDR, BPF_CGROUP_UDP6_RECVMSG,
          &runtime->udp6_v4mapped_recvmsg_prog_fd}},
    };
    bool program_load_failed = false;
    for (size_t index = 0; index < ARRAY_SIZE(programs); ++index) {
        struct sb_ebpf_cgroup_program_spec *program = &programs[index];
        if (!program->enabled) continue;
        *program->program.fd = build_cgroup_program(
            program,
            &config,
            &maps,
            self_tgid,
            listen_port,
            log_error);
        if (*program->program.fd < 0) {
            sb_ebpf_set_error_stage(runtime->error_stage, program->program.name);
            program_load_failed = true;
        }
    }
    if (enable_udp && runtime->socket_release_supported) {
        runtime->socket_release_prog_fd = build_socket_release_prog(
            runtime->udp_redirect_map_fd,
            runtime->udp_token_map_fd,
            runtime->udp_peer_map_fd,
            runtime->bypass_socket_cookie_map_fd,
            "sb_ebpf_rel");
        if (runtime->socket_release_prog_fd < 0) {
            sb_ebpf_set_error_stage(runtime->error_stage, "sb_ebpf_rel");
        }
    }
    if (program_load_failed ||
        (enable_udp && runtime->socket_release_supported &&
         runtime->socket_release_prog_fd < 0)) {
        goto load_fail;
    }
    sb_ebpf_set_error_stage(runtime->error_stage, NULL);
    return 0;

load_fail:
    {
        int saved = errno;
        close_runtime_programs(runtime);
        errno = saved;
    }
    return -1;
}

int sb_ebpf_cgroup_load_programs(
    struct sb_ebpf_cgroup_runtime *runtime,
    uint16_t listen_port,
    uint32_t self_tgid,
    bool enable_ipv4,
    bool hijack_dns,
    uint32_t udp_timeout_seconds,
    const uint8_t redirect_ipv4[4],
    uint32_t redirect_ipv4_prefix_bits,
    bool enable_ipv6,
    const uint8_t redirect_ipv6[16],
    uint32_t redirect_ipv6_prefix_bits) {
    bool try_tgid = self_tgid != 0U;
    if (!try_tgid) {
        sb_ebpf_set_error_stage(runtime->error_stage, "socket bypass map");
        runtime->bypass_socket_cookie_map_fd = create_bypass_socket_cookie_map(
            runtime->socket_bypass_map_capacity);
        if (runtime->bypass_socket_cookie_map_fd < 0) goto load_fail;
    }
    if (load_cgroup_program_set(
            runtime,
            listen_port,
            self_tgid,
            enable_ipv4,
            hijack_dns,
            udp_timeout_seconds,
            redirect_ipv4,
            redirect_ipv4_prefix_bits,
            enable_ipv6,
            redirect_ipv6,
            redirect_ipv6_prefix_bits,
            !try_tgid) == 0) {
        runtime->self_bypass_tgid = try_tgid;
        return 0;
    }
    if (try_tgid) {
        sb_ebpf_set_error_stage(runtime->error_stage, "socket bypass fallback map");
        runtime->bypass_socket_cookie_map_fd = create_bypass_socket_cookie_map(
            runtime->socket_bypass_map_capacity);
        if (runtime->bypass_socket_cookie_map_fd < 0) goto load_fail;
    }
    if (try_tgid && load_cgroup_program_set(
            runtime,
            listen_port,
            0U,
            enable_ipv4,
            hijack_dns,
            udp_timeout_seconds,
            redirect_ipv4,
            redirect_ipv4_prefix_bits,
            enable_ipv6,
            redirect_ipv6,
            redirect_ipv6_prefix_bits,
            true) == 0) {
        runtime->self_bypass_tgid = false;
        return 0;
    }
load_fail:
    {
        int saved = errno;
        (void)sb_ebpf_cgroup_close(runtime);
        errno = saved;
    }
    return -1;
}
