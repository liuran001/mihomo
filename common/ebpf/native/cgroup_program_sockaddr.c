// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

// Included by cgroup_program.c. Connect and UDP sendmsg program builders.

static int load_sock_addr_program(
    struct bpf_builder *builder,
    const size_t *bypass_jumps,
    size_t bypass_jump_count,
    const size_t *allow_jumps,
    size_t allow_jump_count,
    const size_t *drop_jumps,
    size_t drop_jump_count,
    enum bpf_attach_type attach_type,
    const char *name,
    bool log_error) {
    size_t allow_label = emit_exit(builder, 1);
    size_t drop_label = emit_exit(builder, 0);
    patch_jumps(builder, bypass_jumps, bypass_jump_count, allow_label);
    patch_jumps(builder, allow_jumps, allow_jump_count, allow_label);
    patch_jumps(builder, drop_jumps, drop_jump_count, drop_label);
    if (builder->overflow) {
        errno = EMSGSIZE;
        return -1;
    }
    return sb_ebpf_load_prog(
        builder->insns,
        builder->count,
        name,
        BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
        attach_type,
        log_error);
}

static int build_ipv4_sock_addr_prog(
    const struct sb_ebpf_cgroup_config *config,
    uint32_t self_tgid,
    const struct sb_ebpf_cgroup_program_maps *maps,
    uint8_t protocol,
    bool protocol_from_context,
    uint16_t listen_port,
    enum bpf_attach_type attach_type,
    const char *name,
    bool log_error) {
    struct bpf_builder b = {0};
    size_t bypass_jumps[96];
    size_t bypass_jump_count = 0;
    size_t drop_jumps[16];
    size_t drop_jump_count = 0;
    size_t allow_jumps[16];
    size_t allow_jump_count = 0;
    size_t udp_cidr_bypass_jumps[2];
    size_t udp_cidr_bypass_jump_count = 0;

    emit_sock_addr_prologue(
        &b,
        config,
        self_tgid,
        maps->bypass_socket_cookie,
        maps->include_uid,
        maps->exclude_uid,
        protocol,
        protocol_from_context,
        bypass_jumps,
        &bypass_jump_count);
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip4)));
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_6, offsetof(struct bpf_sock_addr, user_port)));
    emit_dns_off_bypass(
        &b, config, protocol, protocol_from_context, BPF_REG_8,
        bypass_jumps, &bypass_jump_count);
    emit_udp_system_service_bypass(
        &b, protocol, protocol_from_context, BPF_REG_8, bypass_jumps, &bypass_jump_count);
    // Connected UDP send() may not hit UDP_SENDMSG on Android kernels, so CONNECT must continue interception.
    // This can expose the redirect peer via getpeername(), but it avoids direct UDP leakage.
    if (attach_type == BPF_CGROUP_INET4_CONNECT && protocol_from_context) {
        emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_6, offsetof(struct bpf_sock_addr, protocol)));
        size_t tcp_connect = emit_jump(&b, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_2, SB_EBPF_PROTO_TCP, 0));
        bypass_jumps[bypass_jump_count++] =
            emit_jump(&b, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_2, SB_EBPF_PROTO_UDP, 0));
        emit_udp_connected_state_reset(
            &b, maps->udp_redirect, maps->udp_token, maps->udp_peer);
        emit_udp_peer_cache_update(&b, maps->udp_peer, false, bypass_jumps, &bypass_jump_count);
        patch_jump(&b, tcp_connect, b.count);
    }
    if (attach_type == BPF_CGROUP_UDP4_SENDMSG && protocol == SB_EBPF_PROTO_UDP && !protocol_from_context) {
        emit_udp_connected_token_restore_v4(
            &b, maps->udp_token, listen_port, allow_jumps, &allow_jump_count);
        emit_udp_flow_cache_restore_v4(
            &b, maps->udp_flow, listen_port, config->udp_timeout_seconds, false,
            allow_jumps, &allow_jump_count);
        emit_udp_peer_cache_restore_v4(&b, maps->udp_peer);
    }
    size_t dns_hijack_jumps[2];
    size_t dns_hijack_jump_count = 0;
    emit_dns_hijack_jumps(
        &b, config, protocol, protocol_from_context, BPF_REG_8,
        dns_hijack_jumps, &dns_hijack_jump_count);
    emit_ipv4_destination_bypass(&b, bypass_jumps, &bypass_jump_count);
    bool cache_udp_cidr_bypass =
        attach_type == BPF_CGROUP_UDP4_SENDMSG &&
        protocol == SB_EBPF_PROTO_UDP &&
        !protocol_from_context &&
        maps->udp_flow >= 0;
    emit_ipv4_cidr_bypass(
        &b,
        maps->bypass_ipv4_cidr,
        BPF_REG_7,
        cache_udp_cidr_bypass ? udp_cidr_bypass_jumps : bypass_jumps,
        cache_udp_cidr_bypass ? &udp_cidr_bypass_jump_count : &bypass_jump_count);
    if (udp_cidr_bypass_jump_count > 0U) {
        size_t continue_interception = emit_jump(&b, BPF_JMP_IMM_OP(BPF_JA, 0, 0, 0));
        size_t cache_bypass = b.count;
        emit_udp_flow_bypass_cache_update_v4(&b, maps->udp_flow, false);
        allow_jumps[allow_jump_count++] = emit_jump(&b, BPF_JMP_IMM_OP(BPF_JA, 0, 0, 0));
        patch_jumps(&b, udp_cidr_bypass_jumps, udp_cidr_bypass_jump_count, cache_bypass);
        patch_jump(&b, continue_interception, b.count);
    }
    patch_jumps(&b, dns_hijack_jumps, dns_hijack_jump_count, b.count);
    emit_redirect_update_and_rewrite_by_protocol(
        &b,
        config,
        maps->tcp_redirect,
        maps->udp_redirect,
        maps->udp_token,
        maps->udp_flow,
        protocol,
        protocol_from_context,
        listen_port,
        drop_jumps,
        &drop_jump_count);
    return load_sock_addr_program(
        &b,
        bypass_jumps,
        bypass_jump_count,
        allow_jumps,
        allow_jump_count,
        drop_jumps,
        drop_jump_count,
        attach_type,
        name,
        log_error);
}

static int build_ipv6_sock_addr_prog(
    const struct sb_ebpf_cgroup_config *config,
    uint32_t self_tgid,
    const struct sb_ebpf_cgroup_program_maps *maps,
    uint8_t protocol,
    bool protocol_from_context,
    uint16_t listen_port,
    enum bpf_attach_type attach_type,
    const char *name,
    bool log_error) {
    struct bpf_builder b = {0};
    size_t bypass_jumps[96];
    size_t bypass_jump_count = 0;
    size_t drop_jumps[16];
    size_t drop_jump_count = 0;
    size_t allow_jumps[16];
    size_t allow_jump_count = 0;
    size_t udp_cidr_bypass_jumps[2];
    size_t udp_cidr_bypass_jump_count = 0;

    emit_sock_addr_prologue(
        &b,
        config,
        self_tgid,
        maps->bypass_socket_cookie,
        maps->include_uid,
        maps->exclude_uid,
        protocol,
        protocol_from_context,
        bypass_jumps,
        &bypass_jump_count);
    emit_ipv6_sock_addr_destination(&b);
    emit_dns_off_bypass(
        &b, config, protocol, protocol_from_context, BPF_REG_5,
        bypass_jumps, &bypass_jump_count);
    emit_udp_system_service_bypass(
        &b, protocol, protocol_from_context, BPF_REG_5, bypass_jumps, &bypass_jump_count);
    if (attach_type == BPF_CGROUP_UDP6_SENDMSG && protocol == SB_EBPF_PROTO_UDP && !protocol_from_context) {
        emit_udp_connected_token_restore_v6(
            &b, maps->udp_token, listen_port, allow_jumps, &allow_jump_count);
        emit_udp_flow_cache_restore_v6(
            &b, maps->udp_flow, listen_port, config->udp_timeout_seconds,
            allow_jumps, &allow_jump_count);
    }
    bool emitted_v4mapped_branch = false;
    if (config->disable_ipv4) {
        size_t not_mapped_jumps[3];
        size_t not_mapped_jump_count = 0;
        emit_ipv4_mapped_ipv6_check_jumps(&b, not_mapped_jumps, &not_mapped_jump_count);
        allow_jumps[allow_jump_count++] = emit_jump(&b, BPF_JMP_IMM_OP(BPF_JA, 0, 0, 0));
        patch_jumps(&b, not_mapped_jumps, not_mapped_jump_count, b.count);
    } else {
        emitted_v4mapped_branch = emit_ipv4_mapped_ipv6_branch(
            &b,
            config,
            maps->tcp_redirect,
            maps->udp_redirect,
            maps->udp_token,
            maps->udp_flow,
            maps->udp_peer,
            maps->bypass_ipv4_cidr,
            protocol,
            protocol_from_context,
            listen_port,
            attach_type,
            bypass_jumps,
            &bypass_jump_count,
            drop_jumps,
            &drop_jump_count,
            allow_jumps,
            &allow_jump_count);
    }
    if (emitted_v4mapped_branch) {
        emit_ipv6_sock_addr_destination(&b);
    }
    if (maps->ipv6_available >= 0) {
        emit_ipv6_availability_bypass(
            &b, maps->ipv6_available, bypass_jumps, &bypass_jump_count);
        // map_lookup_elem() invalidates R1-R5. Restore the destination registers
        // used by the common native IPv6 path after the availability lookup.
        emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_4, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 12));
        emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_5, BPF_REG_6, offsetof(struct bpf_sock_addr, user_port)));
    }
    // Connected UDP send() may not hit UDP_SENDMSG on Android kernels. Rewrite at CONNECT so all
    // packets reach the inbound listener; UDP6_SENDMSG remains a fallback for sendmsg() callers.
    if (attach_type == BPF_CGROUP_INET6_CONNECT && protocol_from_context) {
        emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_6, offsetof(struct bpf_sock_addr, protocol)));
        size_t tcp_connect = emit_jump(&b, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_2, SB_EBPF_PROTO_TCP, 0));
        bypass_jumps[bypass_jump_count++] =
            emit_jump(&b, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_2, SB_EBPF_PROTO_UDP, 0));
        emit_udp_connected_state_reset(
            &b, maps->udp_redirect, maps->udp_token, maps->udp_peer);
        emit_udp_peer_cache_update(&b, maps->udp_peer, true, bypass_jumps, &bypass_jump_count);
        // map_update_elem() invalidates R1-R5. Reload the destination before the common
        // IPv6 interception path reads the address and port registers.
        emit_ipv6_sock_addr_destination(&b);
        patch_jump(&b, tcp_connect, b.count);
    }
    if (attach_type == BPF_CGROUP_UDP6_SENDMSG && protocol == SB_EBPF_PROTO_UDP && !protocol_from_context) {
        emit_udp_peer_cache_restore_v6(&b, maps->udp_peer);
    }
    size_t dns_hijack_jumps[2];
    size_t dns_hijack_jump_count = 0;
    emit_dns_hijack_jumps(
        &b, config, protocol, protocol_from_context, BPF_REG_5,
        dns_hijack_jumps, &dns_hijack_jump_count);
    emit_ipv6_destination_bypass(&b, bypass_jumps, &bypass_jump_count);
    bool cache_udp_cidr_bypass =
        attach_type == BPF_CGROUP_UDP6_SENDMSG &&
        protocol == SB_EBPF_PROTO_UDP &&
        !protocol_from_context &&
        maps->udp_flow >= 0;
    emit_ipv6_cidr_bypass(
        &b,
        maps->bypass_ipv6_cidr,
        cache_udp_cidr_bypass ? udp_cidr_bypass_jumps : bypass_jumps,
        cache_udp_cidr_bypass ? &udp_cidr_bypass_jump_count : &bypass_jump_count);
    if (udp_cidr_bypass_jump_count > 0U) {
        size_t continue_interception = emit_jump(&b, BPF_JMP_IMM_OP(BPF_JA, 0, 0, 0));
        size_t cache_bypass = b.count;
        emit_udp_flow_bypass_cache_update_v6(&b, maps->udp_flow);
        allow_jumps[allow_jump_count++] = emit_jump(&b, BPF_JMP_IMM_OP(BPF_JA, 0, 0, 0));
        patch_jumps(&b, udp_cidr_bypass_jumps, udp_cidr_bypass_jump_count, cache_bypass);
        patch_jump(&b, continue_interception, b.count);
    }
    patch_jumps(&b, dns_hijack_jumps, dns_hijack_jump_count, b.count);
    emit_redirect_update_and_rewrite_v6_by_protocol(
        &b,
        config,
        maps->tcp_redirect,
        maps->udp_redirect,
        maps->udp_token,
        maps->udp_flow,
        protocol,
        protocol_from_context,
        listen_port,
        drop_jumps,
        &drop_jump_count);
    return load_sock_addr_program(
        &b,
        bypass_jumps,
        bypass_jump_count,
        allow_jumps,
        allow_jump_count,
        drop_jumps,
        drop_jump_count,
        attach_type,
        name,
        log_error);
}

static int build_ipv4_mapped_ipv6_sock_addr_prog(
    const struct sb_ebpf_cgroup_config *config,
    uint32_t self_tgid,
    const struct sb_ebpf_cgroup_program_maps *maps,
    uint8_t protocol,
    bool protocol_from_context,
    uint16_t listen_port,
    enum bpf_attach_type attach_type,
    const char *name,
    bool log_error) {
    struct bpf_builder b = {0};
    size_t bypass_jumps[96];
    size_t bypass_jump_count = 0;
    size_t drop_jumps[16];
    size_t drop_jump_count = 0;
    size_t allow_jumps[16];
    size_t allow_jump_count = 0;

    emit_sock_addr_prologue(
        &b,
        config,
        self_tgid,
        maps->bypass_socket_cookie,
        maps->include_uid,
        maps->exclude_uid,
        protocol,
        protocol_from_context,
        bypass_jumps,
        &bypass_jump_count);
    emit_ipv6_sock_addr_destination(&b);
    emit_dns_off_bypass(
        &b, config, protocol, protocol_from_context, BPF_REG_5,
        bypass_jumps, &bypass_jump_count);
    emit_udp_system_service_bypass(
        &b, protocol, protocol_from_context, BPF_REG_5, bypass_jumps, &bypass_jump_count);
    if (attach_type == BPF_CGROUP_UDP6_SENDMSG && protocol == SB_EBPF_PROTO_UDP && !protocol_from_context) {
        emit_udp_connected_token_restore_v6(
            &b, maps->udp_token, listen_port, allow_jumps, &allow_jump_count);
        emit_udp_flow_cache_restore_v6(
            &b, maps->udp_flow, listen_port, config->udp_timeout_seconds,
            allow_jumps, &allow_jump_count);
    }
    (void)emit_ipv4_mapped_ipv6_branch(
        &b,
        config,
        maps->tcp_redirect,
        maps->udp_redirect,
        maps->udp_token,
        maps->udp_flow,
        maps->udp_peer,
        maps->bypass_ipv4_cidr,
        protocol,
        protocol_from_context,
        listen_port,
        attach_type,
        bypass_jumps,
        &bypass_jump_count,
        drop_jumps,
        &drop_jump_count,
        allow_jumps,
        &allow_jump_count);
    return load_sock_addr_program(
        &b,
        bypass_jumps,
        bypass_jump_count,
        allow_jumps,
        allow_jump_count,
        drop_jumps,
        drop_jump_count,
        attach_type,
        name,
        log_error);
}
