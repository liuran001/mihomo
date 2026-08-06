// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

// Included by cgroup_program.c. UDP peer and connected-socket state emitters.

#define UDP_FLOW_LISTENER_OFFSET(MEMBER) \
    (offsetof(struct sb_ebpf_udp_flow_value, listener) + \
     offsetof(struct sb_ebpf_listener_key, MEMBER))

static void emit_connected_udp_original_flag(
    struct bpf_builder *builder,
    bool connected_udp) {
    if (!connected_udp) return;
    emit(builder, BPF_ST_MEM(
        BPF_B,
        BPF_REG_10,
        STACK_ORIGINAL_DST + (int)offsetof(struct sb_ebpf_original_dst, flags),
        SB_EBPF_ORIGINAL_DST_FLAG_CONNECTED_UDP));
}

static void emit_udp_peer_cache_update_v4(
    struct bpf_builder *builder,
    int udp_peer_map_fd,
    int address_offset,
    size_t *bypass_jumps,
    size_t *bypass_jump_count) {
    if (udp_peer_map_fd < 0) return;

    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_6, address_offset));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_6, offsetof(struct bpf_sock_addr, user_port)));
    bypass_jumps[(*bypass_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_7, 0, 0));
    bypass_jumps[(*bypass_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_8, 0, 0));

    emit(builder, BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_get_socket_cookie));
    bypass_jumps[(*bypass_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_0, 0, 0));

    emit_zero_region(builder, STACK_UDP_PEER_KEY, sizeof(struct sb_ebpf_udp_peer_key));
    emit_zero_region(builder, STACK_UDP_PEER_VALUE, sizeof(struct sb_ebpf_udp_peer_value));
    emit(builder, BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, STACK_UDP_PEER_KEY + (int)offsetof(struct sb_ebpf_udp_peer_key, cookie)));
    emit(builder, BPF_ST_MEM(BPF_B, BPF_REG_10, STACK_UDP_PEER_VALUE + (int)offsetof(struct sb_ebpf_udp_peer_value, family), AF_INET));
    emit(builder, BPF_ST_MEM(BPF_B, BPF_REG_10, STACK_UDP_PEER_VALUE + (int)offsetof(struct sb_ebpf_udp_peer_value, protocol), SB_EBPF_PROTO_UDP));
    emit(builder, BPF_STX_MEM(BPF_H, BPF_REG_10, BPF_REG_8, STACK_UDP_PEER_VALUE + (int)offsetof(struct sb_ebpf_udp_peer_value, port)));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_7, STACK_UDP_PEER_VALUE + (int)offsetof(struct sb_ebpf_udp_peer_value, addr)));

    emit_ld_map_fd(builder, BPF_REG_1, udp_peer_map_fd);
    emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    emit(builder, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_2, STACK_UDP_PEER_KEY));
    emit(builder, BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(builder, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_3, STACK_UDP_PEER_VALUE));
    emit(builder, BPF_MOV64_IMM(BPF_REG_4, BPF_ANY));
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_map_update_elem));
}

static void emit_udp_peer_cache_update_v6(
    struct bpf_builder *builder,
    int udp_peer_map_fd,
    size_t *bypass_jumps,
    size_t *bypass_jump_count) {
    if (udp_peer_map_fd < 0) return;

    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6)));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 4));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_9, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 8));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_4, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 12));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_5, BPF_REG_6, offsetof(struct bpf_sock_addr, user_port)));
    emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_7));
    emit(builder, BPF_ALU64_REG_OP(BPF_OR, BPF_REG_2, BPF_REG_8));
    emit(builder, BPF_ALU64_REG_OP(BPF_OR, BPF_REG_2, BPF_REG_9));
    emit(builder, BPF_ALU64_REG_OP(BPF_OR, BPF_REG_2, BPF_REG_4));
    bypass_jumps[(*bypass_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_2, 0, 0));
    bypass_jumps[(*bypass_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_5, 0, 0));

    emit(builder, BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_get_socket_cookie));
    bypass_jumps[(*bypass_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_0, 0, 0));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_4, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 12));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_5, BPF_REG_6, offsetof(struct bpf_sock_addr, user_port)));

    emit_zero_region(builder, STACK_UDP_PEER_KEY, sizeof(struct sb_ebpf_udp_peer_key));
    emit_zero_region(builder, STACK_UDP_PEER_VALUE, sizeof(struct sb_ebpf_udp_peer_value));
    emit(builder, BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, STACK_UDP_PEER_KEY + (int)offsetof(struct sb_ebpf_udp_peer_key, cookie)));
    emit(builder, BPF_ST_MEM(BPF_B, BPF_REG_10, STACK_UDP_PEER_VALUE + (int)offsetof(struct sb_ebpf_udp_peer_value, family), AF_INET6));
    emit(builder, BPF_ST_MEM(BPF_B, BPF_REG_10, STACK_UDP_PEER_VALUE + (int)offsetof(struct sb_ebpf_udp_peer_value, protocol), SB_EBPF_PROTO_UDP));
    emit(builder, BPF_STX_MEM(BPF_H, BPF_REG_10, BPF_REG_5, STACK_UDP_PEER_VALUE + (int)offsetof(struct sb_ebpf_udp_peer_value, port)));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_7, STACK_UDP_PEER_VALUE + (int)offsetof(struct sb_ebpf_udp_peer_value, addr)));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_8, STACK_UDP_PEER_VALUE + (int)offsetof(struct sb_ebpf_udp_peer_value, addr) + 4));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_9, STACK_UDP_PEER_VALUE + (int)offsetof(struct sb_ebpf_udp_peer_value, addr) + 8));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_4, STACK_UDP_PEER_VALUE + (int)offsetof(struct sb_ebpf_udp_peer_value, addr) + 12));

    emit_ld_map_fd(builder, BPF_REG_1, udp_peer_map_fd);
    emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    emit(builder, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_2, STACK_UDP_PEER_KEY));
    emit(builder, BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(builder, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_3, STACK_UDP_PEER_VALUE));
    emit(builder, BPF_MOV64_IMM(BPF_REG_4, BPF_ANY));
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_map_update_elem));
}

static void emit_udp_peer_cache_update(
    struct bpf_builder *builder,
    int udp_peer_map_fd,
    bool ipv6,
    size_t *bypass_jumps,
    size_t *bypass_jump_count) {
    if (ipv6) {
        emit_udp_peer_cache_update_v6(builder, udp_peer_map_fd, bypass_jumps, bypass_jump_count);
    } else {
        emit_udp_peer_cache_update_v4(
            builder,
            udp_peer_map_fd,
            (int)offsetof(struct bpf_sock_addr, user_ip4),
            bypass_jumps,
            bypass_jump_count);
    }
}

static void emit_udp_peer_cache_restore_v4(
    struct bpf_builder *builder,
    int udp_peer_map_fd) {
    if (udp_peer_map_fd < 0) return;

    size_t missing_ip = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_7, 0, 0));
    size_t has_complete_peer = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_8, 0, 0));
    patch_jump(builder, missing_ip, builder->count);

    emit(builder, BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_get_socket_cookie));
    size_t no_cookie = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_0, 0, 0));
    emit_zero_region(builder, STACK_UDP_PEER_KEY, sizeof(struct sb_ebpf_udp_peer_key));
    emit(builder, BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, STACK_UDP_PEER_KEY + (int)offsetof(struct sb_ebpf_udp_peer_key, cookie)));
    emit_ld_map_fd(builder, BPF_REG_1, udp_peer_map_fd);
    emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    emit(builder, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_2, STACK_UDP_PEER_KEY));
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_map_lookup_elem));
    size_t no_peer = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_0, 0, 0));
    emit(builder, BPF_LDX_MEM(BPF_B, BPF_REG_2, BPF_REG_0, offsetof(struct sb_ebpf_udp_peer_value, family)));
    size_t wrong_family = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_2, AF_INET, 0));
    emit(builder, BPF_LDX_MEM(BPF_B, BPF_REG_2, BPF_REG_0, offsetof(struct sb_ebpf_udp_peer_value, protocol)));
    size_t wrong_proto = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_2, SB_EBPF_PROTO_UDP, 0));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_0, offsetof(struct sb_ebpf_udp_peer_value, addr)));
    emit(builder, BPF_LDX_MEM(BPF_H, BPF_REG_8, BPF_REG_0, offsetof(struct sb_ebpf_udp_peer_value, port)));

    size_t done = builder->count;
    patch_jump(builder, has_complete_peer, done);
    patch_jump(builder, no_cookie, done);
    patch_jump(builder, no_peer, done);
    patch_jump(builder, wrong_family, done);
    patch_jump(builder, wrong_proto, done);
}

static void emit_udp_peer_cache_restore_v6(
    struct bpf_builder *builder,
    int udp_peer_map_fd) {
    if (udp_peer_map_fd < 0) return;

    emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_7));
    emit(builder, BPF_ALU64_REG_OP(BPF_OR, BPF_REG_2, BPF_REG_8));
    emit(builder, BPF_ALU64_REG_OP(BPF_OR, BPF_REG_2, BPF_REG_9));
    emit(builder, BPF_ALU64_REG_OP(BPF_OR, BPF_REG_2, BPF_REG_4));
    size_t missing_addr = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_2, 0, 0));
    size_t has_complete_peer = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_5, 0, 0));
    patch_jump(builder, missing_addr, builder->count);

    emit(builder, BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_get_socket_cookie));
    size_t no_cookie = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_0, 0, 0));
    emit_zero_region(builder, STACK_UDP_PEER_KEY, sizeof(struct sb_ebpf_udp_peer_key));
    emit(builder, BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, STACK_UDP_PEER_KEY + (int)offsetof(struct sb_ebpf_udp_peer_key, cookie)));
    emit_ld_map_fd(builder, BPF_REG_1, udp_peer_map_fd);
    emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    emit(builder, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_2, STACK_UDP_PEER_KEY));
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_map_lookup_elem));
    size_t no_peer = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_0, 0, 0));
    emit(builder, BPF_LDX_MEM(BPF_B, BPF_REG_2, BPF_REG_0, offsetof(struct sb_ebpf_udp_peer_value, family)));
    size_t wrong_family = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_2, AF_INET6, 0));
    emit(builder, BPF_LDX_MEM(BPF_B, BPF_REG_2, BPF_REG_0, offsetof(struct sb_ebpf_udp_peer_value, protocol)));
    size_t wrong_proto = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_2, SB_EBPF_PROTO_UDP, 0));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_0, offsetof(struct sb_ebpf_udp_peer_value, addr)));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_0, offsetof(struct sb_ebpf_udp_peer_value, addr) + 4));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_9, BPF_REG_0, offsetof(struct sb_ebpf_udp_peer_value, addr) + 8));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_4, BPF_REG_0, offsetof(struct sb_ebpf_udp_peer_value, addr) + 12));
    emit(builder, BPF_LDX_MEM(BPF_H, BPF_REG_5, BPF_REG_0, offsetof(struct sb_ebpf_udp_peer_value, port)));
    size_t restored_peer = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JA, 0, 0, 0));

    size_t fallback = builder->count;
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6)));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 4));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_9, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 8));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_4, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 12));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_5, BPF_REG_6, offsetof(struct bpf_sock_addr, user_port)));
    size_t done = builder->count;
    patch_jump(builder, restored_peer, done);
    patch_jump(builder, has_complete_peer, done);
    patch_jump(builder, no_cookie, fallback);
    patch_jump(builder, no_peer, fallback);
    patch_jump(builder, wrong_family, fallback);
    patch_jump(builder, wrong_proto, fallback);
}

static void emit_udp_connected_token_restore_v4(
    struct bpf_builder *builder,
    int udp_token_map_fd,
    uint16_t listen_port,
    size_t *allow_jumps,
    size_t *allow_jump_count) {
    if (udp_token_map_fd < 0) return;

    size_t missing_ip = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_7, 0, 0));
    size_t complete_peer = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_8, 0, 0));
    patch_jump(builder, missing_ip, builder->count);

    emit(builder, BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_get_socket_cookie));
    size_t no_cookie = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_0, 0, 0));
    emit(builder, BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, STACK_COOKIE_KEY));
    emit_ld_map_fd(builder, BPF_REG_1, udp_token_map_fd);
    emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    emit(builder, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_2, STACK_COOKIE_KEY));
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_map_lookup_elem));
    size_t no_token = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_0, 0, 0));
    emit(builder, BPF_LDX_MEM(BPF_B, BPF_REG_2, BPF_REG_0, offsetof(struct sb_ebpf_listener_key, family)));
    size_t wrong_family = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_2, AF_INET, 0));
    emit(builder, BPF_LDX_MEM(BPF_B, BPF_REG_2, BPF_REG_0, offsetof(struct sb_ebpf_listener_key, protocol)));
    size_t wrong_protocol = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_2, SB_EBPF_PROTO_UDP, 0));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_0, offsetof(struct sb_ebpf_listener_key, token_addr)));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_6, BPF_REG_7, offsetof(struct bpf_sock_addr, user_ip4)));
    emit_ctx_st32(builder, offsetof(struct bpf_sock_addr, user_port), htons(listen_port));
    allow_jumps[(*allow_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JA, 0, 0, 0));

    size_t done = builder->count;
    patch_jump(builder, complete_peer, done);
    patch_jump(builder, no_cookie, done);
    patch_jump(builder, no_token, done);
    patch_jump(builder, wrong_family, done);
    patch_jump(builder, wrong_protocol, done);
}

static void emit_udp_connected_token_restore_v6(
    struct bpf_builder *builder,
    int udp_token_map_fd,
    uint16_t listen_port,
    size_t *allow_jumps,
    size_t *allow_jump_count) {
    if (udp_token_map_fd < 0) return;

    emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_7));
    emit(builder, BPF_ALU64_REG_OP(BPF_OR, BPF_REG_2, BPF_REG_8));
    emit(builder, BPF_ALU64_REG_OP(BPF_OR, BPF_REG_2, BPF_REG_9));
    emit(builder, BPF_ALU64_REG_OP(BPF_OR, BPF_REG_2, BPF_REG_4));
    size_t missing_address = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_2, 0, 0));
    size_t complete_peer = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_5, 0, 0));
    patch_jump(builder, missing_address, builder->count);

    emit(builder, BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_get_socket_cookie));
    size_t no_cookie = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_0, 0, 0));
    emit(builder, BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, STACK_COOKIE_KEY));
    emit_ld_map_fd(builder, BPF_REG_1, udp_token_map_fd);
    emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    emit(builder, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_2, STACK_COOKIE_KEY));
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_map_lookup_elem));
    size_t no_token = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_0, 0, 0));
    emit(builder, BPF_LDX_MEM(BPF_B, BPF_REG_2, BPF_REG_0, offsetof(struct sb_ebpf_listener_key, protocol)));
    size_t wrong_protocol = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_2, SB_EBPF_PROTO_UDP, 0));
    emit(builder, BPF_LDX_MEM(BPF_B, BPF_REG_2, BPF_REG_0, offsetof(struct sb_ebpf_listener_key, family)));
    size_t ipv6_token = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_2, AF_INET6, 0));
    size_t wrong_family = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_2, AF_INET, 0));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_0, offsetof(struct sb_ebpf_listener_key, token_addr)));
    emit_ctx_st32(builder, offsetof(struct bpf_sock_addr, user_ip6), 0);
    emit_ctx_st32(builder, offsetof(struct bpf_sock_addr, user_ip6) + 4, 0);
    emit_ctx_st32(builder, offsetof(struct bpf_sock_addr, user_ip6) + 8, 0xffff0000U);
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_6, BPF_REG_7, offsetof(struct bpf_sock_addr, user_ip6) + 12));
    emit_ctx_st32(builder, offsetof(struct bpf_sock_addr, user_port), htons(listen_port));
    allow_jumps[(*allow_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JA, 0, 0, 0));

    patch_jump(builder, ipv6_token, builder->count);
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_0, offsetof(struct sb_ebpf_listener_key, token_addr)));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_0, offsetof(struct sb_ebpf_listener_key, token_addr) + 4));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_9, BPF_REG_0, offsetof(struct sb_ebpf_listener_key, token_addr) + 8));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_4, BPF_REG_0, offsetof(struct sb_ebpf_listener_key, token_addr) + 12));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_6, BPF_REG_7, offsetof(struct bpf_sock_addr, user_ip6)));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_6, BPF_REG_8, offsetof(struct bpf_sock_addr, user_ip6) + 4));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_6, BPF_REG_9, offsetof(struct bpf_sock_addr, user_ip6) + 8));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_6, BPF_REG_4, offsetof(struct bpf_sock_addr, user_ip6) + 12));
    emit_ctx_st32(builder, offsetof(struct bpf_sock_addr, user_port), htons(listen_port));
    allow_jumps[(*allow_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JA, 0, 0, 0));

    size_t done = builder->count;
    patch_jump(builder, complete_peer, done);
    patch_jump(builder, no_cookie, done);
    patch_jump(builder, no_token, done);
    patch_jump(builder, wrong_protocol, done);
    patch_jump(builder, wrong_family, done);
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6)));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 4));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_9, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 8));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_4, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 12));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_5, BPF_REG_6, offsetof(struct bpf_sock_addr, user_port)));
}

static void emit_udp_flow_cache_update(
    struct bpf_builder *builder,
    int udp_flow_map_fd) {
    if (udp_flow_map_fd < 0) return;

    emit(builder, BPF_LDX_MEM(
        BPF_DW,
        BPF_REG_2,
        BPF_REG_10,
        STACK_ORIGINAL_DST + (int)offsetof(struct sb_ebpf_original_dst, socket_cookie)));
    size_t missing_cookie = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_2, 0, 0));
    emit_zero_region(builder, STACK_UDP_FLOW_KEY, sizeof(struct sb_ebpf_udp_flow_key));
    emit(builder, BPF_STX_MEM(
        BPF_DW,
        BPF_REG_10,
        BPF_REG_2,
        STACK_UDP_FLOW_KEY + (int)offsetof(struct sb_ebpf_udp_flow_key, cookie)));
    for (size_t offset = 0; offset < 20U; offset += sizeof(uint32_t)) {
        emit(builder, BPF_LDX_MEM(
            BPF_W,
            BPF_REG_2,
            BPF_REG_10,
            STACK_ORIGINAL_DST + (int)offset));
        emit(builder, BPF_STX_MEM(
            BPF_W,
            BPF_REG_10,
            BPF_REG_2,
            STACK_UDP_FLOW_KEY + (int)offsetof(struct sb_ebpf_udp_flow_key, family) + (int)offset));
    }
    emit_zero_region(builder, STACK_UDP_FLOW_VALUE, sizeof(struct sb_ebpf_udp_flow_value));
    emit(builder, BPF_ST_MEM(
        BPF_B,
        BPF_REG_10,
        STACK_UDP_FLOW_VALUE + (int)offsetof(struct sb_ebpf_udp_flow_value, action),
        SB_EBPF_UDP_FLOW_ACTION_PROXY));
    for (size_t offset = 0; offset < sizeof(struct sb_ebpf_listener_key); offset += sizeof(uint32_t)) {
        emit(builder, BPF_LDX_MEM(
            BPF_W,
            BPF_REG_2,
            BPF_REG_10,
            STACK_REDIRECT_KEY + (int)offset));
        emit(builder, BPF_STX_MEM(
            BPF_W,
            BPF_REG_10,
            BPF_REG_2,
            STACK_UDP_FLOW_VALUE + (int)offsetof(struct sb_ebpf_udp_flow_value, listener) + (int)offset));
    }
    emit_ld_map_fd(builder, BPF_REG_1, udp_flow_map_fd);
    emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    emit(builder, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_2, STACK_UDP_FLOW_KEY));
    emit(builder, BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(builder, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_3, STACK_UDP_FLOW_VALUE));
    emit(builder, BPF_MOV64_IMM(BPF_REG_4, BPF_ANY));
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_map_update_elem));
    patch_jump(builder, missing_cookie, builder->count);
}

static void emit_udp_flow_cache_key_v4(
    struct bpf_builder *builder,
    size_t *miss_jumps,
    size_t *miss_jump_count) {
    miss_jumps[(*miss_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_7, 0, 0));
    miss_jumps[(*miss_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_8, 0, 0));
    emit(builder, BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_get_socket_cookie));
    miss_jumps[(*miss_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_0, 0, 0));
    emit_zero_region(builder, STACK_UDP_FLOW_KEY, sizeof(struct sb_ebpf_udp_flow_key));
    emit(builder, BPF_STX_MEM(
        BPF_DW,
        BPF_REG_10,
        BPF_REG_0,
        STACK_UDP_FLOW_KEY + (int)offsetof(struct sb_ebpf_udp_flow_key, cookie)));
    emit(builder, BPF_ST_MEM(
        BPF_B,
        BPF_REG_10,
        STACK_UDP_FLOW_KEY + (int)offsetof(struct sb_ebpf_udp_flow_key, family),
        AF_INET));
    emit(builder, BPF_ST_MEM(
        BPF_B,
        BPF_REG_10,
        STACK_UDP_FLOW_KEY + (int)offsetof(struct sb_ebpf_udp_flow_key, protocol),
        SB_EBPF_PROTO_UDP));
    emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_8));
    emit(builder, BPF_ENDIAN_OP(BPF_REG_2, 16));
    emit(builder, BPF_STX_MEM(
        BPF_H,
        BPF_REG_10,
        BPF_REG_2,
        STACK_UDP_FLOW_KEY + (int)offsetof(struct sb_ebpf_udp_flow_key, port)));
    emit(builder, BPF_STX_MEM(
        BPF_W,
        BPF_REG_10,
        BPF_REG_7,
        STACK_UDP_FLOW_KEY + (int)offsetof(struct sb_ebpf_udp_flow_key, addr)));
}

static void emit_udp_flow_bypass_cache_update_v4(
    struct bpf_builder *builder,
    int udp_flow_map_fd,
    bool v4mapped) {
    if (udp_flow_map_fd < 0) return;

    size_t done_jumps[4];
    size_t done_jump_count = 0;
    int address_offset = v4mapped
        ? (int)offsetof(struct bpf_sock_addr, user_ip6) + 12
        : (int)offsetof(struct bpf_sock_addr, user_ip4);
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_6, address_offset));
    emit(builder, BPF_LDX_MEM(
        BPF_W, BPF_REG_8, BPF_REG_6, offsetof(struct bpf_sock_addr, user_port)));
    emit_udp_flow_cache_key_v4(builder, done_jumps, &done_jump_count);

    emit_zero_region(builder, STACK_UDP_FLOW_VALUE, sizeof(struct sb_ebpf_udp_flow_value));
    emit(builder, BPF_ST_MEM(
        BPF_B,
        BPF_REG_10,
        STACK_UDP_FLOW_VALUE + (int)offsetof(struct sb_ebpf_udp_flow_value, action),
        SB_EBPF_UDP_FLOW_ACTION_BYPASS));
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_ktime_get_ns));
    emit(builder, BPF_ALU64_IMM_OP(BPF_DIV, BPF_REG_0, 1000000000U));
    emit(builder, BPF_STX_MEM(
        BPF_W,
        BPF_REG_10,
        BPF_REG_0,
        STACK_UDP_FLOW_VALUE + (int)offsetof(struct sb_ebpf_udp_flow_value, last_seen_seconds)));
    emit_ld_map_fd(builder, BPF_REG_1, udp_flow_map_fd);
    emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    emit(builder, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_2, STACK_UDP_FLOW_KEY));
    emit(builder, BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(builder, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_3, STACK_UDP_FLOW_VALUE));
    emit(builder, BPF_MOV64_IMM(BPF_REG_4, BPF_ANY));
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_map_update_elem));

    size_t done = builder->count;
    patch_jumps(builder, done_jumps, done_jump_count, done);
}

static void emit_udp_flow_bypass_cache_update_v6(
    struct bpf_builder *builder,
    int udp_flow_map_fd) {
    if (udp_flow_map_fd < 0) return;

    size_t done_jumps[4];
    size_t done_jump_count = 0;
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6)));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 4));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_9, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 8));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_4, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 12));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_5, BPF_REG_6, offsetof(struct bpf_sock_addr, user_port)));
    emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_7));
    emit(builder, BPF_ALU64_REG_OP(BPF_OR, BPF_REG_2, BPF_REG_8));
    emit(builder, BPF_ALU64_REG_OP(BPF_OR, BPF_REG_2, BPF_REG_9));
    emit(builder, BPF_ALU64_REG_OP(BPF_OR, BPF_REG_2, BPF_REG_4));
    done_jumps[done_jump_count++] = emit_jump(
        builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_2, 0, 0));
    done_jumps[done_jump_count++] = emit_jump(
        builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_5, 0, 0));

    emit_zero_region(builder, STACK_UDP_FLOW_KEY, sizeof(struct sb_ebpf_udp_flow_key));
    emit(builder, BPF_ST_MEM(
        BPF_B,
        BPF_REG_10,
        STACK_UDP_FLOW_KEY + (int)offsetof(struct sb_ebpf_udp_flow_key, family),
        AF_INET6));
    emit(builder, BPF_ST_MEM(
        BPF_B,
        BPF_REG_10,
        STACK_UDP_FLOW_KEY + (int)offsetof(struct sb_ebpf_udp_flow_key, protocol),
        SB_EBPF_PROTO_UDP));
    emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_5));
    emit(builder, BPF_ENDIAN_OP(BPF_REG_2, 16));
    emit(builder, BPF_STX_MEM(
        BPF_H,
        BPF_REG_10,
        BPF_REG_2,
        STACK_UDP_FLOW_KEY + (int)offsetof(struct sb_ebpf_udp_flow_key, port)));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_7, STACK_UDP_FLOW_KEY + (int)offsetof(struct sb_ebpf_udp_flow_key, addr)));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_8, STACK_UDP_FLOW_KEY + (int)offsetof(struct sb_ebpf_udp_flow_key, addr) + 4));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_9, STACK_UDP_FLOW_KEY + (int)offsetof(struct sb_ebpf_udp_flow_key, addr) + 8));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_4, STACK_UDP_FLOW_KEY + (int)offsetof(struct sb_ebpf_udp_flow_key, addr) + 12));
    emit(builder, BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_get_socket_cookie));
    done_jumps[done_jump_count++] = emit_jump(
        builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_0, 0, 0));
    emit(builder, BPF_STX_MEM(
        BPF_DW,
        BPF_REG_10,
        BPF_REG_0,
        STACK_UDP_FLOW_KEY + (int)offsetof(struct sb_ebpf_udp_flow_key, cookie)));

    emit_zero_region(builder, STACK_UDP_FLOW_VALUE, sizeof(struct sb_ebpf_udp_flow_value));
    emit(builder, BPF_ST_MEM(
        BPF_B,
        BPF_REG_10,
        STACK_UDP_FLOW_VALUE + (int)offsetof(struct sb_ebpf_udp_flow_value, action),
        SB_EBPF_UDP_FLOW_ACTION_BYPASS));
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_ktime_get_ns));
    emit(builder, BPF_ALU64_IMM_OP(BPF_DIV, BPF_REG_0, 1000000000U));
    emit(builder, BPF_STX_MEM(
        BPF_W,
        BPF_REG_10,
        BPF_REG_0,
        STACK_UDP_FLOW_VALUE + (int)offsetof(struct sb_ebpf_udp_flow_value, last_seen_seconds)));
    emit_ld_map_fd(builder, BPF_REG_1, udp_flow_map_fd);
    emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    emit(builder, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_2, STACK_UDP_FLOW_KEY));
    emit(builder, BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(builder, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_3, STACK_UDP_FLOW_VALUE));
    emit(builder, BPF_MOV64_IMM(BPF_REG_4, BPF_ANY));
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_map_update_elem));

    size_t done = builder->count;
    patch_jumps(builder, done_jumps, done_jump_count, done);
}

static void emit_udp_flow_cache_action(
    struct bpf_builder *builder,
    uint32_t udp_timeout_seconds,
    size_t *miss_jumps,
    size_t *miss_jump_count,
    size_t *allow_jumps,
    size_t *allow_jump_count) {
    emit(builder, BPF_LDX_MEM(
        BPF_B,
        BPF_REG_2,
        BPF_REG_0,
        offsetof(struct sb_ebpf_udp_flow_value, action)));
    size_t proxy = emit_jump(builder, BPF_JMP_IMM_OP(
        BPF_JEQ, BPF_REG_2, SB_EBPF_UDP_FLOW_ACTION_PROXY, 0));
    miss_jumps[(*miss_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(
        BPF_JNE, BPF_REG_2, SB_EBPF_UDP_FLOW_ACTION_BYPASS, 0));

    emit(builder, BPF_MOV64_REG(BPF_REG_9, BPF_REG_0));
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_ktime_get_ns));
    emit(builder, BPF_ALU64_IMM_OP(BPF_DIV, BPF_REG_0, 1000000000U));
    emit(builder, BPF_LDX_MEM(
        BPF_W,
        BPF_REG_2,
        BPF_REG_9,
        offsetof(struct sb_ebpf_udp_flow_value, last_seen_seconds)));
    emit(builder, BPF_MOV32_REG(BPF_REG_3, BPF_REG_0));
    emit(builder, BPF_ALU32_REG_OP(BPF_SUB, BPF_REG_3, BPF_REG_2));
    emit(builder, BPF_ALU32_IMM_OP(BPF_MOV, BPF_REG_4, udp_timeout_seconds));
    miss_jumps[(*miss_jump_count)++] = emit_jump(builder, BPF_JMP_REG_OP(
        BPF_JGT, BPF_REG_3, BPF_REG_4, 0));
    emit(builder, BPF_STX_MEM(
        BPF_W,
        BPF_REG_9,
        BPF_REG_0,
        offsetof(struct sb_ebpf_udp_flow_value, last_seen_seconds)));
    allow_jumps[(*allow_jump_count)++] = emit_jump(
        builder, BPF_JMP_IMM_OP(BPF_JA, 0, 0, 0));
    patch_jump(builder, proxy, builder->count);
}

static void emit_udp_flow_cache_restore_v4(
    struct bpf_builder *builder,
    int udp_flow_map_fd,
    uint16_t listen_port,
    uint32_t udp_timeout_seconds,
    bool v4mapped,
    size_t *allow_jumps,
    size_t *allow_jump_count) {
    if (udp_flow_map_fd < 0) return;

    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_7, STACK_SAVED_V6_LAST_WORD));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_8, STACK_SAVED_PORT));
    size_t miss_jumps[12];
    size_t miss_jump_count = 0;
    emit_udp_flow_cache_key_v4(builder, miss_jumps, &miss_jump_count);
    emit_ld_map_fd(builder, BPF_REG_1, udp_flow_map_fd);
    emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    emit(builder, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_2, STACK_UDP_FLOW_KEY));
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_map_lookup_elem));
    miss_jumps[miss_jump_count++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_0, 0, 0));
    emit_udp_flow_cache_action(
        builder,
        udp_timeout_seconds,
        miss_jumps,
        &miss_jump_count,
        allow_jumps,
        allow_jump_count);
    emit(builder, BPF_LDX_MEM(BPF_B, BPF_REG_2, BPF_REG_0, UDP_FLOW_LISTENER_OFFSET(family)));
    miss_jumps[miss_jump_count++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_2, AF_INET, 0));
    emit(builder, BPF_LDX_MEM(BPF_B, BPF_REG_2, BPF_REG_0, UDP_FLOW_LISTENER_OFFSET(protocol)));
    miss_jumps[miss_jump_count++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_2, SB_EBPF_PROTO_UDP, 0));
    emit(builder, BPF_LDX_MEM(BPF_H, BPF_REG_2, BPF_REG_0, UDP_FLOW_LISTENER_OFFSET(listener_port)));
    miss_jumps[miss_jump_count++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_2, listen_port, 0));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_0, UDP_FLOW_LISTENER_OFFSET(token_addr)));
    if (v4mapped) {
        emit_ctx_st32(builder, offsetof(struct bpf_sock_addr, user_ip6), 0);
        emit_ctx_st32(builder, offsetof(struct bpf_sock_addr, user_ip6) + 4, 0);
        emit_ctx_st32(builder, offsetof(struct bpf_sock_addr, user_ip6) + 8, 0xffff0000U);
        emit(builder, BPF_STX_MEM(
            BPF_W,
            BPF_REG_6,
            BPF_REG_2,
            offsetof(struct bpf_sock_addr, user_ip6) + 12));
    } else {
        emit(builder, BPF_STX_MEM(
            BPF_W,
            BPF_REG_6,
            BPF_REG_2,
            offsetof(struct bpf_sock_addr, user_ip4)));
    }
    emit_ctx_st32(builder, offsetof(struct bpf_sock_addr, user_port), htons(listen_port));
    allow_jumps[(*allow_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JA, 0, 0, 0));

    size_t miss_label = builder->count;
    patch_jumps(builder, miss_jumps, miss_jump_count, miss_label);
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_10, STACK_SAVED_V6_LAST_WORD));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_10, STACK_SAVED_PORT));
}

static void emit_udp_flow_cache_restore_v6(
    struct bpf_builder *builder,
    int udp_flow_map_fd,
    uint16_t listen_port,
    uint32_t udp_timeout_seconds,
    size_t *allow_jumps,
    size_t *allow_jump_count) {
    if (udp_flow_map_fd < 0) return;

    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_7, STACK_REDIRECT_KEY));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_8, STACK_SAVED_V6_WORD1));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_9, STACK_SAVED_V6_WORD2));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_4, STACK_SAVED_V6_LAST_WORD));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_5, STACK_SAVED_PORT));
    size_t miss_jumps[12];
    size_t miss_jump_count = 0;
    emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_7));
    emit(builder, BPF_ALU64_REG_OP(BPF_OR, BPF_REG_2, BPF_REG_8));
    emit(builder, BPF_ALU64_REG_OP(BPF_OR, BPF_REG_2, BPF_REG_9));
    emit(builder, BPF_ALU64_REG_OP(BPF_OR, BPF_REG_2, BPF_REG_4));
    miss_jumps[miss_jump_count++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_2, 0, 0));
    miss_jumps[miss_jump_count++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_5, 0, 0));
    emit(builder, BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_get_socket_cookie));
    miss_jumps[miss_jump_count++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_0, 0, 0));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_4, BPF_REG_10, STACK_SAVED_V6_LAST_WORD));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_5, BPF_REG_10, STACK_SAVED_PORT));
    emit_zero_region(builder, STACK_UDP_FLOW_KEY, sizeof(struct sb_ebpf_udp_flow_key));
    emit(builder, BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, STACK_UDP_FLOW_KEY));
    emit(builder, BPF_ST_MEM(BPF_B, BPF_REG_10, STACK_UDP_FLOW_KEY + (int)offsetof(struct sb_ebpf_udp_flow_key, family), AF_INET6));
    emit(builder, BPF_ST_MEM(BPF_B, BPF_REG_10, STACK_UDP_FLOW_KEY + (int)offsetof(struct sb_ebpf_udp_flow_key, protocol), SB_EBPF_PROTO_UDP));
    emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_5));
    emit(builder, BPF_ENDIAN_OP(BPF_REG_2, 16));
    emit(builder, BPF_STX_MEM(BPF_H, BPF_REG_10, BPF_REG_2, STACK_UDP_FLOW_KEY + (int)offsetof(struct sb_ebpf_udp_flow_key, port)));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_10, STACK_REDIRECT_KEY));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_2, STACK_UDP_FLOW_KEY + (int)offsetof(struct sb_ebpf_udp_flow_key, addr)));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_8, STACK_UDP_FLOW_KEY + (int)offsetof(struct sb_ebpf_udp_flow_key, addr) + 4));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_9, STACK_UDP_FLOW_KEY + (int)offsetof(struct sb_ebpf_udp_flow_key, addr) + 8));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_4, STACK_UDP_FLOW_KEY + (int)offsetof(struct sb_ebpf_udp_flow_key, addr) + 12));
    emit_ld_map_fd(builder, BPF_REG_1, udp_flow_map_fd);
    emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    emit(builder, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_2, STACK_UDP_FLOW_KEY));
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_map_lookup_elem));
    miss_jumps[miss_jump_count++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_0, 0, 0));
    emit_udp_flow_cache_action(
        builder,
        udp_timeout_seconds,
        miss_jumps,
        &miss_jump_count,
        allow_jumps,
        allow_jump_count);
    emit(builder, BPF_LDX_MEM(BPF_B, BPF_REG_2, BPF_REG_0, UDP_FLOW_LISTENER_OFFSET(family)));
    miss_jumps[miss_jump_count++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_2, AF_INET6, 0));
    emit(builder, BPF_LDX_MEM(BPF_B, BPF_REG_2, BPF_REG_0, UDP_FLOW_LISTENER_OFFSET(protocol)));
    miss_jumps[miss_jump_count++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_2, SB_EBPF_PROTO_UDP, 0));
    emit(builder, BPF_LDX_MEM(BPF_H, BPF_REG_2, BPF_REG_0, UDP_FLOW_LISTENER_OFFSET(listener_port)));
    miss_jumps[miss_jump_count++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_2, listen_port, 0));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_0, UDP_FLOW_LISTENER_OFFSET(token_addr)));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_0, UDP_FLOW_LISTENER_OFFSET(token_addr) + 4));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_9, BPF_REG_0, UDP_FLOW_LISTENER_OFFSET(token_addr) + 8));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_4, BPF_REG_0, UDP_FLOW_LISTENER_OFFSET(token_addr) + 12));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_6, BPF_REG_7, offsetof(struct bpf_sock_addr, user_ip6)));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_6, BPF_REG_8, offsetof(struct bpf_sock_addr, user_ip6) + 4));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_6, BPF_REG_9, offsetof(struct bpf_sock_addr, user_ip6) + 8));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_6, BPF_REG_4, offsetof(struct bpf_sock_addr, user_ip6) + 12));
    emit_ctx_st32(builder, offsetof(struct bpf_sock_addr, user_port), htons(listen_port));
    allow_jumps[(*allow_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JA, 0, 0, 0));

    size_t miss_label = builder->count;
    patch_jumps(builder, miss_jumps, miss_jump_count, miss_label);
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_10, STACK_REDIRECT_KEY));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_10, STACK_SAVED_V6_WORD1));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_9, BPF_REG_10, STACK_SAVED_V6_WORD2));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_4, BPF_REG_10, STACK_SAVED_V6_LAST_WORD));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_5, BPF_REG_10, STACK_SAVED_PORT));
}
