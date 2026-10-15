//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"net/netip"
	"testing"

	LC "github.com/metacubex/mihomo/listener/config"
)

// TestReadmeDocumentedValues pins the option values written in README.md to the
// code that parses them. mihomo -t does not validate listener options at all --
// a bogus dns-mode or a UID range with the wrong separator passes the config
// test and only fails when the listener starts -- so the README cannot be
// checked by running it through the binary. This is that check.
func TestReadmeDocumentedValues(t *testing.T) {
	for _, mode := range []string{"", "local", "shared", "hybrid"} {
		if _, _, _, err := normalizeModeWithEnabled(mode, nil, nil); err != nil {
			t.Errorf("mode %q 被拒绝: %v", mode, err)
		}
	}
	for _, mode := range []string{"", "hijack", "respect_policy", "respect_bypass", "off"} {
		if _, err := normalizeDNSMode(mode); err != nil {
			t.Errorf("dns-mode %q 被拒绝: %v", mode, err)
		}
	}
	for _, plane := range []string{"", "cgroup", "tc"} {
		if _, _, err := normalizeLocalDataPlane(LC.EBPFLocal{DataPlane: plane}); err != nil {
			t.Errorf("local.data-plane %q 被拒绝: %v", plane, err)
		}
	}
	for _, plane := range []string{"", "packet_rewrite", "socket_assign"} {
		if _, err := normalizeSharedDataPlane(LC.EBPFShared{DataPlane: plane}); err != nil {
			t.Errorf("shared.data-plane %q 被拒绝: %v", plane, err)
		}
	}
	for _, mode := range []string{"", "off", "reply"} {
		if _, err := normalizeFakeIPICMP(mode); err != nil {
			t.Errorf("fakeip-icmp %q 被拒绝: %v", mode, err)
		}
	}
	if _, err := normalizeFakeIPICMP("on"); err == nil {
		t.Error("fakeip-icmp 只有 off / reply 两个值，on 本应被拒绝")
	}
	if _, err := parseUIDRanges([]uint32{0, 1000}, []string{"10000:19999", "20000:20100"}); err != nil {
		t.Errorf("README 写的 UID 范围被拒绝: %v", err)
	}
	if _, err := parseUIDRanges(nil, []string{"10000-19999"}); err == nil {
		t.Error("连字符分隔符本应被拒绝 —— README 若这么写就是错的")
	}
	if _, err := parseSharedMACAddresses("include_mac_address",
		[]string{"aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"}); err != nil {
		t.Errorf("README 写的 MAC 格式被拒绝: %v", err)
	}
	if _, err := parsePortRanges("local.bypass_port", []uint16{22}, []string{"1000:2000"}); err != nil {
		t.Errorf("README 写的端口范围被拒绝: %v", err)
	}
	// README 说 udp-timeout 默认 300 秒、最小 5 秒
	if got := resolveUDPTimeout(0); got.Seconds() != 300 {
		t.Errorf("udp-timeout 默认值是 %v，README 写的是 300s", got)
	}
	if got := resolveUDPTimeout(1); got.Seconds() != 5 {
		t.Errorf("udp-timeout 下限是 %v，README 写的是 5s", got)
	}
	if got := resolveUDPTimeout(300); got.Seconds() != 300 {
		t.Errorf("udp-timeout 300 解析成了 %v", got)
	}
	// README: allow-default-upstream(单臂旁路由) 仅 shared/hybrid 模式可配
	allow := true
	if err := validateSharedOptions(true, LC.EBPFShared{AllowDefaultUpstream: &allow}); err != nil {
		t.Errorf("shared 模式下 allow-default-upstream 本应被接受: %v", err)
	}
	if err := validateSharedOptions(false, LC.EBPFShared{AllowDefaultUpstream: &allow}); err == nil {
		t.Error("shared 未启用时 allow-default-upstream 本应被拒绝")
	}
}

// TestFakeIPICMPDocumentedRequirements pins the README's rule for when
// fakeip-icmp: reply is accepted -- a configured fake-ip range plus an
// attachment that can carry the reply program. The reply programs run on a TC
// hook, which is what rules cgroup-only out.
func TestFakeIPICMPDocumentedRequirements(t *testing.T) {
	fakeIPv4 := netip.MustParsePrefix("198.18.0.0/16")
	none := netip.Prefix{}
	if err := validateFakeIPICMP(false, none, none, true, localDataPlaneCgroup, false, ""); err != nil {
		t.Errorf("fakeip-icmp 关着时不该有任何限制: %v", err)
	}
	if err := validateFakeIPICMP(true, none, none, true, localDataPlaneTC, false, ""); err == nil {
		t.Error("没配 fake-ip 段时 reply 本应被拒绝")
	}
	if err := validateFakeIPICMP(true, fakeIPv4, none, true, localDataPlaneTC, false, ""); err != nil {
		t.Errorf("local.data-plane=tc 本应被接受: %v", err)
	}
	for _, plane := range []string{sharedDataPlanePacketRewrite, sharedDataPlaneSocketAssign} {
		if err := validateFakeIPICMP(true, fakeIPv4, none, false, "", true, plane); err != nil {
			t.Errorf("shared.data-plane=%s 本应被接受: %v", plane, err)
		}
	}
	// cgroup 的 connect()/sendmsg() hook 看不到 ICMP，没有 shared 兜底就没人能回包。
	if err := validateFakeIPICMP(true, fakeIPv4, none, true, localDataPlaneCgroup, false, ""); err == nil {
		t.Error("local.data-plane=cgroup 且没开 shared 本应被拒绝")
	}
	if err := validateFakeIPICMP(true, fakeIPv4, none, true, localDataPlaneCgroup, true, sharedDataPlanePacketRewrite); err != nil {
		t.Errorf("cgroup + shared 本应被接受: %v", err)
	}
}

// TestLegacyOptionsKeepOldConfigsWorking pins the mapping from the pre-rework
// option surface -- the one every existing config of this branch was written
// against -- onto the current one.
func TestLegacyOptionsKeepOldConfigsWorking(t *testing.T) {
	no := false
	legacy := LC.EBPF{
		Mode:                 "hybrid",
		DNSMode:              "hijack",
		BypassPrivateAddress: &no,
		TCPSplice:            true,
		Local: LC.EBPFLocal{
			IPv6Mode:      "auto",
			StateCapacity: 32768,
		},
		Shared: LC.EBPFShared{
			Interface:     []string{"br0"},
			IPv6Mode:      "always",
			StateCapacity: 65536,
			Advanced:      LC.EBPFSharedAdvanced{TCPriority: 7, RoutingMark: 0x2333},
		},
	}
	options, notes, err := applyLegacyOptions(legacy)
	if err != nil {
		t.Fatalf("legacy config rejected: %v", err)
	}
	if options.Local.DNSMode != "hijack" || options.Shared.DNSMode != "hijack" {
		t.Errorf("top-level dns-mode was not folded into both roles: local=%q shared=%q", options.Local.DNSMode, options.Shared.DNSMode)
	}
	if options.Local.BypassPrivateAddress == nil || *options.Local.BypassPrivateAddress ||
		options.Shared.BypassPrivateAddress == nil || *options.Shared.BypassPrivateAddress {
		t.Error("top-level bypass-private-address: false was not folded into both roles")
	}
	if options.Local.IPv6 == nil || !*options.Local.IPv6 {
		t.Error("local.ipv6-mode: auto should enable IPv6 interception")
	}
	if options.Shared.IPv6 == nil || !*options.Shared.IPv6 {
		t.Error("shared.ipv6-mode: always should enable IPv6 interception")
	}
	if options.TCPriority != 7 {
		t.Errorf("shared.advanced.tc-priority was not lifted to tc-priority, got %d", options.TCPriority)
	}
	if options.Local.StateCapacity != 32768 || options.Shared.StateCapacity != 65536 {
		t.Error("state-capacity values must survive the mapping")
	}
	// auto, routing-mark and tcp-splice each deserve one note; nothing else.
	if len(notes) != 3 {
		t.Errorf("expected three notes (ipv6 auto, routing-mark, tcp-splice), got %d: %v", len(notes), notes)
	}

	// The whole legacy config must then pass the current validation.
	if _, err := normalizeDataPlanes(options); err != nil {
		t.Errorf("folded config rejected by the data-plane normaliser: %v", err)
	}
	if err := validateLocalOptions(true, options.Local); err != nil {
		t.Errorf("folded local options rejected: %v", err)
	}
	if err := validateSharedOptions(true, options.Shared); err != nil {
		t.Errorf("folded shared options rejected: %v", err)
	}
}

// A new-style key always wins over a leftover legacy one.
func TestLegacyOptionsDoNotOverrideNewKeys(t *testing.T) {
	yes := true
	options, _, err := applyLegacyOptions(LC.EBPF{
		Mode:    "local",
		DNSMode: "hijack",
		Local:   LC.EBPFLocal{DNSMode: "off", IPv6Mode: "off", IPv6: &yes},
	})
	if err != nil {
		t.Fatal(err)
	}
	if options.Local.DNSMode != "off" {
		t.Errorf("local.dns-mode was overridden by the legacy top-level value: %q", options.Local.DNSMode)
	}
	if options.Local.IPv6 == nil || !*options.Local.IPv6 {
		t.Error("local.ipv6 was overridden by the legacy ipv6-mode")
	}
}

// Legacy keys for a role that is not enabled are dropped rather than folded,
// because the validator rejects role options on a disabled role.
func TestLegacyOptionsRespectRoleEnablement(t *testing.T) {
	options, _, err := applyLegacyOptions(LC.EBPF{
		Mode:    "local",
		DNSMode: "hijack",
		Shared:  LC.EBPFShared{IPv6Mode: "always"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if options.Shared.DNSMode != "" || options.Shared.IPv6 != nil {
		t.Errorf("legacy shared keys were folded into a disabled shared role: %+v", options.Shared)
	}
	if err := validateSharedOptions(false, options.Shared); err != nil {
		t.Errorf("mode=local with legacy shared keys must still validate: %v", err)
	}
}

func TestLegacyOptionsRejectNonsense(t *testing.T) {
	if _, _, err := applyLegacyOptions(LC.EBPF{Local: LC.EBPFLocal{IPv6Mode: "maybe"}}); err == nil {
		t.Error("an unknown local.ipv6-mode must be rejected")
	}
	if _, _, err := applyLegacyOptions(LC.EBPF{Mode: "shared", Shared: LC.EBPFShared{Interface: []string{"br0"}, IPv6Mode: "auto"}}); err == nil {
		t.Error("shared.ipv6-mode never supported auto and must be rejected")
	}
	if _, _, err := applyLegacyOptions(LC.EBPF{Local: LC.EBPFLocal{StateCapacity: maximumStateCapacity + 1}}); err == nil {
		t.Error("a state-capacity above the documented cap must be rejected")
	}
}
