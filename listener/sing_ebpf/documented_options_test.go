//go:build with_ebpf && (linux || android)

package sing_ebpf

import "testing"

// TestReadmeDocumentedValues pins the option values written in README.md to the
// code that parses them. mihomo -t does not validate listener options at all --
// a bogus dns-mode or a UID range with the wrong separator passes the config
// test and only fails when the listener starts -- so the README cannot be
// checked by running it through the binary. This is that check.
func TestReadmeDocumentedValues(t *testing.T) {
	for _, mode := range []string{"", "local", "shared", "hybrid"} {
		if _, _, _, err := normalizeMode(mode); err != nil {
			t.Errorf("mode %q 被拒绝: %v", mode, err)
		}
	}
	for _, mode := range []string{"", "hijack", "respect_bypass", "off"} {
		if _, err := normalizeDNSMode(mode); err != nil {
			t.Errorf("dns-mode %q 被拒绝: %v", mode, err)
		}
	}
	for _, mode := range []string{"", "auto", "always", "off"} {
		if _, err := normalizeCgroupIPv6Mode(mode); err != nil {
			t.Errorf("local.ipv6-mode %q 被拒绝: %v", mode, err)
		}
	}
	for _, mode := range []string{"", "always", "off"} {
		if _, err := normalizeSharedIPv6Mode(mode); err != nil {
			t.Errorf("shared.ipv6-mode %q 被拒绝: %v", mode, err)
		}
	}
	if _, err := parseUIDRanges([]uint32{0, 1000}, []string{"10000:19999", "20000:20100"}); err != nil {
		t.Errorf("README 写的 UID 范围被拒绝: %v", err)
	}
	if _, err := parseUIDRanges(nil, []string{"10000-19999"}); err == nil {
		t.Error("连字符分隔符本应被拒绝 —— README 若这么写就是错的")
	}
	if _, err := parseSharedNetworkMACAddresses("include_mac_address",
		[]string{"aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"}); err != nil {
		t.Errorf("README 写的 MAC 格式被拒绝: %v", err)
	}
	// README 说 state-capacity 默认 32768、上限 1048576
	if _, err := normalizeCgroupMapCapacity(32768); err != nil {
		t.Errorf("state-capacity 32768 被拒绝: %v", err)
	}
	if _, err := normalizeCgroupMapCapacity(1 << 20); err != nil {
		t.Errorf("state-capacity 上限 1048576 被拒绝: %v", err)
	}
	if _, err := normalizeCgroupMapCapacity(1<<20 + 1); err == nil {
		t.Error("超过上限本应被拒绝")
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
}
