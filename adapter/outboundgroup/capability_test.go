package outboundgroup

import (
	"testing"

	"github.com/metacubex/mihomo/common/structure"
)

func TestRequireCapabilityDecode(t *testing.T) {
	decoder := structure.NewDecoder(structure.Option{TagName: "group", WeaklyTypedInput: true})
	raw := map[string]any{
		"name":        "自动选择",
		"type":        "url-test",
		"prefer-udp":  true,
		"prefer-ipv6": true,
		"use":         []any{"SSLinks"},
	}
	opt := GroupCommonOption{}
	if err := decoder.Decode(raw, &opt); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !opt.PreferUDP {
		t.Error("prefer-udp 未解析为 true")
	}
	if !opt.PreferIPv6 {
		t.Error("prefer-ipv6 未解析为 true")
	}
	t.Logf("decoded: PreferUDP=%v PreferIPv6=%v", opt.PreferUDP, opt.PreferIPv6)
}
