package outboundgroup

import (
	"testing"

	"github.com/metacubex/mihomo/common/structure"
)

func TestRequireCapabilityDecode(t *testing.T) {
	decoder := structure.NewDecoder(structure.Option{TagName: "group", WeaklyTypedInput: true})
	raw := map[string]any{
		"name":         "自动选择",
		"type":         "url-test",
		"require-udp":  true,
		"require-ipv6": true,
		"use":          []any{"SSLinks"},
	}
	opt := GroupCommonOption{}
	if err := decoder.Decode(raw, &opt); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !opt.RequireUDP {
		t.Error("require-udp 未解析为 true")
	}
	if !opt.RequireIPv6 {
		t.Error("require-ipv6 未解析为 true")
	}
	t.Logf("decoded: RequireUDP=%v RequireIPv6=%v", opt.RequireUDP, opt.RequireIPv6)
}
