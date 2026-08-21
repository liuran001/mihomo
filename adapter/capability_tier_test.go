package adapter

import (
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

// seed 直接写入能力缓存，避免测试真的发起网络探测
func seed(name string, udp, ipv6 *bool) {
	st := capabilityStateFor(name)
	set := func(e *capabilityEntry, v *bool) {
		e.mu.Lock()
		defer e.mu.Unlock()
		if v == nil {
			e.known, e.probing = false, true // 标记探测中，防止测试触发真实探测
			return
		}
		e.known, e.ok, e.expire, e.probing = true, *v, time.Now().Add(time.Hour), false
	}
	set(&st.udp, udp)
	set(&st.ipv6, ipv6)
}

func names(ps []C.Proxy) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.Name()
	}
	return out
}

func TestCapabilityTierLadder(t *testing.T) {
	capabilityCache.Range(func(k, _ any) bool { capabilityCache.Delete(k); return true })
	yes, no := true, false

	seed("both", &yes, &yes)   // UDP + IPv6
	seed("udponly", &yes, &no) // 仅 UDP
	seed("unprobed", nil, nil) // 未探测
	seed("neither", &no, &no)  // 都不支持
	all := []C.Proxy{stub("both"), stub("udponly"), stub("unprobed"), stub("neither")}

	// 1) 最优层存在时只用它
	if got := names(FilterProxiesByCapability(all, true, true)); len(got) != 1 || got[0] != "both" {
		t.Errorf("应只选 both，得到 %v", got)
	}
	// 2) 去掉最优层 → 降级到仅 UDP
	if got := names(FilterProxiesByCapability(all[1:], true, true)); len(got) != 1 || got[0] != "udponly" {
		t.Errorf("应降级到 udponly，得到 %v", got)
	}
	// 3) 再去掉 → 降级到未探测
	if got := names(FilterProxiesByCapability(all[2:], true, true)); len(got) != 1 || got[0] != "unprobed" {
		t.Errorf("应降级到 unprobed，得到 %v", got)
	}
	// 4) 只剩确认不支持的 → 仍然返回（兜底，不让组变空）
	if got := names(FilterProxiesByCapability(all[3:], true, true)); len(got) != 1 || got[0] != "neither" {
		t.Errorf("应兜底返回 neither，得到 %v", got)
	}
	// 5) 未开启偏好时原样返回
	if got := FilterProxiesByCapability(all, false, false); len(got) != 4 {
		t.Errorf("未开启时应返回全部 4 个，得到 %d", len(got))
	}
	// 6) 只要求 UDP 时，ipv6 缺失不该影响入选
	if got := names(FilterProxiesByCapability(all, true, false)); len(got) != 2 ||
		got[0] != "both" || got[1] != "udponly" {
		t.Errorf("只要求 UDP 时应选 both+udponly，得到 %v", got)
	}
}
