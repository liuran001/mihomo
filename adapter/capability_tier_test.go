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

	// 构造：3 个双通、2 个仅 UDP、2 个未探测、3 个都不支持，共 10 个（> minCandidates）
	var all []C.Proxy
	mk := func(prefix string, n int, udp, v6 *bool) []C.Proxy {
		out := make([]C.Proxy, 0, n)
		for i := 0; i < n; i++ {
			name := prefix + string(rune('A'+i))
			seed(name, udp, v6)
			out = append(out, stub(name))
		}
		return out
	}
	both := mk("both", 3, &yes, &yes)
	udpOnly := mk("udp", 2, &yes, &no)
	unprobed := mk("unk", 2, nil, nil)
	neither := mk("bad", 3, &no, &no)
	all = append(all, both...)
	all = append(all, udpOnly...)
	all = append(all, unprobed...)
	all = append(all, neither...)

	// 1) 顶层不足 minCandidates → 向下合并直到够用，且顶层节点排在前面
	got := names(FilterProxiesByCapability(all, true, true))
	if len(got) < minCandidates {
		t.Errorf("候选应至少 %d 个，得到 %d: %v", minCandidates, len(got), got)
	}
	for i, n := range got[:3] {
		if n != "both"+string(rune('A'+i)) {
			t.Errorf("双通节点应排在最前，位置 %d 得到 %s", i, n)
		}
	}
	if contains(got, "badA") {
		t.Errorf("已有足够候选时不应纳入确认不支持的节点: %v", got)
	}

	// 2) 顶层本身就够 → 只用顶层
	many := mk("rich", 6, &yes, &yes)
	got2 := names(FilterProxiesByCapability(append(many, neither...), true, true))
	if len(got2) != 6 {
		t.Errorf("顶层足够时应只用顶层 6 个，得到 %d: %v", len(got2), got2)
	}

	// 3) 只剩确认不支持的 → 仍然返回，不让组变空
	got3 := names(FilterProxiesByCapability(neither, true, true))
	if len(got3) != len(neither) {
		t.Errorf("兜底应返回全部 %d 个，得到 %v", len(neither), got3)
	}

	// 4) 未开启偏好 → 原样返回
	if len(FilterProxiesByCapability(all, false, false)) != len(all) {
		t.Error("未开启偏好时应原样返回")
	}

	// 5) 候选总数本就不超过下限 → 不做任何筛选
	small := append([]C.Proxy{}, both...)
	small = append(small, neither[0])
	if len(FilterProxiesByCapability(small, true, true)) != len(small) {
		t.Error("总数不足下限时应原样返回")
	}
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}
