package adapter

import (
	"context"
	"encoding/binary"
	"testing"
	"time"

	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
)

type capabilityProbeProxy struct {
	C.Proxy
	statusCalled bool
	urlCalled    bool
}

func (p *capabilityProbeProxy) Name() string { return "probe" }
func (p *capabilityProbeProxy) StatusTest(context.Context, string) (uint16, bool, error) {
	p.statusCalled = true
	return 204, true, nil
}
func (p *capabilityProbeProxy) URLTest(context.Context, string, utils.IntRanges[uint16]) (uint16, error) {
	p.urlCalled = true
	return 0, nil
}

func TestIPv6CapabilityProbeDoesNotMutateHealth(t *testing.T) {
	p := &capabilityProbeProxy{}
	entry := &capabilityEntry{}
	probeCapability(p, capabilityIPv6, entry)
	if !p.statusCalled {
		t.Fatal("IPv6 capability probe must use StatusTest")
	}
	if p.urlCalled {
		t.Fatal("IPv6 capability probe must not call URLTest")
	}
	entry.mu.Lock()
	ok := entry.known && entry.ok
	entry.mu.Unlock()
	if !ok {
		t.Fatal("successful status probe should cache a positive capability")
	}
}

// seed 直接写入能力缓存，避免测试真的发起网络探测
func seed(name string, udp, ipv6 *bool) {
	// Keep the legacy entry populated for direct cache tests, and populate the
	// production identity used by CapabilityPenalty as well.
	states := []*capabilityState{capabilityStateFor(name), capabilityStateForProxy(stub(name))}
	set := func(e *capabilityEntry, v *bool) {
		e.mu.Lock()
		defer e.mu.Unlock()
		if v == nil {
			e.known, e.probing = false, true // 标记探测中，防止测试触发真实探测
			return
		}
		e.known, e.ok, e.expire, e.probing = true, *v, time.Now().Add(time.Hour), false
	}
	for _, st := range states {
		set(&st.udp, udp)
		set(&st.ipv6, ipv6)
	}
}

func TestCapabilityPenaltyDemotesWithoutFiltering(t *testing.T) {
	capabilityCache.Range(func(k, _ any) bool { capabilityCache.Delete(k); return true })
	yes, no := true, false

	mk := func(name string, udp, v6 *bool) C.Proxy {
		seed(name, udp, v6)
		return stub(name)
	}
	both := mk("both", &yes, &yes)
	udpOnly := mk("udpOnly", &yes, &no)
	unprobed := mk("unprobed", nil, nil)
	neither := mk("neither", &no, &no)

	cases := []struct {
		proxy C.Proxy
		want  uint16
		why   string
	}{
		{both, 0, "两项能力都确认具备的节点不应被惩罚"},
		{udpOnly, capabilityMissingPenalty, "仅缺 IPv6 应只计一份缺失惩罚"},
		{unprobed, 2 * capabilityUnknownPenalty, "尚未探明应计轻微惩罚"},
		{neither, 2 * capabilityMissingPenalty, "两项都缺应计两份缺失惩罚"},
	}
	for _, c := range cases {
		if got := CapabilityPenalty(c.proxy, true, true); got != c.want {
			t.Errorf("%s: CapabilityPenalty(%s) = %d, want %d", c.why, c.proxy.Name(), got, c.want)
		}
	}

	// 惩罚必须是相对的：缺能力的快节点仍应排在具备能力的慢节点之前，
	// 这正是「降优先级而非移出候选池」的核心区别。
	fastMissing := AddCapabilityPenalty(100, neither, true, true)
	slowCapable := AddCapabilityPenalty(2000, both, true, true)
	if fastMissing >= slowCapable {
		t.Errorf("缺能力的快节点(%d)不应输给具备能力的慢节点(%d)", fastMissing, slowCapable)
	}

	// 未开启偏好时不得有任何惩罚，也不得触发探测
	for _, p := range []C.Proxy{both, neither, unprobed} {
		if got := CapabilityPenalty(p, false, false); got != 0 {
			t.Errorf("未开启偏好时 %s 的惩罚应为 0，得到 %d", p.Name(), got)
		}
	}
	if got := CapabilityPenalty(nil, true, true); got != 0 {
		t.Errorf("空节点的惩罚应为 0，得到 %d", got)
	}

	// 只开启单项偏好时只计该项
	if got := CapabilityPenalty(udpOnly, true, false); got != 0 {
		t.Errorf("仅要求 UDP 时具备 UDP 的节点不应被惩罚，得到 %d", got)
	}
	if got := CapabilityPenalty(udpOnly, false, true); got != capabilityMissingPenalty {
		t.Errorf("仅要求 IPv6 时缺 IPv6 的节点应被惩罚 %d，得到 %d", capabilityMissingPenalty, got)
	}
}

func TestAddCapabilityPenaltySaturates(t *testing.T) {
	capabilityCache.Range(func(k, _ any) bool { capabilityCache.Delete(k); return true })
	no := false
	seed("saturate", &no, &no)
	p := stub("saturate")

	// 已经不可用（0xFFFF）的节点加惩罚后不得回绕成一个很小的延迟，
	// 否则一个死节点会因为溢出而排到最前面。
	if got := AddCapabilityPenalty(0xFFFF, p, true, true); got != 0xFFFF {
		t.Errorf("惩罚应饱和在 0xFFFF，得到 %d", got)
	}
	if got := AddCapabilityPenalty(0xFFFF-10, p, true, true); got != 0xFFFF {
		t.Errorf("接近上限时惩罚应饱和在 0xFFFF，得到 %d", got)
	}
	if got := AddCapabilityPenalty(300, p, true, true); got != 300+2*capabilityMissingPenalty {
		t.Errorf("未溢出时应正常累加，得到 %d", got)
	}
}

func TestValidSTUNBindingSuccess(t *testing.T) {
	txid := make([]byte, 12)
	for i := range txid {
		txid[i] = byte(i + 1)
	}
	msg := make([]byte, 20)
	binary.BigEndian.PutUint16(msg[0:2], 0x0101)
	binary.BigEndian.PutUint16(msg[2:4], 0)
	binary.BigEndian.PutUint32(msg[4:8], 0x2112A442)
	copy(msg[8:20], txid)
	if !validSTUNBindingSuccess(msg, txid) {
		t.Fatal("expected valid STUN success response")
	}
	msg[0] = 0x00
	if validSTUNBindingSuccess(msg, txid) {
		t.Fatal("invalid STUN type must be rejected")
	}
	msg[0] = 0x01
	msg[1] = 0x01
	msg[2] = 0
	msg[3] = 1
	if validSTUNBindingSuccess(msg, txid) {
		t.Fatal("STUN length mismatch must be rejected")
	}
	msg[3] = 0
	msg[19]++
	if validSTUNBindingSuccess(msg, txid) {
		t.Fatal("wrong STUN transaction ID must be rejected")
	}
}

func TestCapabilityProbeSemaphoreSkipsWhenBusy(t *testing.T) {
	for i := 0; i < cap(capabilityProbeSem); i++ {
		capabilityProbeSem <- struct{}{}
	}
	defer func() {
		for i := 0; i < cap(capabilityProbeSem); i++ {
			<-capabilityProbeSem
		}
	}()
	entry := &capabilityEntry{probing: true}
	probeCapability(&capabilityProbeProxy{}, capabilityIPv6, entry)
	entry.mu.Lock()
	probing := entry.probing
	entry.mu.Unlock()
	if probing {
		t.Fatal("probe skipped due to saturation must clear probing for a later retry")
	}
}

func TestCapabilityCacheSeparatesProxyIdentity(t *testing.T) {
	capabilityCache.Range(func(k, _ any) bool { capabilityCache.Delete(k); return true })
	yes := true
	a := stubProxy{name: "same", type_: C.Http, provider: "one"}
	b := stubProxy{name: "same", type_: C.Http, provider: "two"}
	stateA := capabilityStateForProxy(a)
	stateA.udp.mu.Lock()
	stateA.udp.known, stateA.udp.ok, stateA.udp.expire = true, yes, time.Now().Add(time.Hour)
	stateA.udp.mu.Unlock()
	stateB := capabilityStateForProxy(b)
	stateB.udp.mu.Lock()
	known := stateB.udp.known
	stateB.udp.mu.Unlock()
	if known {
		t.Fatal("same-named proxies from different providers must not share capability state")
	}
}
