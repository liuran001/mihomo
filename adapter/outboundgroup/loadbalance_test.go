package outboundgroup

import (
	"context"
	"errors"
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

type strategyTestProxy struct {
	C.Proxy
	name     string
	alive    bool
	addr     string
	provider string
}

func (p strategyTestProxy) Name() string                { return p.name }
func (p strategyTestProxy) AliveForTestUrl(string) bool { return p.alive }
func (p strategyTestProxy) Addr() string                { return p.addr }
func (p strategyTestProxy) Type() C.AdapterType         { return C.Http }
func (p strategyTestProxy) ProxyInfo() C.ProxyInfo      { return C.ProxyInfo{ProviderName: p.provider} }

func strategyProxies(names ...string) []C.Proxy {
	proxies := make([]C.Proxy, len(names))
	for i, name := range names {
		proxies[i] = strategyTestProxy{name: name, alive: true}
	}
	return proxies
}

func TestConsistentHashingStableAcrossCandidateReorder(t *testing.T) {
	metadata := &C.Metadata{Host: "example.com"}
	strategy := strategyConsistentHashing("test", false, false)
	first := strategy(strategyProxies("a", "b", "c"), metadata, false)
	second := strategy(strategyProxies("c", "a", "b"), metadata, false)
	if first.Name() != second.Name() {
		t.Fatalf("candidate reorder migrated consistent hash from %q to %q", first.Name(), second.Name())
	}
}

func TestStickySessionsStableAcrossCandidateReorder(t *testing.T) {
	metadata := &C.Metadata{Host: "example.com"}
	strategy := strategyStickySessions("test", false, false)
	first := strategy(strategyProxies("a", "b", "c"), metadata, false)
	second := strategy(strategyProxies("c", "a", "b"), metadata, false)
	if first.Name() != second.Name() {
		t.Fatalf("candidate reorder migrated sticky session from %q to %q", first.Name(), second.Name())
	}
}

func TestStickySessionsDistinguishesDuplicateNames(t *testing.T) {
	metadata := &C.Metadata{Host: "example.com"}
	strategy := strategyStickySessions("test", false, false)
	first := strategy([]C.Proxy{
		strategyTestProxy{name: "same", addr: "one", provider: "p1", alive: true},
		strategyTestProxy{name: "same", addr: "two", provider: "p2", alive: true},
	}, metadata, false)
	second := strategy([]C.Proxy{
		strategyTestProxy{name: "same", addr: "two", provider: "p2", alive: true},
		strategyTestProxy{name: "same", addr: "one", provider: "p1", alive: true},
	}, metadata, false)
	if first.Addr() != second.Addr() {
		t.Fatalf("duplicate proxy names migrated sticky session from %q to %q", first.Addr(), second.Addr())
	}
}

// capabilityDemotedProxy 的能力探测始终失败，所以只要开启了偏好，它就一定带有
// 非零的 capability 惩罚。用它来守住核心语义：偏好只改变节点的排序，不能把节点
// 从候选池里拿掉 —— 早先的实现会直接截断候选，导致连 DIRECT 都被踢出组。
type capabilityDemotedProxy struct {
	strategyTestProxy
}

func (p capabilityDemotedProxy) StatusTest(context.Context, string) (uint16, bool, error) {
	return 0, false, errors.New("capability unavailable")
}

func demotedProxies(names ...string) []C.Proxy {
	proxies := make([]C.Proxy, len(names))
	for i, name := range names {
		proxies[i] = capabilityDemotedProxy{
			strategyTestProxy{name: name, alive: true, addr: name, provider: "p"},
		}
	}
	return proxies
}

func TestRoundRobinKeepsDemotedProxiesInRotation(t *testing.T) {
	metadata := &C.Metadata{Host: "example.com"}
	proxies := demotedProxies("a", "b")
	strategy := strategyRoundRobin("test", false, true)

	seen := map[string]int{}
	for i := 0; i < 4; i++ {
		seen[strategy(proxies, metadata, true).Name()]++
	}
	if len(seen) != len(proxies) {
		t.Fatalf("全部节点被降权时轮换仍应覆盖所有节点，实际只用到 %v", seen)
	}
	for name, hits := range seen {
		if hits != 2 {
			t.Errorf("轮换应保持均匀，节点 %s 命中 %d 次", name, hits)
		}
	}
}

func TestConsistentHashingKeepsDemotedProxiesSelectable(t *testing.T) {
	metadata := &C.Metadata{Host: "example.com"}
	proxies := demotedProxies("a", "b", "c")
	strategy := strategyConsistentHashing("test", false, true)

	// 全部降权时仍必须选出一个存活节点，且映射保持稳定。
	first := strategy(proxies, metadata, false)
	if first == nil {
		t.Fatal("全部节点被降权时不应选不出节点")
	}
	second := strategy(proxies, metadata, false)
	if first.Name() != second.Name() {
		t.Fatalf("一致性哈希应稳定，得到 %q 与 %q", first.Name(), second.Name())
	}
}
