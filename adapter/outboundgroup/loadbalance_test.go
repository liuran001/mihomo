package outboundgroup

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/metacubex/mihomo/adapter"
	C "github.com/metacubex/mihomo/constant"
)

var capabilityTestSequence atomic.Uint64

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

// StatusTest 必须存在：strategyTestProxy 内嵌的是 nil 的 C.Proxy，一旦某个策略
// 触发能力探测，探测 goroutine 就会在这个 nil 接口上空指针解引用，直接带走整个
// 测试进程（而不是让某个测试失败）。
func (p strategyTestProxy) StatusTest(context.Context, string) (uint16, bool, error) {
	return 0, false, errors.New("capability probe unavailable in tests")
}

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

func TestUniqueProxiesByNameOmitsProviderCollisions(t *testing.T) {
	first := strategyTestProxy{name: "same", addr: "one", provider: "p1", alive: true}
	second := strategyTestProxy{name: "same", addr: "two", provider: "p2", alive: true}
	unique := strategyTestProxy{name: "unique", addr: "three", provider: "p3", alive: true}

	byName := uniqueProxiesByName([]C.Proxy{first, second, unique})
	if _, ok := byName["same"]; ok {
		t.Fatal("ambiguous provider name was retained in cache lookup")
	}
	if got := byName["unique"]; got != unique {
		t.Fatalf("unique proxy lookup = %v, want %v", got, unique)
	}
}

func TestStickySessionsSeparatesDelimiterCollisions(t *testing.T) {
	metadata := &C.Metadata{Host: "example.com"}
	strategy := strategyStickySessions("test", false, false)
	a := strategyTestProxy{name: "same", provider: "provider|segment", addr: "endpoint", alive: true}
	b := strategyTestProxy{name: "same", provider: "provider", addr: "segment|endpoint", alive: true}

	first := strategy([]C.Proxy{a, b}, metadata, false)
	second := strategy([]C.Proxy{b, a}, metadata, false)
	if first.ProxyInfo().ProviderName != second.ProxyInfo().ProviderName || first.Addr() != second.Addr() {
		t.Fatalf(
			"delimiter collision migrated sticky session from provider=%q addr=%q to provider=%q addr=%q",
			first.ProxyInfo().ProviderName, first.Addr(), second.ProxyInfo().ProviderName, second.Addr(),
		)
	}
}

func TestConsistentHashingSeparatesDelimiterCollisions(t *testing.T) {
	metadata := &C.Metadata{Host: "example.com"}
	strategy := strategyConsistentHashing("test", false, false)
	a := strategyTestProxy{name: "same", provider: "provider|segment", addr: "endpoint", alive: true}
	b := strategyTestProxy{name: "same", provider: "provider", addr: "segment|endpoint", alive: true}

	first := strategy([]C.Proxy{a, b}, metadata, false)
	second := strategy([]C.Proxy{b, a}, metadata, false)
	if first.ProxyInfo().ProviderName != second.ProxyInfo().ProviderName || first.Addr() != second.Addr() {
		t.Fatalf(
			"delimiter collision migrated consistent hash from provider=%q addr=%q to provider=%q addr=%q",
			first.ProxyInfo().ProviderName, first.Addr(), second.ProxyInfo().ProviderName, second.Addr(),
		)
	}
}

func TestStickySessionKeySeparatesSourceAndDestinationLengths(t *testing.T) {
	a := stickySessionKey("ab", "c")
	b := stickySessionKey("a", "bc")
	if a == b {
		t.Fatalf("sticky keys unexpectedly collide: %q", a)
	}
}

func TestDelayExceedsToleranceDoesNotWrap(t *testing.T) {
	if delayExceedsTolerance(0xFFFF, 0xFFFF, 100) {
		t.Fatal("maximal candidate plus tolerance must not wrap and trigger a switch")
	}
	if !delayExceedsTolerance(0xFFFF, 0xFF00, 100) {
		t.Fatal("a materially faster candidate should exceed the tolerance")
	}
	if delayExceedsTolerance(100, 0xFFFF, 100) {
		t.Fatal("a low current delay should not exceed a maximal candidate")
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

// 亲和性策略的映射必须与 capability 判定完全无关。判定会随探测从 unknown 变成
// confirmed，若它参与排序，探测落地就会把活跃会话迁到别的节点上 —— 这正是
// TestConsistentHashingKeepsDemotedProxiesSelectable 在 -count=2 下偶发失败的原因。
func TestAffinityStrategiesIgnoreCapabilityVerdicts(t *testing.T) {
	metadata := &C.Metadata{Host: "example.com"}
	// 混合节点：demoted 的探测必定失败，普通的保持 unknown。
	mixed := []C.Proxy{
		capabilityDemotedProxy{strategyTestProxy{name: "a", alive: true, addr: "a", provider: "p"}},
		strategyTestProxy{name: "b", alive: true, addr: "b", provider: "p"},
		capabilityDemotedProxy{strategyTestProxy{name: "c", alive: true, addr: "c", provider: "p"}},
	}
	// 同一批节点，同样的身份，但不开启任何能力偏好 —— 这是纯哈希的基准答案。
	plain := []C.Proxy{
		strategyTestProxy{name: "a", alive: true, addr: "a", provider: "p"},
		strategyTestProxy{name: "b", alive: true, addr: "b", provider: "p"},
		strategyTestProxy{name: "c", alive: true, addr: "c", provider: "p"},
	}

	for _, testCase := range []struct {
		name  string
		build func(preferIPv6 bool) strategyFn
	}{
		{name: "consistent-hashing", build: func(preferIPv6 bool) strategyFn {
			return strategyConsistentHashing("test", false, preferIPv6)
		}},
		{name: "sticky-sessions", build: func(preferIPv6 bool) strategyFn {
			return strategyStickySessions("test", false, preferIPv6)
		}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			want := testCase.build(false)(plain, metadata, false).Name()
			withPreference := testCase.build(true)
			// 反复调用：任何一次探测在调用之间落地都不得改变结果。
			for i := 0; i < 8; i++ {
				if got := withPreference(mixed, metadata, false).Name(); got != want {
					t.Fatalf("第 %d 次调用被能力判定改写了映射：得到 %q，纯哈希应为 %q", i+1, got, want)
				}
			}
		})
	}
}

// 未完成的探测不是降权：把 unknown 当成已确认失败，会让刚加载的大机场里每个
// 节点都被判定为降权，首轮轮换直接跳过全部节点。
func TestCapabilityDemotedIgnoresUnfinishedProbe(t *testing.T) {
	// 能力缓存是进程级全局的，判定一旦落地就会留在里面。用唯一身份保证每次调用
	// 看到的都是「探测尚未出结果」这个状态，否则 -count>1 时第二轮读到的是上一轮
	// 的结果。
	unique := fmt.Sprintf("%s-%d", t.Name(), capabilityTestSequence.Add(1))
	fresh := strategyTestProxy{name: unique, alive: true, addr: unique, provider: unique}
	if adapter.CapabilityDemoted(fresh, false, true) {
		t.Fatal("尚未出结果的探测不应被当作确认失败")
	}
	if adapter.CapabilityDemoted(nil, false, true) {
		t.Fatal("nil 节点不应被判定为降权")
	}
	if adapter.CapabilityDemoted(fresh, false, false) {
		t.Fatal("未开启任何偏好时不应有降权")
	}
}
