package outboundgroup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/common/callback"
	"github.com/metacubex/mihomo/common/lru"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"

	"golang.org/x/net/publicsuffix"
)

type LoadBalanceOption struct {
	Strategy string `group:"strategy,omitempty"`
}

type LoadBalance struct {
	*GroupBase
	disableUDP     bool
	strategyFn     strategyFn
	testUrl        string
	expectedStatus string
}

type strategyFn = func(proxies []C.Proxy, metadata *C.Metadata, touch bool) C.Proxy

var errStrategy = errors.New("unsupported strategy")

func getKey(metadata *C.Metadata) string {
	if metadata == nil {
		return ""
	}

	if metadata.Host != "" {
		// ip host
		if ip := net.ParseIP(metadata.Host); ip != nil {
			return metadata.Host
		}

		if etld, err := publicsuffix.EffectiveTLDPlusOne(metadata.Host); err == nil {
			return etld
		}
	}

	if !metadata.DstIP.IsValid() {
		return ""
	}

	return metadata.DstIP.String()
}

func getKeyWithSrcAndDst(metadata *C.Metadata) string {
	dst := getKey(metadata)
	src := ""
	if metadata != nil {
		src = metadata.SrcIP.String()
	}

	return fmt.Sprintf("%s%s", src, dst)
}

// DialContext implements C.ProxyAdapter
func (lb *LoadBalance) DialContext(ctx context.Context, metadata *C.Metadata) (c C.Conn, err error) {
	proxy := lb.Unwrap(metadata, true)
	c, err = proxy.DialContext(ctx, metadata)

	if err == nil {
		c.AppendToChains(lb)
	} else {
		lb.onDialFailed(proxy.Type(), err, lb.healthCheck)
	}

	if N.NeedHandshake(c) {
		c = callback.NewFirstWriteCallBackConn(c, func(err error) {
			if err == nil {
				lb.onDialSuccess()
			} else {
				lb.onDialFailed(proxy.Type(), err, lb.healthCheck)
			}
		})
	}

	return
}

// ListenPacketContext implements C.ProxyAdapter
func (lb *LoadBalance) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (pc C.PacketConn, err error) {
	defer func() {
		if err == nil {
			pc.AppendToChains(lb)
		}
	}()

	proxy := lb.Unwrap(metadata, true)
	return proxy.ListenPacketContext(ctx, metadata)
}

// SupportUDP implements C.ProxyAdapter
func (lb *LoadBalance) SupportUDP() bool {
	return !lb.disableUDP
}

// IsL3Protocol implements C.ProxyAdapter
func (lb *LoadBalance) IsL3Protocol(metadata *C.Metadata) bool {
	return lb.Unwrap(metadata, false).IsL3Protocol(metadata)
}

func strategyRoundRobin(url string, preferUDP, preferIPv6 bool) strategyFn {
	idx := 0
	idxMutex := sync.Mutex{}
	prefers := preferUDP || preferIPv6
	return func(proxies []C.Proxy, metadata *C.Metadata, touch bool) C.Proxy {
		idxMutex.Lock()
		defer idxMutex.Unlock()

		length := len(proxies)

		// Two passes: rotate among the nodes that meet the capability
		// preferences first, and only fall through to penalized ones when none
		// of them is alive. A node that failed a probe loses its turn in the
		// preferred rotation but stays in the group.
		for _, preferredOnly := range [2]bool{true, false} {
			for i := 0; i < length; i++ {
				proxy := proxies[(idx+i)%length]
				if !proxy.AliveForTestUrl(url) {
					continue
				}
				if preferredOnly && adapter.CapabilityPenalty(proxy, preferUDP, preferIPv6) != 0 {
					continue
				}
				if touch {
					idx = (idx + i + 1) % length
				}
				return proxy
			}
			if !prefers {
				break // the second pass would repeat the first
			}
		}

		return proxies[0]
	}
}

func strategyConsistentHashing(url string, preferUDP, preferIPv6 bool) strategyFn {
	return func(proxies []C.Proxy, metadata *C.Metadata, touch bool) C.Proxy {
		key := utils.MapHash(getKey(metadata))
		var best, bestAlive C.Proxy
		var bestScore, bestAliveScore uint64
		var bestAlivePenalty uint16
		for _, proxy := range proxies {
			score := rendezvousScore(key, proxyIdentity(proxy))
			if best == nil || score > bestScore {
				best, bestScore = proxy, score
			}
			if !proxy.AliveForTestUrl(url) {
				continue
			}
			// Rank by capability penalty first, then by rendezvous score, so
			// preferences pick the bucket and hashing stays stable within it.
			penalty := adapter.CapabilityPenalty(proxy, preferUDP, preferIPv6)
			if bestAlive == nil || penalty < bestAlivePenalty ||
				(penalty == bestAlivePenalty && score > bestAliveScore) {
				bestAlive, bestAliveScore, bestAlivePenalty = proxy, score, penalty
			}
		}
		if bestAlive != nil {
			return bestAlive
		}
		return best
	}
}

func rendezvousScore(key uint64, name string) uint64 {
	return utils.MapHash(fmt.Sprintf("%016x:%s", key, name))
}

func proxyIdentity(proxy C.Proxy) string {
	if proxy == nil {
		return ""
	}
	info := proxy.ProxyInfo()
	return fmt.Sprintf("%s|%s|%s|%s", proxy.Name(), proxy.Type().String(), info.ProviderName, proxy.Addr())
}

func strategyStickySessions(url string, preferUDP, preferIPv6 bool) strategyFn {
	ttl := time.Minute * 10
	lruCache := lru.New[uint64, string](
		lru.WithAge[uint64, string](int64(ttl.Seconds())),
		lru.WithSize[uint64, string](1000))
	return func(proxies []C.Proxy, metadata *C.Metadata, touch bool) C.Proxy {
		key := utils.MapHash(getKeyWithSrcAndDst(metadata))
		if identity, has := lruCache.Get(key); has {
			for _, proxy := range proxies {
				if proxyIdentity(proxy) == identity && proxy.AliveForTestUrl(url) {
					return proxy
				}
			}
		}

		var best, bestAlive C.Proxy
		var bestScore, bestAliveScore uint64
		var bestAlivePenalty uint16
		for _, proxy := range proxies {
			score := rendezvousScore(key, proxyIdentity(proxy))
			if best == nil || score > bestScore {
				best, bestScore = proxy, score
			}
			if !proxy.AliveForTestUrl(url) {
				continue
			}
			penalty := adapter.CapabilityPenalty(proxy, preferUDP, preferIPv6)
			if bestAlive == nil || penalty < bestAlivePenalty ||
				(penalty == bestAlivePenalty && score > bestAliveScore) {
				bestAlive, bestAliveScore, bestAlivePenalty = proxy, score, penalty
			}
		}
		if bestAlive != nil {
			lruCache.Set(key, proxyIdentity(bestAlive))
			return bestAlive
		}
		return best
	}
}

// Unwrap implements C.ProxyAdapter
func (lb *LoadBalance) Unwrap(metadata *C.Metadata, touch bool) C.Proxy {
	proxies := lb.GetProxies(touch)
	return lb.strategyFn(proxies, metadata, touch)
}

// MarshalJSON implements C.ProxyAdapter
func (lb *LoadBalance) MarshalJSON() ([]byte, error) {
	var all []string
	for _, proxy := range lb.GetProxies(false) {
		all = append(all, proxy.Name())
	}
	return json.Marshal(map[string]any{
		"type":           lb.Type().String(),
		"all":            all,
		"testUrl":        lb.testUrl,
		"expectedStatus": lb.expectedStatus,
		"hidden":         lb.Hidden(),
		"icon":           lb.Icon(),
		"emptyFallback":  lb.EmptyFallback().Name(),
	})
}

func (lb *LoadBalance) Providers() []P.ProxyProvider {
	return lb.providers
}

func (lb *LoadBalance) Proxies() []C.Proxy {
	return lb.GetProxies(false)
}

func (lb *LoadBalance) Now() string {
	return ""
}

func NewLoadBalance(option GroupCommonOption, loadBalanceOption LoadBalanceOption, emptyFallback C.Proxy, providers []P.ProxyProvider) (lb *LoadBalance, err error) {
	var strategyFn strategyFn
	switch loadBalanceOption.Strategy {
	case "", "consistent-hashing":
		strategyFn = strategyConsistentHashing(option.URL, option.PreferUDP, option.PreferIPv6)
	case "round-robin":
		strategyFn = strategyRoundRobin(option.URL, option.PreferUDP, option.PreferIPv6)
	case "sticky-sessions":
		strategyFn = strategyStickySessions(option.URL, option.PreferUDP, option.PreferIPv6)
	default:
		return nil, fmt.Errorf("%w: %s", errStrategy, loadBalanceOption.Strategy)
	}
	return &LoadBalance{
		GroupBase: NewGroupBase(GroupBaseOption{
			Name:             option.Name,
			Type:             C.LoadBalance,
			Hidden:           option.Hidden,
			Icon:             option.Icon,
			Filter:           option.Filter,
			ExcludeFilter:    option.ExcludeFilter,
			ExcludeType:      option.ExcludeType,
			TestTimeout:      option.TestTimeout,
			MaxFailedTimes:   option.MaxFailedTimes,
			EmptyFallback:    emptyFallback,
			PreferUDP:        option.PreferUDP,
			PenalizeUnstable: option.PenalizeUnstable,
			PreferIPv6:       option.PreferIPv6,
			Providers:        providers,
		}),
		strategyFn:     strategyFn,
		disableUDP:     option.DisableUDP,
		testUrl:        option.URL,
		expectedStatus: option.ExpectedStatus,
	}, nil
}
