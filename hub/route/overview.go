package route

import (
	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
	"github.com/metacubex/mihomo/adapter/provider"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel"
)

type overviewExit struct {
	Chain []string `json:"chain"`
	Smart bool     `json:"smart"`
}

func overviewExitChain(mode tunnel.TunnelMode, rules []C.Rule, proxies map[string]C.Proxy) overviewExit {
	target := "GLOBAL"
	if mode == tunnel.Direct {
		target = "DIRECT"
	} else if mode == tunnel.Rule {
		for index := len(rules) - 1; index >= 0; index-- {
			rule := rules[index]
			if rule.RuleType() == C.MATCH {
				target = rule.Adapter()
				break
			}
		}
	}
	exit := overviewExit{Chain: make([]string, 0, 4)}
	seen := make(map[string]bool)
	proxy := proxies[target]
	for proxy != nil && len(exit.Chain) < 32 && !seen[proxy.Name()] {
		seen[proxy.Name()] = true
		exit.Chain = append(exit.Chain, proxy.Name())
		switch proxy.Type() {
		case C.Smart:
			exit.Smart = true
			return exit
		case C.LoadBalance:
			return exit
		case C.Selector, C.Fallback, C.URLTest, C.Relay:
			proxy = proxy.Adapter().Unwrap(nil, false)
		default:
			return exit
		}
	}
	return exit
}

func getOverview(writer http.ResponseWriter, request *http.Request) {
	providers := make(map[string]provider.ProxyProviderSummary)
	for name, source := range tunnel.Providers() {
		if summary, ok := source.(interface {
			Summary() provider.ProxyProviderSummary
		}); ok {
			providers[name] = summary.Summary()
		}
	}
	render.JSON(writer, request, render.M{
		"exit": overviewExitChain(tunnel.Mode(), tunnel.Rules(), tunnel.Proxies()), "providers": providers,
	})
}
