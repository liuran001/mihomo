package provider

import (
	"encoding/json"
	"sync"
	"testing"

	"github.com/metacubex/mihomo/component/resource"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
)

type summaryVehicle struct {
	P.Vehicle
}

func (summaryVehicle) Type() P.VehicleType { return P.HTTP }

func TestProviderSummaryDoesNotInspectProxies(t *testing.T) {
	fetcher := resource.NewFetcher[[]C.Proxy]("test", 0, summaryVehicle{}, nil, nil, nil)
	defer fetcher.Close()
	source := &proxySetProvider{baseProvider: baseProvider{proxies: make([]C.Proxy, 10000)}, Fetcher: fetcher}
	source.subscriptionInfo.Store(&SubscriptionInfo{Total: 1234})
	summary := source.Summary()
	if summary.Count != 10000 || summary.Name != "test" || summary.SubscriptionInfo.Total != 1234 {
		t.Fatalf("unexpected summary: %+v", summary)
	}
	encoded, err := json.Marshal(summary)
	if err != nil || len(encoded) > 512 {
		t.Fatalf("summary scales with provider nodes: bytes=%d err=%v", len(encoded), err)
	}
	var workers sync.WaitGroup
	workers.Go(func() {
		for count := range 100 {
			source.subscriptionInfo.Store(&SubscriptionInfo{Total: int64(count)})
		}
	})
	for range 100 {
		source.Summary()
	}
	workers.Wait()
}
