//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"testing"

	CiliumEBPF "github.com/cilium/ebpf"
)

type occupancyTestIterator struct {
	calls  int
	limit  int
	cancel context.CancelFunc
}

func (iterator *occupancyTestIterator) NextKey(key, nextKey any) error {
	iterator.calls++
	if iterator.cancel != nil && iterator.calls == 64 {
		iterator.cancel()
	}
	if iterator.limit >= 0 && iterator.calls > iterator.limit {
		return CiliumEBPF.ErrKeyNotExist
	}
	return nil
}

func TestMapOccupancyIterationIsBounded(t *testing.T) {
	iterator := &occupancyTestIterator{limit: -1}
	entries, err := countMapKeys(context.Background(), iterator, 4, 1<<20)
	if err != errMapKeyIterationAborted || entries != mapOccupancyKeyBudget || iterator.calls > mapOccupancyKeyBudget+1 {
		t.Fatalf("unbounded scan: entries=%d calls=%d err=%v", entries, iterator.calls, err)
	}
}

func TestMapOccupancyIterationHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	iterator := &occupancyTestIterator{limit: -1, cancel: cancel}
	_, err := countMapKeys(ctx, iterator, 4, 1<<20)
	if err != context.Canceled || iterator.calls > 65 {
		t.Fatalf("scan ignored cancellation: calls=%d err=%v", iterator.calls, err)
	}
	iterator.calls = 0
	_, err = countMapKeys(ctx, iterator, 4, 1<<20)
	if err != context.Canceled || iterator.calls != 0 {
		t.Fatalf("cancelled scan still accessed map: calls=%d err=%v", iterator.calls, err)
	}
}

func TestMapOccupancyExactCapacity(t *testing.T) {
	iterator := &occupancyTestIterator{limit: 4}
	entries, err := countMapKeys(context.Background(), iterator, 4, 4)
	if entries != 4 || err != nil {
		t.Fatalf("full map: entries=%d err=%v", entries, err)
	}
}

func TestMapOccupancyCacheClassification(t *testing.T) {
	if category := metadataForMapName("sb_sh_bypass").category; category != MapCategoryCache {
		t.Fatalf("sb_sh_bypass category = %s", category)
	}
	if pressure := mapPressure(MapCategoryCache, 16384, 16384, false); pressure != "cache" {
		t.Fatalf("full cache pressure = %s", pressure)
	}
	// Policy tables sharing the prefix keep their own classification.
	for _, name := range []string{"sb_sh_bypass4", "sb_sh_bypass6"} {
		if category := metadataForMapName(name).category; category != MapCategoryConfiguredPolicy {
			t.Errorf("%s category = %s", name, category)
		}
	}
	// LRU maps holding live connection state still report pressure.
	for _, name := range []string{"sb_cg_tcp", "sb_cg_flow", "sb_tc_assign"} {
		category := metadataForMapName(name).category
		if category != MapCategoryRuntime {
			t.Errorf("%s category = %s", name, category)
		}
		if pressure := mapPressure(category, 100, 100, false); pressure != "degraded" {
			t.Errorf("full %s pressure = %s", name, pressure)
		}
	}
	maps := []MapOccupancy{{Pressure: "healthy"}, {Pressure: "cache"}, {Pressure: "configured"}}
	if got := mapOccupancyStatus(maps); got != "pass" {
		t.Fatalf("full cache status = %s, want pass", got)
	}
}

func TestMapOccupancyPolicyClassification(t *testing.T) {
	for _, name := range []string{"sb_cg_lforce4", "sb_sh_sforce6", "sb_sh_inc4", "sb_sh_exc6", "sb_cg_bypass_po", "sb_tc_lport"} {
		category := metadataForMapName(name).category
		if category != MapCategoryConfiguredPolicy {
			t.Errorf("%s category = %s", name, category)
		}
		if pressure := mapPressure(category, 1, 1, false); pressure != "configured" {
			t.Errorf("full policy %s pressure = %s", name, pressure)
		}
	}
	if pressure := mapPressure(MapCategoryRuntime, 95, 100, false); pressure != "degraded" {
		t.Fatalf("runtime pressure = %s", pressure)
	}
	if pressure := mapPressure(MapCategoryCache, 0, 100, true); pressure != "unavailable" {
		t.Fatalf("failed cache inspection pressure = %s", pressure)
	}
	if pressure := mapPressure(MapCategoryRuntime, 0, 100, true); pressure != "unavailable" {
		t.Fatalf("failed inspection pressure = %s", pressure)
	}
	for _, pressures := range [][]string{{"warning", "unavailable"}, {"unavailable", "warning"}, {"unavailable", "degraded"}} {
		maps := make([]MapOccupancy, len(pressures))
		for i, pressure := range pressures {
			maps[i].Pressure = pressure
		}
		want := "unknown"
		if pressures[len(pressures)-1] == "degraded" {
			want = "degraded"
		}
		if got := mapOccupancyStatus(maps); got != want {
			t.Errorf("%v status = %s, want %s", pressures, got, want)
		}
	}
}
