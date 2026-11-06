//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"cmp"
	"context"
	"slices"
	"sync"
	"time"

	ECommon "github.com/metacubex/mihomo/common/ebpf"
)

var ebpfDiagnostics = struct {
	sync.RWMutex
	next     uint64
	inbounds map[*Inbound]uint64
}{inbounds: make(map[*Inbound]uint64)}

type InboundDiagnostics struct {
	ID              uint64                   `json:"id"`
	Mode            string                   `json:"mode"`
	LocalDataPlane  string                   `json:"local_data_plane"`
	SharedDataPlane string                   `json:"shared_data_plane"`
	SelfBypass      string                   `json:"self_bypass"`
	Maintenance     []ECommon.MapMaintenance `json:"maintenance"`
	Resources       *ECommon.RuntimeState    `json:"resources,omitempty"`
	ResourceError   string                   `json:"resource_error,omitempty"`
}

func (i *Inbound) registerDiagnostics() {
	ebpfDiagnostics.Lock()
	defer ebpfDiagnostics.Unlock()
	ebpfDiagnostics.next++
	ebpfDiagnostics.inbounds[i] = ebpfDiagnostics.next
}

func (i *Inbound) unregisterDiagnostics() {
	ebpfDiagnostics.Lock()
	defer ebpfDiagnostics.Unlock()
	delete(ebpfDiagnostics.inbounds, i)
}

// Diagnostics inspects only resources held by this process's active inbounds.
// It is explicitly requested by the controller; no worker counts map keys.
func Diagnostics() []InboundDiagnostics {
	return DiagnosticsContext(context.Background())
}

func DiagnosticsSummary() []InboundDiagnostics {
	result, _ := collectDiagnostics(false)
	return result
}

func collectDiagnostics(detailed bool) ([]InboundDiagnostics, map[uint64][]ECommon.RuntimeResources) {
	ebpfDiagnostics.RLock()
	defer ebpfDiagnostics.RUnlock()
	result := make([]InboundDiagnostics, 0, len(ebpfDiagnostics.inbounds))
	resources := make(map[uint64][]ECommon.RuntimeResources)
	for i, id := range ebpfDiagnostics.inbounds {
		d := InboundDiagnostics{ID: id, Mode: i.mode, LocalDataPlane: i.localDataPlane, SharedDataPlane: i.sharedDataPlane, SelfBypass: i.selfBypassMode()}
		var owners []ECommon.RuntimeResources
		if detailed {
			owners = append(owners, i.selfBypass.RuntimeResources(), i.processTracker.RuntimeResources())
		}
		if b := i.cgroupBackendInstance(); b != nil {
			if detailed {
				owners = append(owners, b.RuntimeResources())
			}
			d.Maintenance = append(d.Maintenance, b.MapMaintenance()...)
		}
		if b := i.tcBackend(); b != nil {
			if detailed {
				owners = append(owners, b.RuntimeResources())
			}
			d.Maintenance = append(d.Maintenance, b.MapMaintenance()...)
		}
		if i.sharedRewrite != nil {
			if b := i.sharedRewrite.sharedBackendInstance(); b != nil {
				if detailed {
					owners = append(owners, b.RuntimeResources())
				}
				d.Maintenance = append(d.Maintenance, b.MapMaintenance()...)
			}
		}
		if detailed {
			resources[id] = owners
		}
		result = append(result, d)
	}
	slices.SortFunc(result, func(a, b InboundDiagnostics) int { return cmp.Compare(a.ID, b.ID) })
	return result, resources
}

func DiagnosticsContext(ctx context.Context) []InboundDiagnostics {
	ctx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	result, resources := collectDiagnostics(true)
	for index := range result {
		state := ECommon.InspectRuntimeResourcesContext(ctx, resources[result[index].ID]...)
		result[index].Resources = &state
		if state.ProgramsError != nil {
			result[index].ResourceError = state.ProgramsError.Error()
		}
	}
	return result
}
