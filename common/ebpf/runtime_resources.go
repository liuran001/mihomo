//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	CiliumEBPF "github.com/cilium/ebpf"
)

type RuntimeProgram struct {
	ID       CiliumEBPF.ProgramID   `json:"id"`
	Name     string                 `json:"name"`
	Type     CiliumEBPF.ProgramType `json:"type"`
	MapIDs   []CiliumEBPF.MapID     `json:"map_ids"`
	MapCount int                    `json:"map_count"`
}

type RuntimeState struct {
	Programs      []RuntimeProgram   `json:"programs"`
	ProgramsError error              `json:"-"`
	MapOccupancy  MapOccupancyReport `json:"maps"`
}

// RuntimeResources identifies resources held by one owner, not resources with
// matching names elsewhere on the host. IDs are snapshots: inspection may race
// with shutdown, in which case it reports an error instead of a false zero.
type RuntimeResources struct {
	Programs []CiliumEBPF.ProgramID
	Maps     []CiliumEBPF.MapID
	Error    error
}

func (r *RuntimeResources) add(programs []*CiliumEBPF.Program, maps map[string]*CiliumEBPF.Map) {
	for _, program := range programs {
		if program == nil {
			continue
		}
		info, err := program.Info()
		if err != nil {
			r.Error = errors.Join(r.Error, err)
			continue
		}
		if id, ok := info.ID(); ok {
			r.Programs = append(r.Programs, id)
		}
	}
	for _, m := range maps {
		if m == nil {
			continue
		}
		info, err := m.Info()
		if err != nil {
			r.Error = errors.Join(r.Error, err)
			continue
		}
		if id, ok := info.ID(); ok {
			r.Maps = append(r.Maps, id)
		}
	}
}

func (r *RuntimeResources) merge(other RuntimeResources) {
	r.Programs = append(r.Programs, other.Programs...)
	r.Maps = append(r.Maps, other.Maps...)
	r.Error = errors.Join(r.Error, other.Error)
}

func (b *TCBackend) RuntimeResources() (r RuntimeResources) {
	if b == nil {
		return
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime != nil {
		r.add(b.runtime.programs, b.runtime.maps)
	}
	r.merge(b.fakeIPICMP.RuntimeResources())
	return
}
func (b *CgroupBackend) RuntimeResources() (r RuntimeResources) {
	if b == nil {
		return
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime != nil {
		r.add(b.runtime.programs, b.runtime.maps)
	}
	return
}
func (b *SharedNetworkBackend) RuntimeResources() (r RuntimeResources) {
	if b == nil {
		return
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime != nil {
		r.add(b.runtime.programs, b.runtime.maps)
	}
	r.merge(b.fakeIPICMP.RuntimeResources())
	return
}
func (b *FakeIPICMPBackend) RuntimeResources() (r RuntimeResources) {
	if b == nil {
		return
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime != nil {
		r.add(b.runtime.programs, b.runtime.maps)
	}
	return
}
func (b *SelfBypass) RuntimeResources() (r RuntimeResources) {
	if b == nil {
		return
	}
	b.access.RLock()
	defer b.access.RUnlock()
	r.add(b.programs, map[string]*CiliumEBPF.Map{"sockets": b.sockets})
	return
}
func (b *ProcessTracker) RuntimeResources() (r RuntimeResources) {
	if b == nil {
		return
	}
	b.access.RLock()
	defer b.access.RUnlock()
	r.add(b.programs, map[string]*CiliumEBPF.Map{"owners": b.owners, "policy": b.policyUID, "metadata": b.metadata})
	return
}

func InspectRuntimeResources(owners ...RuntimeResources) RuntimeState {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	return InspectRuntimeResourcesContext(ctx, owners...)
}

func InspectRuntimeResourcesContext(ctx context.Context, owners ...RuntimeResources) RuntimeState {
	var resources RuntimeResources
	for _, owner := range owners {
		resources.merge(owner)
	}
	slices.Sort(resources.Programs)
	slices.Sort(resources.Maps)
	resources.Programs = slices.Compact(resources.Programs)
	resources.Maps = slices.Compact(resources.Maps)
	state := RuntimeState{ProgramsError: resources.Error, MapOccupancy: MapOccupancyReport{Status: "pass"}}
	if resources.Error != nil {
		state.MapOccupancy.Error = resources.Error.Error()
	}
	for _, id := range resources.Programs {
		if err := ctx.Err(); err != nil {
			state.ProgramsError = errors.Join(state.ProgramsError, err)
			break
		}
		program, err := CiliumEBPF.NewProgramFromID(id)
		if err != nil {
			state.ProgramsError = errors.Join(state.ProgramsError, err)
			continue
		}
		info, err := program.Info()
		_ = program.Close()
		if err != nil {
			state.ProgramsError = errors.Join(state.ProgramsError, err)
			continue
		}
		mapIDs, _ := info.MapIDs()
		state.Programs = append(state.Programs, RuntimeProgram{ID: id, Name: info.Name, Type: info.Type, MapIDs: mapIDs, MapCount: len(mapIDs)})
	}
	for _, id := range resources.Maps {
		if err := ctx.Err(); err != nil {
			state.MapOccupancy.Error = err.Error()
			break
		}
		m, err := CiliumEBPF.NewMapFromID(id)
		if err != nil {
			state.MapOccupancy.Maps = append(state.MapOccupancy.Maps, MapOccupancy{ID: id, Error: fmt.Sprint(err), Pressure: "unavailable"})
			continue
		}
		info, err := m.Info()
		if err != nil {
			_ = m.Close()
			state.MapOccupancy.Maps = append(state.MapOccupancy.Maps, MapOccupancy{ID: id, Error: fmt.Sprint(err), Pressure: "unavailable"})
			continue
		}
		state.MapOccupancy.Maps = append(state.MapOccupancy.Maps, inspectMapOccupancy(ctx, m, id, info))
		_ = m.Close()
	}
	state.MapOccupancy.Status = mapOccupancyStatus(state.MapOccupancy.Maps)
	if state.MapOccupancy.Error != "" {
		state.MapOccupancy.Status = "unknown"
	}
	return state
}
