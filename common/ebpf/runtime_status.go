//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"reflect"
	"sort"
	"sync"

	CiliumEBPF "github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

type RuntimeMapStatus struct {
	Name         string `json:"name"`
	Type         string `json:"type"`
	ID           uint32 `json:"id,omitempty"`
	KeySize      uint32 `json:"key_size"`
	ValueSize    uint32 `json:"value_size"`
	MemlockBytes uint64 `json:"memlock_bytes,omitempty"`
	Entries      uint32 `json:"entries"`
	Capacity     uint32 `json:"capacity"`
	EntriesKnown bool   `json:"entries_known"`
	Error        string `json:"error,omitempty"`
}

type RuntimeProgramStatus struct {
	Name            string `json:"name"`
	Section         string `json:"section"`
	ID              uint32 `json:"id,omitempty"`
	MemlockBytes    uint64 `json:"memlock_bytes,omitempty"`
	RunCount        uint64 `json:"run_count,omitempty"`
	RuntimeNanos    uint64 `json:"runtime_ns,omitempty"`
	AverageNanos    uint64 `json:"average_ns_per_run,omitempty"`
	RecursionMisses uint64 `json:"recursion_misses,omitempty"`
	Loaded          bool   `json:"loaded"`
	Attached        bool   `json:"attached"`
	StatsKnown      bool   `json:"stats_known,omitempty"`
	AttachType      string `json:"attach_type,omitempty"`
	AttachmentMode  string `json:"attachment_mode,omitempty"`
	LinkID          uint32 `json:"link_id,omitempty"`
	Error           string `json:"error,omitempty"`
	StatsError      string `json:"stats_error,omitempty"`
}

type CgroupRuntimeStatus struct {
	UDPCleanupMode                 string                 `json:"udp_cleanup_mode"`
	TCPRedirectReservationFailures uint64                 `json:"tcp_redirect_reservation_failures"`
	UDPRedirectReservationFailures uint64                 `json:"udp_redirect_reservation_failures"`
	UDPRecoveryUpdateFailures      uint64                 `json:"udp_recovery_update_failures"`
	StatsError                     string                 `json:"stats_error,omitempty"`
	Maps                           []RuntimeMapStatus     `json:"maps"`
	Programs                       []RuntimeProgramStatus `json:"programs"`
}

type SharedNetworkRuntimeStatus struct {
	Maps     []RuntimeMapStatus     `json:"maps"`
	Programs []RuntimeProgramStatus `json:"programs"`
}

type runtimeStatusCollector struct {
	access       sync.Mutex
	batchSupport map[CiliumEBPF.MapType]*mapBatchSupport
}

func (c *runtimeStatusCollector) collect(maps map[string]*CiliumEBPF.Map) []RuntimeMapStatus {
	c.access.Lock()
	defer c.access.Unlock()
	if c.batchSupport == nil {
		c.batchSupport = make(map[CiliumEBPF.MapType]*mapBatchSupport)
	}
	names := make([]string, 0, len(maps))
	for name := range maps {
		names = append(names, name)
	}
	sort.Strings(names)
	status := make([]RuntimeMapStatus, 0, len(names))
	for _, name := range names {
		mapInstance := maps[name]
		entry := RuntimeMapStatus{Name: name}
		if mapInstance == nil {
			entry.Error = "map is unavailable"
			status = append(status, entry)
			continue
		}
		info, err := mapInstance.Info()
		if err != nil {
			entry.Error = err.Error()
			status = append(status, entry)
			continue
		}
		entry.Type = info.Type.String()
		entry.KeySize = info.KeySize
		entry.ValueSize = info.ValueSize
		entry.Capacity = info.MaxEntries
		if id, available := info.ID(); available {
			entry.ID = uint32(id)
		}
		if memlock, available := info.Memlock(); available {
			entry.MemlockBytes = memlock
		}
		if info.Type == CiliumEBPF.Array || info.Type == CiliumEBPF.PerCPUArray {
			entry.Entries = info.MaxEntries
			entry.EntriesKnown = true
			status = append(status, entry)
			continue
		}
		if !collectRuntimeMapEntries {
			status = append(status, entry)
			continue
		}
		if info.Type == CiliumEBPF.Hash || info.Type == CiliumEBPF.LPMTrie {
			support := c.batchSupport[info.Type]
			if support == nil {
				support = new(mapBatchSupport)
				c.batchSupport[info.Type] = support
			}
			entry.Entries, err = countMapEntriesEfficient(
				mapInstance,
				uintptr(info.KeySize),
				uintptr(info.ValueSize),
				info.MaxEntries,
				support,
			)
		} else {
			// Reading LRU values would refresh their eviction order. Key-only
			// traversal is slower but keeps diagnostics observational.
			entry.Entries, err = countMapEntries(
				mapInstance.FD(),
				uintptr(info.KeySize),
				info.MaxEntries,
			)
		}
		if err == nil {
			entry.EntriesKnown = true
		} else {
			entry.Error = err.Error()
		}
		status = append(status, entry)
	}
	return status
}

func countMapEntriesEfficient(
	mapInstance *CiliumEBPF.Map,
	keySize uintptr,
	valueSize uintptr,
	capacity uint32,
	support *mapBatchSupport,
) (uint32, error) {
	if keySize == 0 || valueSize == 0 || capacity == 0 {
		return 0, unix.EINVAL
	}
	if support.mode.Load() != mapBatchUnsupported {
		count, err := countMapEntriesBatch(mapInstance, keySize, valueSize, capacity)
		if err == nil {
			support.mode.CompareAndSwap(mapBatchUnknown, mapBatchSupported)
			return count, nil
		}
		if !mapBatchUnsupportedError(err) {
			return count, err
		}
		support.mode.Store(mapBatchUnsupported)
	}
	if mapInstance == nil {
		return 0, errBackendClosed
	}
	return countMapEntries(mapInstance.FD(), keySize, capacity)
}

func countMapEntriesBatch(mapInstance *CiliumEBPF.Map, keySize uintptr, valueSize uintptr, capacity uint32) (uint32, error) {
	if mapInstance == nil {
		return 0, errBackendClosed
	}
	batchCapacity := min(uint32(mapBatchMaxEntries), capacity)
	keyType := reflect.ArrayOf(int(keySize), reflect.TypeFor[byte]())
	valueType := reflect.ArrayOf(int(valueSize), reflect.TypeFor[byte]())
	keys := reflect.MakeSlice(reflect.SliceOf(keyType), int(batchCapacity), int(batchCapacity))
	values := reflect.MakeSlice(reflect.SliceOf(valueType), int(batchCapacity), int(batchCapacity))
	var cursor CiliumEBPF.MapBatchCursor
	var count uint32
	for count < capacity {
		batchSize := min(batchCapacity, capacity-count)
		batchCountValue, err := mapInstance.BatchLookup(
			&cursor,
			keys.Slice(0, int(batchSize)).Interface(),
			values.Slice(0, int(batchSize)).Interface(),
			nil,
		)
		batchCount := uint32(batchCountValue)
		count += batchCount
		if errors.Is(err, CiliumEBPF.ErrKeyNotExist) {
			return count, nil
		}
		if err != nil {
			return count, err
		}
		if batchCount == 0 {
			return count, unix.EIO
		}
	}
	return count, nil
}

func runtimeProgramStatus(program *CiliumEBPF.Program, name string, section string) RuntimeProgramStatus {
	status := RuntimeProgramStatus{Name: name, Section: section, Loaded: program != nil}
	if program == nil {
		return status
	}
	info, err := program.Info()
	if err != nil {
		status.Error = err.Error()
		return status
	}
	if id, available := info.ID(); available {
		status.ID = uint32(id)
	}
	if memlock, available := info.Memlock(); available {
		status.MemlockBytes = memlock
	}
	populateProgramRuntimeStats(program, &status)
	return status
}
