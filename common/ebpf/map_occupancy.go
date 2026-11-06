//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"errors"

	CiliumEBPF "github.com/cilium/ebpf"
)

// MapOccupancy describes one sing-ebpf map observed by an explicit diagnostic
// request. It is intentionally not collected by any runtime worker.
type MapOccupancy struct {
	ID         CiliumEBPF.MapID `json:"id"`
	Name       string           `json:"name"`
	Category   MapCategory      `json:"category"`
	Type       string           `json:"type"`
	MaxEntries uint32           `json:"max_entries"`
	KeySize    uint32           `json:"key_size"`
	ValueSize  uint32           `json:"value_size"`
	Flags      uint32           `json:"flags"`
	Entries    uint32           `json:"entries,omitempty"`
	Pressure   string           `json:"pressure"`
	Supported  bool             `json:"supported"`
	Error      string           `json:"error,omitempty"`
}

// MapCategory identifies the semantic role used when interpreting map
// occupancy diagnostics.
type MapCategory string

const (
	// MapCategoryRuntime identifies maps that hold live runtime state.
	MapCategoryRuntime MapCategory = "runtime"
	// MapCategoryConfiguredPolicy identifies maps whose capacity is derived
	// from the currently compiled policy.
	MapCategoryConfiguredPolicy MapCategory = "configured_policy"
)

// mapMetadata is the library-owned semantic metadata for a kernel map. The
// kernel exposes only its name and layout through map info; keeping the
// classification here prevents consumers from duplicating sing-ebpf's map
// naming scheme.
type mapMetadata struct {
	category MapCategory
}

var configuredPolicyMapMetadata = map[string]mapMetadata{
	"sb_cg_bypass4":  {category: MapCategoryConfiguredPolicy},
	"sb_cg_bypass6":  {category: MapCategoryConfiguredPolicy},
	"sb_tc_bypass4":  {category: MapCategoryConfiguredPolicy},
	"sb_tc_bypass6":  {category: MapCategoryConfiguredPolicy},
	"sb_tc_sbypass4": {category: MapCategoryConfiguredPolicy},
	"sb_tc_sbypass6": {category: MapCategoryConfiguredPolicy},
	"sb_tc_host4":    {category: MapCategoryConfiguredPolicy},
	"sb_tc_host6":    {category: MapCategoryConfiguredPolicy},
	"sb_cg_host4":    {category: MapCategoryConfiguredPolicy},
	"sb_cg_host6":    {category: MapCategoryConfiguredPolicy},
	"sb_sh_host4":    {category: MapCategoryConfiguredPolicy},
	"sb_sh_host6":    {category: MapCategoryConfiguredPolicy},
	"sb_sh_bypass4":  {category: MapCategoryConfiguredPolicy},
	"sb_sh_bypass6":  {category: MapCategoryConfiguredPolicy},

	"sb_cg_lforce4":     {category: MapCategoryConfiguredPolicy},
	"sb_cg_lforce6":     {category: MapCategoryConfiguredPolicy},
	"sb_tc_lforce4":     {category: MapCategoryConfiguredPolicy},
	"sb_tc_lforce6":     {category: MapCategoryConfiguredPolicy},
	"sb_tc_sforce4":     {category: MapCategoryConfiguredPolicy},
	"sb_tc_sforce6":     {category: MapCategoryConfiguredPolicy},
	"sb_sh_sforce4":     {category: MapCategoryConfiguredPolicy},
	"sb_sh_sforce6":     {category: MapCategoryConfiguredPolicy},
	"sb_icmp_lforce4":   {category: MapCategoryConfiguredPolicy},
	"sb_icmp_lforce6":   {category: MapCategoryConfiguredPolicy},
	"sb_icmp_sforce4":   {category: MapCategoryConfiguredPolicy},
	"sb_icmp_sforce6":   {category: MapCategoryConfiguredPolicy},
	"sb_cg_bypass_port": {category: MapCategoryConfiguredPolicy},
	"sb_cg_uid":         {category: MapCategoryConfiguredPolicy},
	"sb_proc_uid":       {category: MapCategoryConfiguredPolicy},
	"sb_tc_uid":         {category: MapCategoryConfiguredPolicy},
	"sb_tc_insrc4":      {category: MapCategoryConfiguredPolicy},
	"sb_tc_insrc6":      {category: MapCategoryConfiguredPolicy},
	"sb_tc_exsrc4":      {category: MapCategoryConfiguredPolicy},
	"sb_tc_exsrc6":      {category: MapCategoryConfiguredPolicy},
	"sb_tc_insmac":      {category: MapCategoryConfiguredPolicy},
	"sb_tc_exsmac":      {category: MapCategoryConfiguredPolicy},
	"sb_tc_lport":       {category: MapCategoryConfiguredPolicy},
	"sb_tc_sport":       {category: MapCategoryConfiguredPolicy},
	"sb_sh_inc4":        {category: MapCategoryConfiguredPolicy},
	"sb_sh_inc6":        {category: MapCategoryConfiguredPolicy},
	"sb_sh_exc4":        {category: MapCategoryConfiguredPolicy},
	"sb_sh_exc6":        {category: MapCategoryConfiguredPolicy},
	"sb_sh_inmac":       {category: MapCategoryConfiguredPolicy},
	"sb_sh_exmac":       {category: MapCategoryConfiguredPolicy},
	"sb_sh_port":        {category: MapCategoryConfiguredPolicy},
}

func metadataForMapName(name string) mapMetadata {
	for fullName, metadata := range configuredPolicyMapMetadata {
		// BPF_OBJ_NAME_LEN includes the trailing NUL.
		if name == fullName[:min(len(fullName), 15)] {
			return metadata
		}
	}
	return mapMetadata{category: MapCategoryRuntime}
}

type MapOccupancyReport struct {
	Status string         `json:"status"`
	Maps   []MapOccupancy `json:"maps"`
	Error  string         `json:"error,omitempty"`
}

func inspectMapOccupancy(ctx context.Context, m *CiliumEBPF.Map, id CiliumEBPF.MapID, info *CiliumEBPF.MapInfo) MapOccupancy {
	item := MapOccupancy{ID: id, Name: info.Name, Category: metadataForMapName(info.Name).category, Type: info.Type.String(),
		MaxEntries: info.MaxEntries, KeySize: info.KeySize, ValueSize: info.ValueSize, Flags: info.Flags}
	if !occupancySupported(info.Type) {
		item.Pressure = "not_applicable"
		return item
	}
	item.Supported = true
	var err error
	item.Entries, err = countMapKeys(ctx, m, info.KeySize, info.MaxEntries)
	if err != nil {
		item.Error = err.Error()
	}
	item.Pressure = mapPressure(item.Category, item.Entries, item.MaxEntries, item.Error != "")
	return item
}

func mapOccupancyStatus(maps []MapOccupancy) string {
	status := "pass"
	for _, item := range maps {
		if item.Pressure == "degraded" {
			return "degraded"
		} else if item.Pressure == "unavailable" {
			status = "unknown"
		} else if item.Pressure == "warning" && status == "pass" {
			status = "warning"
		}
	}
	return status
}

func mapPressure(category MapCategory, entries, maxEntries uint32, failed bool) string {
	if failed {
		return "unavailable"
	}
	if category == MapCategoryConfiguredPolicy {
		return "configured"
	}
	if maxEntries == 0 {
		return "unknown"
	}
	ratio := float64(entries) / float64(maxEntries)
	switch {
	case ratio >= 0.95:
		return "degraded"
	case ratio >= 0.85:
		return "warning"
	default:
		return "healthy"
	}
}

var errMapKeyIterationAborted = errors.New("map key iteration aborted")

const mapOccupancyKeyBudget = 16384

type mapKeyIterator interface {
	NextKey(key, nextKey any) error
}

func countMapKeys(ctx context.Context, iterator mapKeyIterator, keySize uint32, maxEntries uint32) (uint32, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	key := make([]byte, keySize)
	next := make([]byte, keySize)
	err := iterator.NextKey(nil, &next)
	var entries uint32
	for err == nil {
		if entries%64 == 0 {
			if err := ctx.Err(); err != nil {
				return entries, err
			}
		}
		if entries >= min(maxEntries, mapOccupancyKeyBudget) {
			return entries, errMapKeyIterationAborted
		}
		entries++
		copy(key, next)
		err = iterator.NextKey(key, &next)
	}
	if errors.Is(err, CiliumEBPF.ErrKeyNotExist) {
		return entries, nil
	}
	return entries, err
}

func occupancySupported(typ CiliumEBPF.MapType) bool {
	switch typ {
	case CiliumEBPF.Hash, CiliumEBPF.LRUHash, CiliumEBPF.LPMTrie:
		return true
	default:
		return false
	}
}
