//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"errors"
	"testing"

	"github.com/sagernet/netlink"
)

func TestInstallSharedTCFilterRollsBackWhenOldFilterDeleteFails(t *testing.T) {
	deleteErr := errors.New("delete old filter")
	oldFilter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{Handle: netlink.MakeHandle(0, 99)},
		Name:        "sb_share_in",
	}
	newFilter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{Handle: netlink.MakeHandle(0, sharedIngressFilterHandle)},
		Name:        "sb_share_in",
	}
	var added bool
	var deletedNew bool
	previousAdd := sharedTCFilterAdd
	previousDel := sharedTCFilterDel
	t.Cleanup(func() {
		sharedTCFilterAdd = previousAdd
		sharedTCFilterDel = previousDel
	})
	sharedTCFilterAdd = func(filter netlink.Filter) error {
		if filter != newFilter {
			t.Fatalf("unexpected filter added: %p", filter)
		}
		added = true
		return nil
	}
	sharedTCFilterDel = func(filter netlink.Filter) error {
		switch filter {
		case oldFilter:
			return deleteErr
		case newFilter:
			deletedNew = true
			return nil
		default:
			t.Fatalf("unexpected filter deleted: %p", filter)
			return nil
		}
	}

	installed, err := installSharedTCFilter(newFilter, []netlink.Filter{oldFilter})
	if installed != nil {
		t.Fatalf("unexpected installed filter: %v", installed)
	}
	if !errors.Is(err, deleteErr) {
		t.Fatalf("expected old filter delete error, got %v", err)
	}
	if !added || !deletedNew {
		t.Fatalf("rollback incomplete: added=%v deletedNew=%v", added, deletedNew)
	}
}

func TestSharedTCFilterIdentity(t *testing.T) {
	expected := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			Handle:   netlink.MakeHandle(0, sharedIngressFilterHandle),
			Priority: 1,
			Protocol: 0x0003,
		},
		Name:         "sb_share_in",
		DirectAction: true,
		Fd:           7,
		Id:           8,
		Tag:          "cafebabe",
	}
	for name, filter := range map[string]*netlink.BpfFilter{
		"matching": {
			FilterAttrs:  expected.FilterAttrs,
			Name:         expected.Name,
			DirectAction: expected.DirectAction,
			Fd:           expected.Fd,
			Id:           expected.Id,
			Tag:          expected.Tag,
		},
		"wrong handle": {
			FilterAttrs: netlink.FilterAttrs{Handle: netlink.MakeHandle(0, sharedEgressFilterHandle)},
			Name:        expected.Name,
		},
		"wrong name": {
			FilterAttrs: expected.FilterAttrs,
			Name:        "other",
		},
		"wrong priority": {
			FilterAttrs: netlink.FilterAttrs{Handle: expected.Attrs().Handle, Priority: expected.Attrs().Priority + 1},
			Name:        expected.Name,
		},
		"wrong protocol": {
			FilterAttrs: netlink.FilterAttrs{Handle: expected.Attrs().Handle, Protocol: expected.Attrs().Protocol + 1},
			Name:        expected.Name,
		},
		"wrong direct action": {
			FilterAttrs:  expected.FilterAttrs,
			Name:         expected.Name,
			DirectAction: false,
		},
		"wrong id": {
			FilterAttrs: expected.FilterAttrs,
			Name:        expected.Name,
			Id:          42,
		},
		"wrong tag": {
			FilterAttrs: expected.FilterAttrs,
			Name:        expected.Name,
			Tag:         "deadbeef",
		},
	} {
		t.Run(name, func(t *testing.T) {
			matching := sharedTCFilterMatches(filter, expected)
			if matching != (name == "matching") {
				t.Fatalf("matching=%v", matching)
			}
		})
	}
}
