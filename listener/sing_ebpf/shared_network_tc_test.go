//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"errors"
	"testing"

	"github.com/sagernet/netlink"
)

func TestInstallSharedTCFilterRetainsReplacementWhenOldFilterDeleteFails(t *testing.T) {
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
	if installed != newFilter {
		t.Fatalf("replacement was not retained: %v", installed)
	}
	if !errors.Is(err, deleteErr) {
		t.Fatalf("expected old filter delete error, got %v", err)
	}
	if !added || deletedNew {
		t.Fatalf("replacement ownership was lost: added=%v deletedNew=%v", added, deletedNew)
	}
}

func TestInstallSharedTCFilterReplaceCleansOtherSameNameFilters(t *testing.T) {
	current := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{Handle: netlink.MakeHandle(0, sharedIngressFilterHandle)},
		Name:        "sb_share_in",
	}
	stale := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{Handle: netlink.MakeHandle(0, 99)},
		Name:        "sb_share_in",
	}
	replacement := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{Handle: current.Attrs().Handle},
		Name:        "sb_share_in",
	}
	previousReplace := sharedTCFilterReplace
	previousDel := sharedTCFilterDel
	t.Cleanup(func() {
		sharedTCFilterReplace = previousReplace
		sharedTCFilterDel = previousDel
	})
	var replaced bool
	var deletedStale bool
	sharedTCFilterReplace = func(filter netlink.Filter) error {
		if filter != replacement {
			t.Fatalf("unexpected replacement: %p", filter)
		}
		replaced = true
		return nil
	}
	sharedTCFilterDel = func(filter netlink.Filter) error {
		if filter != stale {
			t.Fatalf("unexpected filter deleted: %p", filter)
		}
		deletedStale = true
		return nil
	}

	installed, err := installSharedTCFilter(replacement, []netlink.Filter{current, stale})
	if err != nil || installed != replacement {
		t.Fatalf("installed=%p err=%v", installed, err)
	}
	if !replaced || !deletedStale {
		t.Fatalf("replace cleanup incomplete: replaced=%v deletedStale=%v", replaced, deletedStale)
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
		"missing id": {
			FilterAttrs:  expected.FilterAttrs,
			Name:         expected.Name,
			DirectAction: expected.DirectAction,
		},
		"wrong tag": {
			FilterAttrs: expected.FilterAttrs,
			Name:        expected.Name,
			Tag:         "deadbeef",
		},
		"missing tag": {
			FilterAttrs:  expected.FilterAttrs,
			Name:         expected.Name,
			Id:           expected.Id,
			DirectAction: expected.DirectAction,
		},
	} {
		t.Run(name, func(t *testing.T) {
			matching := sharedTCFilterMatches(filter, expected)
			want := name == "matching" || name == "missing id" || name == "missing tag"
			if matching != want {
				t.Fatalf("matching=%v", matching)
			}
		})
	}
}

func sharedTCTestFilter(handle uint16, name string) *netlink.BpfFilter {
	return &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			Handle:   netlink.MakeHandle(0, handle),
			Priority: defaultSharedNetworkTCPriority,
			Protocol: 0x0003,
		},
		Name:         name,
		DirectAction: true,
		Id:           11,
		Tag:          "feedface",
	}
}

func sharedTCTestAttachment() *sharedTCAttachment {
	return &sharedTCAttachment{
		interfaceName:  "test0",
		interfaceIndex: 3,
		ingress:        sharedTCTestFilter(sharedIngressFilterHandle, "sb_share_in"),
		egress:         sharedTCTestFilter(sharedEgressFilterHandle, "sb_share_out"),
	}
}

// sharedTCFiltersHealthy must separate "the filter is genuinely gone" from "the
// netlink dump did not answer". Only the former may trigger a reattach:
// treating a transient dump failure as unhealthy tears down a working
// attachment, which flaps route_localnet and drops traffic for no reason.
func TestSharedTCFiltersHealthyDistinguishesDumpFailure(t *testing.T) {
	attachment := sharedTCTestAttachment()
	previousList := sharedTCFilterList
	t.Cleanup(func() { sharedTCFilterList = previousList })

	dumpErr := errors.New("dump filters")
	sharedTCFilterList = func(netlink.Link, uint32) ([]netlink.Filter, error) {
		return nil, dumpErr
	}
	healthy, err := sharedTCFiltersHealthy(nil, attachment)
	if healthy {
		t.Fatal("a failed dump must not report the attachment as healthy")
	}
	if !errors.Is(err, dumpErr) {
		t.Fatalf("dump error = %v, want %v", err, dumpErr)
	}
}

func TestSharedTCFiltersHealthyReportsPresentAndMissing(t *testing.T) {
	attachment := sharedTCTestAttachment()
	previousList := sharedTCFilterList
	t.Cleanup(func() { sharedTCFilterList = previousList })

	sharedTCFilterList = func(_ netlink.Link, parent uint32) ([]netlink.Filter, error) {
		switch parent {
		case netlink.HANDLE_MIN_INGRESS:
			return []netlink.Filter{attachment.ingress}, nil
		case netlink.HANDLE_MIN_EGRESS:
			return []netlink.Filter{attachment.egress}, nil
		}
		return nil, nil
	}
	healthy, err := sharedTCFiltersHealthy(nil, attachment)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !healthy {
		t.Fatal("both managed filters are present, attachment should be healthy")
	}

	// An empty egress dump means the filter really is gone: that is the one
	// case that should schedule a reattach, and it must not be reported as an
	// error (the caller only accumulates errors, it does not act on them).
	sharedTCFilterList = func(_ netlink.Link, parent uint32) ([]netlink.Filter, error) {
		if parent == netlink.HANDLE_MIN_INGRESS {
			return []netlink.Filter{attachment.ingress}, nil
		}
		return nil, nil
	}
	healthy, err = sharedTCFiltersHealthy(nil, attachment)
	if err != nil {
		t.Fatalf("a missing filter is not an error, got %v", err)
	}
	if healthy {
		t.Fatal("a missing egress filter must report unhealthy")
	}
}

// A filter installed by something else that merely shares the qdisc must not be
// mistaken for ours.
func TestSharedTCFiltersHealthyIgnoresForeignFilters(t *testing.T) {
	attachment := sharedTCTestAttachment()
	previousList := sharedTCFilterList
	t.Cleanup(func() { sharedTCFilterList = previousList })

	foreign := sharedTCTestFilter(sharedIngressFilterHandle, "sb_share_in")
	foreign.Id = attachment.ingress.Id + 1
	sharedTCFilterList = func(_ netlink.Link, parent uint32) ([]netlink.Filter, error) {
		if parent == netlink.HANDLE_MIN_INGRESS {
			return []netlink.Filter{foreign}, nil
		}
		return []netlink.Filter{attachment.egress}, nil
	}
	healthy, err := sharedTCFiltersHealthy(nil, attachment)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if healthy {
		t.Fatal("a different BPF program id must not satisfy the health check")
	}
}

// A TCX attachment carries no clsact filters. Reporting it unhealthy would make
// reconcile detach and reattach it on every pass.
func TestSharedTCFiltersHealthyWithoutFiltersIsUnhealthyNotAnError(t *testing.T) {
	healthy, err := sharedTCFiltersHealthy(nil, &sharedTCAttachment{interfaceName: "test0"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if healthy {
		t.Fatal("an attachment without managed filters cannot be healthy")
	}
}
