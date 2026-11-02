//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"errors"
	"strings"
	"testing"

	E "github.com/metacubex/sing/common/exceptions"

	"golang.org/x/sys/unix"
)

type fakeTCBackend struct {
	name     string
	closed   int
	closeErr error
}

func (b *fakeTCBackend) Close() error {
	b.closed++
	return b.closeErr
}

func TestRegisterTCTCPListenersOrDirectKeepsSockmapBackend(t *testing.T) {
	sockmap := &fakeTCBackend{name: "sockmap"}
	backend, err := registerTCTCPListenersOrDirect(
		sockmap,
		func(*fakeTCBackend) error { return nil },
		func() (*fakeTCBackend, error) {
			t.Fatal("direct backend must not be prepared")
			return nil, nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if backend != sockmap {
		t.Fatalf("backend = %v, want %v", backend, sockmap)
	}
	if sockmap.closed != 0 {
		t.Fatalf("sockmap closed %d times, want 0", sockmap.closed)
	}
}

func TestRegisterTCTCPListenersOrDirectFallsBackOnEOPNOTSUPP(t *testing.T) {
	sockmap := &fakeTCBackend{name: "sockmap"}
	direct := &fakeTCBackend{name: "direct"}
	var registered []string
	backend, err := registerTCTCPListenersOrDirect(
		sockmap,
		func(current *fakeTCBackend) error {
			registered = append(registered, current.name)
			if current == sockmap {
				return E.Cause(unix.EOPNOTSUPP, "register TC eBPF TCP listener")
			}
			return nil
		},
		func() (*fakeTCBackend, error) {
			if sockmap.closed != 1 {
				t.Fatalf("SOCKMAP backend must be closed before the rebuild: closed %d times", sockmap.closed)
			}
			return direct, nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if backend != direct {
		t.Fatalf("backend = %v, want %v", backend, direct)
	}
	if strings.Join(registered, ",") != "sockmap,direct" {
		t.Fatalf("registered = %v", registered)
	}
	if sockmap.closed != 1 {
		t.Fatalf("sockmap closed %d times, want 1", sockmap.closed)
	}
	if direct.closed != 0 {
		t.Fatalf("direct closed %d times, want 0", direct.closed)
	}
}

func TestRegisterTCTCPListenersOrDirectKeepsOtherErrors(t *testing.T) {
	sockmap := &fakeTCBackend{name: "sockmap"}
	backend, err := registerTCTCPListenersOrDirect(
		sockmap,
		func(*fakeTCBackend) error { return E.Cause(unix.EBADF, "register TC eBPF TCP listener") },
		func() (*fakeTCBackend, error) {
			t.Fatal("direct backend must not be prepared")
			return nil, nil
		},
	)
	if !errors.Is(err, unix.EBADF) {
		t.Fatalf("err = %v, want %v", err, unix.EBADF)
	}
	if backend != nil {
		t.Fatalf("backend = %v, want nil", backend)
	}
	if sockmap.closed != 1 {
		t.Fatalf("sockmap closed %d times, want 1", sockmap.closed)
	}
}

func TestRegisterTCTCPListenersOrDirectReportsRebuildFailure(t *testing.T) {
	sockmap := &fakeTCBackend{name: "sockmap"}
	rebuildErr := errors.New("load legacy programs")
	backend, err := registerTCTCPListenersOrDirect(
		sockmap,
		func(*fakeTCBackend) error { return unix.EOPNOTSUPP },
		func() (*fakeTCBackend, error) { return nil, rebuildErr },
	)
	if !errors.Is(err, unix.EOPNOTSUPP) {
		t.Fatalf("err = %v, want %v", err, unix.EOPNOTSUPP)
	}
	if !errors.Is(err, rebuildErr) {
		t.Fatalf("err = %v, want %v", err, rebuildErr)
	}
	if backend != nil {
		t.Fatalf("backend = %v, want nil", backend)
	}
	if sockmap.closed != 1 {
		t.Fatalf("sockmap closed %d times, want 1", sockmap.closed)
	}
}

func TestRegisterTCTCPListenersOrDirectClosesFailedDirectBackend(t *testing.T) {
	sockmap := &fakeTCBackend{name: "sockmap"}
	direct := &fakeTCBackend{name: "direct"}
	directErr := errors.New("direct registration failed")
	backend, err := registerTCTCPListenersOrDirect(
		sockmap,
		func(current *fakeTCBackend) error {
			if current == sockmap {
				return unix.EOPNOTSUPP
			}
			return directErr
		},
		func() (*fakeTCBackend, error) { return direct, nil },
	)
	if !errors.Is(err, directErr) {
		t.Fatalf("err = %v, want %v", err, directErr)
	}
	if backend != nil {
		t.Fatalf("backend = %v, want nil", backend)
	}
	if sockmap.closed != 1 {
		t.Fatalf("sockmap closed %d times, want 1", sockmap.closed)
	}
	if direct.closed != 1 {
		t.Fatalf("direct closed %d times, want 1", direct.closed)
	}
}
