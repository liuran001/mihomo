//go:build with_gvisor && !no_tailscale

package outbound

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"

	C "github.com/metacubex/mihomo/constant"

	"github.com/metacubex/tailscale/client/tailscale/apitype"
	"github.com/metacubex/tailscale/tailcfg"
)

func TestParseTailscaleServe(t *testing.T) {
	home := t.TempDir()
	oldHome := C.Path.HomeDir()
	C.SetHomeDir(home)
	t.Cleanup(func() { C.SetHomeDir(oldHome) })

	targets, err := parseTailscaleServe([]TailscaleServeOption{
		{Port: 80, Target: "unix:run/webui.sock"},
		{Port: 8080, Target: "http://127.0.0.1:9099"},
		{Port: 8443, Target: "http://[::1]:9099/"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if targets[0].network != "unix" || targets[0].address != filepath.Join(home, "run", "webui.sock") {
		t.Fatalf("unix target: %+v", targets[0])
	}
	if targets[1].network != "tcp" || targets[1].address != "127.0.0.1:9099" || targets[2].address != "[::1]:9099" {
		t.Fatalf("tcp targets: %+v %+v", targets[1], targets[2])
	}

	for _, bad := range [][]TailscaleServeOption{
		{{Port: 0, Target: "http://127.0.0.1:1"}},
		{{Port: 80, Target: "http://127.0.0.1:1"}, {Port: 80, Target: "http://127.0.0.1:2"}},
		{{Port: 80, Target: "http://localhost:9099"}},
		{{Port: 80, Target: "http://127.0.0.1:9099/admin"}},
		{{Port: 80, Target: "https://127.0.0.1:9099"}},
		{{Port: 80, Target: "unix:"}},
		{{Port: 80, Target: "unix:../outside.sock"}},
	} {
		if _, err := parseTailscaleServe(bad); err == nil {
			t.Fatalf("accepted %+v", bad)
		}
	}
}

func TestTailscaleServeHandlerIdentity(t *testing.T) {
	var got http.Header
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		got = request.Header.Clone()
		_, _ = io.WriteString(writer, "ok "+request.Host)
	}))
	defer upstream.Close()
	targets, err := parseTailscaleServe([]TailscaleServeOption{{Port: 80, Target: upstream.URL}})
	if err != nil {
		t.Fatal(err)
	}

	users := map[string]*apitype.WhoIsResponse{
		"100.64.0.2": {Node: &tailcfg.Node{}, UserProfile: &tailcfg.UserProfile{LoginName: "alice@example.com", DisplayName: "Ålice"}},
		"100.64.0.3": {Node: &tailcfg.Node{Tags: []string{"tag:server"}}, UserProfile: &tailcfg.UserProfile{LoginName: "tagged-devices"}},
	}
	whois := func(_ context.Context, remote string) (*apitype.WhoIsResponse, error) {
		host, _, _ := net.SplitHostPort(remote)
		if who, ok := users[host]; ok {
			return who, nil
		}
		return nil, errors.New("unknown peer")
	}
	handler := tailscaleServeHandler(targets[0], whois)

	call := func(remote string) {
		request := httptest.NewRequest(http.MethodGet, "http://phone.tailnet.ts.net/ui", nil)
		request.RemoteAddr = remote
		request.Header.Set("Tailscale-User-Login", "forged@example.com")
		request.Header.Set("tailscale-user-name", "forged")
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusOK || recorder.Body.String() != "ok phone.tailnet.ts.net" {
			t.Fatalf("%s: %d %q", remote, recorder.Code, recorder.Body.String())
		}
	}

	call("100.64.0.2:41000")
	if got.Get("Tailscale-User-Login") != "alice@example.com" || got.Get("Tailscale-User-Name") != "=?utf-8?q?=C3=85lice?=" {
		t.Fatalf("identity headers: %v", got)
	}
	if got.Get("X-Forwarded-For") != "100.64.0.2" {
		t.Fatalf("X-Forwarded-For: %q", got.Get("X-Forwarded-For"))
	}
	for _, remote := range []string{"100.64.0.3:41000", "100.64.0.9:41000"} {
		call(remote)
		if got.Get("Tailscale-User-Login") != "" || got.Get("Tailscale-User-Name") != "" {
			t.Fatalf("%s kept identity headers: %v", remote, got)
		}
	}
}

func TestTailscaleServeHandlerUnixTarget(t *testing.T) {
	dir := t.TempDir()
	socket := filepath.Join(dir, "web.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Skipf("unix sockets unavailable: %v", err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, _ = io.WriteString(writer, request.Header.Get("Tailscale-User-Login"))
	})}
	go func() { _ = server.Serve(listener) }()
	defer server.Close()

	target := tailscaleServeTarget{port: 80, network: "unix", address: socket}
	target.origin = mustServeOrigin()
	handler := tailscaleServeHandler(target, func(context.Context, string) (*apitype.WhoIsResponse, error) {
		return &apitype.WhoIsResponse{Node: &tailcfg.Node{}, UserProfile: &tailcfg.UserProfile{LoginName: "bob@example.com"}}, nil
	})
	request := httptest.NewRequest(http.MethodGet, "http://100.64.0.1/", nil)
	request.RemoteAddr = "100.64.0.2:1234"
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || recorder.Body.String() != "bob@example.com" {
		t.Fatalf("unix target: %d %q", recorder.Code, recorder.Body.String())
	}
}

func mustServeOrigin() *url.URL { return &url.URL{Scheme: "http", Host: "tailscale-serve"} }
