package route

import (
	"encoding/json"
	"testing"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel"
	"github.com/stretchr/testify/assert"
)

type overviewProxy struct {
	C.Proxy
	name      string
	kind      C.AdapterType
	next      C.Proxy
	lastTouch bool
}

func (proxy *overviewProxy) Name() string            { return proxy.name }
func (proxy *overviewProxy) Type() C.AdapterType     { return proxy.kind }
func (proxy *overviewProxy) Adapter() C.ProxyAdapter { return proxy }
func (proxy *overviewProxy) Unwrap(metadata *C.Metadata, touch bool) C.Proxy {
	proxy.lastTouch = touch
	return proxy.next
}

func TestOverviewExitDoesNotTouchProvidersOrSelectSmartNodes(t *testing.T) {
	smart := &overviewProxy{name: "smart", kind: C.Smart}
	selector := &overviewProxy{name: "GLOBAL", kind: C.Selector, next: smart}
	direct := &overviewProxy{name: "DIRECT", kind: C.Direct}
	proxies := map[string]C.Proxy{"GLOBAL": selector, "DIRECT": direct}
	assert.Equal(t, overviewExit{Chain: []string{"GLOBAL", "smart"}, Smart: true}, overviewExitChain(tunnel.Global, nil, proxies))
	assert.False(t, selector.lastTouch)
	assert.Equal(t, overviewExit{Chain: []string{"DIRECT"}}, overviewExitChain(tunnel.Direct, nil, proxies))
	selector.next = selector
	assert.Equal(t, []string{"GLOBAL"}, overviewExitChain(tunnel.Global, nil, proxies).Chain)
}

func TestOverviewAuthentication(t *testing.T) {
	handler := router(false, "overview-secret", "", Cors{})
	for _, token := range []string{"", "Bearer overview-secret"} {
		request := httptest.NewRequest(http.MethodGet, "/overview", nil)
		request.Header.Set("Authorization", token)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if token == "" {
			assert.Equal(t, http.StatusUnauthorized, response.Code)
			continue
		}
		assert.Equal(t, http.StatusOK, response.Code)
		var result map[string]json.RawMessage
		assert.NoError(t, json.Unmarshal(response.Body.Bytes(), &result))
		assert.Contains(t, result, "exit")
		assert.Contains(t, result, "providers")
		assert.NotContains(t, result, "proxies")
		assert.NotContains(t, result, "rules")
	}
}
