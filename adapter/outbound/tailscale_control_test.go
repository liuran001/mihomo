//go:build with_gvisor && !no_tailscale

package outbound

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTailscaleStatusBeforeStart(t *testing.T) {
	ts := &Tailscale{
		Base:   &Base{name: "ts"},
		ctx:    context.Background(),
		option: TailscaleOption{Hostname: "phone", AuthKey: "tskey-test", Serve: []TailscaleServeOption{{Port: 80, Target: "http://127.0.0.1:8080"}}},
	}
	status := ts.TailscaleStatus(context.Background())
	assert.Equal(t, "ts", status["name"])
	assert.Equal(t, "NotStarted", status["state"])
	assert.Equal(t, false, status["started"])
	assert.Equal(t, true, status["authKey"])
	assert.Equal(t, []map[string]any{{"port": uint16(80), "target": "http://127.0.0.1:8080"}}, status["serve"])
	_, hasKey := status["authURL"]
	assert.False(t, hasKey)
	assert.Error(t, ts.TailscaleLogout(context.Background()))
}
