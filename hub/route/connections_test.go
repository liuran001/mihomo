package route

import (
	"encoding/json"
	"testing"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
)

func TestConnectionSummaryAuthenticationAndShape(t *testing.T) {
	handler := router(false, "summary-secret", "", Cors{})
	for _, token := range []string{"", "Bearer wrong", "Bearer summary-secret"} {
		request := httptest.NewRequest(http.MethodGet, "/connections/summary", nil)
		request.Header.Set("Authorization", token)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if token != "Bearer summary-secret" {
			if response.Code != http.StatusUnauthorized {
				t.Fatalf("unauthenticated summary status = %d", response.Code)
			}
			continue
		}
		if response.Code != http.StatusOK {
			t.Fatalf("summary status = %d: %s", response.Code, response.Body.String())
		}
		var result map[string]json.RawMessage
		if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		for _, key := range []string{"connectionCount", "downloadTotal", "uploadTotal", "memory"} {
			if result[key] == nil {
				t.Fatalf("missing summary field %q", key)
			}
		}
		if result["connections"] != nil {
			t.Fatal("summary includes full connections")
		}
	}
}
