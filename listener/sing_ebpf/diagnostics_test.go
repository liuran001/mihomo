//go:build with_ebpf && (linux || android)

package sing_ebpf

import "testing"

func TestDiagnosticsSummaryOmitsResourceInspection(t *testing.T) {
	inbound := &Inbound{mode: "local", localDataPlane: "cgroup"}
	inbound.registerDiagnostics()
	defer inbound.unregisterDiagnostics()
	for _, summary := range DiagnosticsSummary() {
		if summary.Mode != "local" {
			continue
		}
		if summary.Resources != nil || summary.ResourceError != "" {
			t.Fatal("summary inspected runtime resources")
		}
		return
	}
	t.Fatal("active inbound missing from summary")
}
