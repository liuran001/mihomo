package constant

import "sync/atomic"

// configCheck is set by `mihomo -t`: the configuration is parsed only to be
// validated and the process exits right after. Constructors must not start
// long-lived side effects (network nodes, persistent state) in this mode,
// because the real instance may be running against the same state at the
// same time.
var configCheck atomic.Bool

// SetConfigCheck marks the current process as a configuration check.
func SetConfigCheck(enabled bool) { configCheck.Store(enabled) }

// ConfigCheck reports whether the current process only checks the configuration.
func ConfigCheck() bool { return configCheck.Load() }
