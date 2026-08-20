//go:build with_ebpf && android && cmfa

package sing_ebpf

import (
	E "github.com/metacubex/sing/common/exceptions"

	tun "github.com/metacubex/sing-tun"
)

func androidPackageManager() (tun.PackageManager, error) {
	return nil, E.New("Android package manager is unavailable in this build")
}
