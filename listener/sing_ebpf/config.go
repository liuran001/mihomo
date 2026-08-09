//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"net"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"

	ECommon "github.com/metacubex/mihomo/common/ebpf"
	LC "github.com/metacubex/mihomo/listener/config"

	E "github.com/metacubex/sing/common/exceptions"
)

const (
	dnsModeHijack        = "hijack"
	dnsModeOff           = "off"
	cgroupIPv6ModeAlways = "always"
	cgroupIPv6ModeAuto   = "auto"
	cgroupIPv6ModeOff    = "off"
)

var defaultRedirectIPv4Prefix = netip.MustParsePrefix("127.128.0.0/9")

func normalizeDNSMode(mode string) (string, error) {
	switch mode {
	case "", dnsModeHijack:
		return dnsModeHijack, nil
	case dnsModeOff:
		return dnsModeOff, nil
	default:
		return "", E.New("unknown eBPF dns_mode: ", mode)
	}
}

func normalizeCgroupIPv6Mode(mode string) (string, error) {
	switch mode {
	case "", cgroupIPv6ModeAlways:
		return cgroupIPv6ModeAlways, nil
	case cgroupIPv6ModeAuto, cgroupIPv6ModeOff:
		return mode, nil
	default:
		return "", E.New("unknown eBPF cgroup_ipv6_mode: ", mode)
	}
}

func validateCgroupAddressFamilies(ipv6Mode string, ipv4Prefix netip.Prefix, ipv6Prefix netip.Prefix) error {
	if !ipv4Prefix.IsValid() && (!ipv6Prefix.IsValid() || ipv6Mode == cgroupIPv6ModeOff) {
		return E.New("eBPF local cgroup interception has no enabled address family")
	}
	return nil
}

func normalizeCgroupMapCapacity(options LC.EBPFMapCapacity) (ECommon.CgroupMapCapacity, error) {
	capacity := ECommon.DefaultCgroupMapCapacity()
	var err error
	capacity.TCPRedirect, err = normalizeMapCapacityValue("map_capacity.tcp_redirect", options.TCPRedirect, capacity.TCPRedirect)
	if err != nil {
		return ECommon.CgroupMapCapacity{}, err
	}
	capacity.UDPRedirect, err = normalizeMapCapacityValue("map_capacity.udp_redirect", options.UDPRedirect, capacity.UDPRedirect)
	if err != nil {
		return ECommon.CgroupMapCapacity{}, err
	}
	capacity.SocketBypass, err = normalizeMapCapacityValue("map_capacity.socket_bypass", options.SocketBypass, capacity.SocketBypass)
	if err != nil {
		return ECommon.CgroupMapCapacity{}, err
	}
	return capacity, nil
}

func normalizeMapCapacityValue(name string, configured uint32, defaultValue uint32) (uint32, error) {
	if configured == 0 {
		return defaultValue, nil
	}
	if configured > ECommon.MaxConfigurableMapCapacity {
		return 0, E.New(name, " must be between 1 and ", ECommon.MaxConfigurableMapCapacity)
	}
	return configured, nil
}

func normalizeCgroupPath(cgroupPath string) (string, error) {
	if cgroupPath == "" {
		return "", nil
	}
	if !filepath.IsAbs(cgroupPath) {
		return "", E.New("eBPF cgroup_path must be absolute")
	}
	return filepath.Clean(cgroupPath), nil
}

func normalizeRedirectAddresses(addresses []netip.Prefix) (netip.Prefix, netip.Prefix, error) {
	if len(addresses) == 0 {
		return defaultRedirectIPv4Prefix, netip.Prefix{}, nil
	}
	var ipv4Prefix netip.Prefix
	var ipv6Prefix netip.Prefix
	for _, address := range addresses {
		if !address.IsValid() {
			return netip.Prefix{}, netip.Prefix{}, E.New("invalid eBPF redirect address")
		}
		address = address.Masked()
		if err := ECommon.ValidateRedirectPrefix(address); err != nil {
			return netip.Prefix{}, netip.Prefix{}, err
		}
		switch {
		case address.Addr().Is4():
			if ipv4Prefix.IsValid() {
				return netip.Prefix{}, netip.Prefix{}, E.New("duplicate IPv4 eBPF redirect address")
			}
			ipv4Prefix = address
		case address.Addr().Is6() && !address.Addr().Is4In6():
			if ipv6Prefix.IsValid() {
				return netip.Prefix{}, netip.Prefix{}, E.New("duplicate IPv6 eBPF redirect address")
			}
			ipv6Prefix = address
		default:
			return netip.Prefix{}, netip.Prefix{}, E.New("invalid eBPF redirect address family: ", address)
		}
	}
	return ipv4Prefix, ipv6Prefix, nil
}

func parseUIDRanges(uidList []uint32, rangeList []string) ([]ECommon.UIDRange, error) {
	uidRanges := make([]ECommon.UIDRange, 0, len(uidList)+len(rangeList))
	for _, uid := range uidList {
		uidRanges = append(uidRanges, ECommon.UIDRange{Start: uid, End: uid})
	}
	for _, uidRange := range rangeList {
		separator := strings.IndexByte(uidRange, ':')
		if separator < 0 {
			return nil, E.New("missing ':' in range: ", uidRange)
		}
		if separator == 0 {
			return nil, E.New("missing range start: ", uidRange)
		}
		if separator == len(uidRange)-1 {
			return nil, E.New("missing range end: ", uidRange)
		}
		start, err := strconv.ParseUint(uidRange[:separator], 0, 32)
		if err != nil {
			return nil, E.Cause(err, "parse range start")
		}
		end, err := strconv.ParseUint(uidRange[separator+1:], 0, 32)
		if err != nil {
			return nil, E.Cause(err, "parse range end")
		}
		if start > end {
			return nil, E.New("range start is greater than range end: ", uidRange)
		}
		uidRanges = append(uidRanges, ECommon.UIDRange{Start: uint32(start), End: uint32(end)})
	}
	return uidRanges, nil
}

func validateAndroidUIDOptions(goos string, options LC.EBPF) error {
	if !hasAndroidUIDOptions(options) {
		return nil
	}
	if goos != "android" {
		return E.New("include_android_user, include_package, and exclude_package are only supported on Android")
	}
	const maxAndroidUserID = (uint64(^uint32(0)-1) - (androidUserRange - 1)) / androidUserRange
	for _, userID := range options.IncludeAndroidUser {
		if userID < 0 || uint64(userID) > maxAndroidUserID {
			return E.New("invalid include_android_user: ", userID)
		}
	}
	return nil
}

func hasAndroidUIDOptions(options LC.EBPF) bool {
	return len(options.IncludeAndroidUser) > 0 || len(options.IncludePackage) > 0 || len(options.ExcludePackage) > 0
}

func normalizeSourceCIDRs(prefixes []netip.Prefix) ([]netip.Prefix, error) {
	normalized := make([]netip.Prefix, 0, len(prefixes))
	seen := make(map[netip.Prefix]struct{}, len(prefixes))
	for _, prefix := range prefixes {
		if !prefix.IsValid() {
			return nil, E.New("invalid shared-network source CIDR")
		}
		prefix = prefix.Masked()
		if prefix.Addr().Is4In6() && prefix.Bits() >= 96 {
			prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96).Masked()
		}
		if _, loaded := seen[prefix]; loaded {
			continue
		}
		seen[prefix] = struct{}{}
		normalized = append(normalized, prefix)
	}
	return normalized, nil
}

func parseSharedNetworkMACAddresses(name string, addresses []string) ([]ECommon.MACAddress, error) {
	parsed := make([]ECommon.MACAddress, 0, len(addresses))
	seen := make(map[ECommon.MACAddress]struct{}, len(addresses))
	for index, address := range addresses {
		hardwareAddress, err := net.ParseMAC(address)
		if err != nil {
			return nil, E.Cause(err, "parse shared_network.", name, "[", index, "]")
		}
		if len(hardwareAddress) != len(ECommon.MACAddress{}) {
			return nil, E.New("shared_network.", name, "[", index, "] must be a 48-bit MAC address")
		}
		var mac ECommon.MACAddress
		copy(mac[:], hardwareAddress)
		if _, loaded := seen[mac]; loaded {
			continue
		}
		seen[mac] = struct{}{}
		parsed = append(parsed, mac)
	}
	return parsed, nil
}

func normalizeSharedNetworkMapCapacity(options LC.EBPFSharedNetworkMapCapacity) (ECommon.SharedNetworkMapCapacities, error) {
	capacity := ECommon.DefaultSharedNetworkMapCapacities()
	var err error
	capacity.Proxy, err = normalizeMapCapacityValuePtr("shared_network.map_capacity.proxy", options.Proxy, capacity.Proxy)
	if err != nil {
		return ECommon.SharedNetworkMapCapacities{}, err
	}
	capacity.Bypass, err = normalizeMapCapacityValuePtr("shared_network.map_capacity.bypass", options.Bypass, capacity.Bypass)
	if err != nil {
		return ECommon.SharedNetworkMapCapacities{}, err
	}
	capacity.Fragment, err = normalizeMapCapacityValuePtr("shared_network.map_capacity.fragment", options.Fragment, capacity.Fragment)
	if err != nil {
		return ECommon.SharedNetworkMapCapacities{}, err
	}
	return capacity, nil
}

func normalizeMapCapacityValuePtr(name string, configured *uint32, defaultValue uint32) (uint32, error) {
	if configured == nil {
		return defaultValue, nil
	}
	return normalizeMapCapacityValue(name, *configured, defaultValue)
}
