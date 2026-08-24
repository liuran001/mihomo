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
	dnsModeRespectBypass = "respect_bypass"
	dnsModeOff           = "off"
	cgroupIPv6ModeAlways = "always"
	cgroupIPv6ModeAuto   = "auto"
	cgroupIPv6ModeOff    = "off"
	sharedIPv6ModeAlways = "always"
	sharedIPv6ModeOff    = "off"
	ebpfModeLocal        = "local"
	ebpfModeShared       = "shared"
	ebpfModeHybrid       = "hybrid"
)

func normalizeMode(mode string) (string, bool, bool, error) {
	switch mode {
	case "", ebpfModeLocal:
		return ebpfModeLocal, true, false, nil
	case ebpfModeShared:
		return ebpfModeShared, false, true, nil
	case ebpfModeHybrid:
		return ebpfModeHybrid, true, true, nil
	default:
		return "", false, false, E.New("unknown eBPF mode: ", mode)
	}
}

func validateLocalOptions(enabled bool, options LC.EBPFLocal) error {
	if enabled {
		return nil
	}
	if options.CgroupPath != "" {
		return E.New("local.cgroup_path requires local or hybrid mode")
	}
	if options.IPv6Mode != "" {
		return E.New("local.ipv6_mode requires local or hybrid mode")
	}
	if len(options.IncludeUID) > 0 || len(options.IncludeUIDRange) > 0 ||
		len(options.ExcludeUID) > 0 || len(options.ExcludeUIDRange) > 0 ||
		len(options.IncludeAndroidUser) > 0 || len(options.IncludePackage) > 0 ||
		len(options.ExcludePackage) > 0 {
		return E.New("local UID policy requires local or hybrid mode")
	}
	if options.StateCapacity != 0 {
		return E.New("local.state_capacity requires local or hybrid mode")
	}
	return nil
}

func validateSharedOptions(enabled bool, options LC.EBPFShared) error {
	if enabled {
		return nil
	}
	if len(options.Interface) > 0 || options.IPv6Mode != "" ||
		len(options.IncludeSourceCIDR) > 0 || len(options.ExcludeSourceCIDR) > 0 ||
		len(options.IncludeMACAddress) > 0 || len(options.ExcludeMACAddress) > 0 ||
		options.StateCapacity != 0 || options.Advanced.TCPriority != 0 {
		return E.New("shared options require shared or hybrid mode")
	}
	return nil
}

func validateAndroidUIDOptions(goos string, options LC.EBPFLocal) error {
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

func hasAndroidUIDOptions(options LC.EBPFLocal) bool {
	return len(options.IncludeAndroidUser) > 0 || len(options.IncludePackage) > 0 || len(options.ExcludePackage) > 0
}

func normalizeDNSMode(mode string) (string, error) {
	switch mode {
	case "", dnsModeHijack:
		return dnsModeHijack, nil
	case dnsModeRespectBypass, dnsModeOff:
		return mode, nil
	default:
		return "", E.New("unknown eBPF dns_mode: ", mode)
	}
}

func commonDNSMode(mode string) ECommon.DNSMode {
	switch mode {
	case dnsModeRespectBypass:
		return ECommon.DNSModeRespectPolicy
	case dnsModeOff:
		return ECommon.DNSModeOff
	default:
		return ECommon.DNSModeHijack
	}
}

func normalizeCgroupIPv6Mode(mode string) (string, error) {
	switch mode {
	case "", cgroupIPv6ModeAuto:
		return cgroupIPv6ModeAuto, nil
	case cgroupIPv6ModeAlways, cgroupIPv6ModeOff:
		return mode, nil
	default:
		return "", E.New("unknown eBPF local.ipv6_mode: ", mode)
	}
}

func normalizeSharedIPv6Mode(mode string) (string, error) {
	switch mode {
	case "", sharedIPv6ModeAlways:
		return sharedIPv6ModeAlways, nil
	case sharedIPv6ModeOff:
		return sharedIPv6ModeOff, nil
	default:
		return "", E.New("unknown eBPF shared.ipv6_mode: ", mode)
	}
}

func normalizeCgroupMapCapacity(configured uint32) (ECommon.CgroupMapCapacity, error) {
	capacity := ECommon.DefaultCgroupMapCapacity()
	if configured == 0 {
		return capacity, nil
	}
	if configured > ECommon.MaxConfigurableMapCapacity {
		return ECommon.CgroupMapCapacity{}, E.New(
			"local.state_capacity must be between 0 and ",
			ECommon.MaxConfigurableMapCapacity,
		)
	}
	capacity.TCPRedirect = configured
	capacity.UDPRedirect = configured
	capacity.SocketBypass = configured
	return capacity, nil
}

func normalizeSharedNetworkMapCapacity(configured uint32) (ECommon.SharedNetworkMapCapacities, error) {
	capacity := ECommon.DefaultSharedNetworkMapCapacities()
	if configured == 0 {
		return capacity, nil
	}
	if configured > ECommon.MaxConfigurableMapCapacity {
		return ECommon.SharedNetworkMapCapacities{}, E.New(
			"shared.state_capacity must be between 0 and ",
			ECommon.MaxConfigurableMapCapacity,
		)
	}
	capacity.Proxy = configured
	capacity.Bypass = configured
	capacity.Fragment = configured
	return capacity, nil
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

func normalizeSharedNetworkOptions(options LC.EBPFShared) (LC.EBPFShared, error) {
	if len(options.Interface) == 0 {
		return LC.EBPFShared{}, E.New("shared.interface must not be empty")
	}
	if options.Advanced.TCPriority == 0 {
		options.Advanced.TCPriority = defaultSharedNetworkTCPriority
	}
	seen := make(map[string]struct{}, len(options.Interface))
	interfaces := make([]string, 0, len(options.Interface))
	for _, interfaceName := range options.Interface {
		interfaceName = strings.TrimSpace(interfaceName)
		if interfaceName == "" {
			return LC.EBPFShared{}, E.New("shared.interface contains an empty interface name")
		}
		if interfaceName == "lo" {
			return LC.EBPFShared{}, E.New("shared.interface must not contain lo")
		}
		if _, loaded := seen[interfaceName]; loaded {
			continue
		}
		seen[interfaceName] = struct{}{}
		interfaces = append(interfaces, interfaceName)
	}
	options.Interface = interfaces
	var err error
	options.IncludeSourceCIDR, err = normalizeSourceCIDRs(options.IncludeSourceCIDR)
	if err != nil {
		return LC.EBPFShared{}, err
	}
	options.ExcludeSourceCIDR, err = normalizeSourceCIDRs(options.ExcludeSourceCIDR)
	if err != nil {
		return LC.EBPFShared{}, err
	}
	return options, nil
}

func normalizeSourceCIDRs(prefixes []netip.Prefix) ([]netip.Prefix, error) {
	normalized := make([]netip.Prefix, 0, len(prefixes))
	seen := make(map[netip.Prefix]struct{}, len(prefixes))
	for _, prefix := range prefixes {
		if !prefix.IsValid() {
			return nil, E.New("invalid shared source CIDR")
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
			return nil, E.Cause(err, "parse shared.", name, "[", index, "]")
		}
		if len(hardwareAddress) != len(ECommon.MACAddress{}) {
			return nil, E.New("shared.", name, "[", index, "] must be a 48-bit MAC address")
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

func validateSharedNetworkProtocols(enabled bool, enableUDP bool, dnsMode string) error {
	if enabled && dnsMode != dnsModeOff && !enableUDP {
		return E.New("shared mode with DNS interception requires UDP")
	}
	return nil
}
