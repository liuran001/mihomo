package config

import (
	"net/netip"
	"strings"
)

type EBPF struct {
	Mode                 string     `json:"mode" yaml:"mode" inbound:"mode,omitempty"`
	Network              []string   `json:"network" yaml:"network"`
	UDPTimeout           int64      `json:"udp-timeout" yaml:"udp-timeout"`
	DNSMode              string     `json:"dns-mode" yaml:"dns-mode"`
	BypassPrivateAddress *bool      `json:"bypass-private-address" yaml:"bypass-private-address" inbound:"bypass-private-address,omitempty"`
	BypassRuleSet        []string   `json:"bypass-rule-set" yaml:"bypass-rule-set"`
	Local                EBPFLocal  `json:"local" yaml:"local" inbound:"local,omitempty"`
	Shared               EBPFShared `json:"shared" yaml:"shared" inbound:"shared,omitempty"`
}

type EBPFLocal struct {
	CgroupPath         string   `json:"cgroup-path" yaml:"cgroup-path" inbound:"cgroup-path,omitempty"`
	IPv6Mode           string   `json:"ipv6-mode" yaml:"ipv6-mode" inbound:"ipv6-mode,omitempty"`
	IncludeUID         []uint32 `json:"include-uid" yaml:"include-uid" inbound:"include-uid,omitempty"`
	IncludeUIDRange    []string `json:"include-uid-range" yaml:"include-uid-range" inbound:"include-uid-range,omitempty"`
	ExcludeUID         []uint32 `json:"exclude-uid" yaml:"exclude-uid" inbound:"exclude-uid,omitempty"`
	ExcludeUIDRange    []string `json:"exclude-uid-range" yaml:"exclude-uid-range" inbound:"exclude-uid-range,omitempty"`
	IncludeAndroidUser []int    `json:"include-android-user" yaml:"include-android-user" inbound:"include-android-user,omitempty"`
	IncludePackage     []string `json:"include-package" yaml:"include-package" inbound:"include-package,omitempty"`
	ExcludePackage     []string `json:"exclude-package" yaml:"exclude-package" inbound:"exclude-package,omitempty"`
	StateCapacity      uint32   `json:"state-capacity" yaml:"state-capacity" inbound:"state-capacity,omitempty"`
}

type EBPFShared struct {
	Interface         []string           `json:"interface" yaml:"interface" inbound:"interface,omitempty"`
	IPv6Mode          string             `json:"ipv6-mode" yaml:"ipv6-mode" inbound:"ipv6-mode,omitempty"`
	IncludeSourceCIDR []netip.Prefix     `json:"include-source-cidr" yaml:"include-source-cidr" inbound:"include-source-cidr,omitempty"`
	ExcludeSourceCIDR []netip.Prefix     `json:"exclude-source-cidr" yaml:"exclude-source-cidr" inbound:"exclude-source-cidr,omitempty"`
	IncludeMACAddress []string           `json:"include-mac-address" yaml:"include-mac-address" inbound:"include-mac-address,omitempty"`
	ExcludeMACAddress []string           `json:"exclude-mac-address" yaml:"exclude-mac-address" inbound:"exclude-mac-address,omitempty"`
	StateCapacity     uint32             `json:"state-capacity" yaml:"state-capacity" inbound:"state-capacity,omitempty"`
	Advanced          EBPFSharedAdvanced `json:"advanced" yaml:"advanced" inbound:"advanced,omitempty"`
}

type EBPFSharedAdvanced struct {
	TCPriority uint16 `json:"tc-priority" yaml:"tc-priority" inbound:"tc-priority,omitempty"`
}

type EBPFMapCapacity struct {
	TCPRedirect  uint32 `json:"tcp-redirect" yaml:"tcp-redirect" inbound:"tcp-redirect,omitempty"`
	UDPRedirect  uint32 `json:"udp-redirect" yaml:"udp-redirect" inbound:"udp-redirect,omitempty"`
	SocketBypass uint32 `json:"socket-bypass" yaml:"socket-bypass" inbound:"socket-bypass,omitempty"`
}

func (c EBPF) String() string {
	builder := &strings.Builder{}
	builder.WriteString("mode=")
	builder.WriteString(c.Mode)
	builder.WriteString(", network=")
	builder.WriteString(strings.Join(c.Network, ","))
	builder.WriteString(", dns_mode=")
	builder.WriteString(c.DNSMode)
	return builder.String()
}
