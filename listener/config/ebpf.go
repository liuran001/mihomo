package config

import (
	"net/netip"
	"strings"
)

type EBPF struct {
	Mode       string   `json:"mode" yaml:"mode" inbound:"mode,omitempty"`
	Network    []string `json:"network" yaml:"network"`
	UDPTimeout int64    `json:"udp-timeout" yaml:"udp-timeout"`
	TCPriority uint16   `json:"tc-priority" yaml:"tc-priority" inbound:"tc-priority,omitempty"`
	// BypassRuleSet is bypassed by every data plane. local.bypass-rule-set and
	// shared.bypass-rule-set add rule sets for one scope only.
	BypassRuleSet []string   `json:"bypass-rule-set" yaml:"bypass-rule-set"`
	FakeIPICMP    string     `json:"fakeip-icmp" yaml:"fakeip-icmp" inbound:"fakeip-icmp,omitempty"`
	Local         EBPFLocal  `json:"local" yaml:"local" inbound:"local,omitempty"`
	Shared        EBPFShared `json:"shared" yaml:"shared" inbound:"shared,omitempty"`

	// BypassTUNDirect decides whether a destination this inbound bypasses is
	// connected directly when a TUN listener's auto-route claims it anyway.
	// Defaults to true. See docs/ebpf-inbound.md, "Coexisting with TUN".
	BypassTUNDirect *bool `json:"bypass-tun-direct" yaml:"bypass-tun-direct" inbound:"bypass-tun-direct,omitempty"`

	// The keys below predate the unified data-plane configuration and are
	// still accepted so an existing config keeps working. They are folded
	// into the local/shared sections when those do not set their own value.
	DNSMode              string `json:"dns-mode" yaml:"dns-mode" inbound:"dns-mode,omitempty"`
	BypassPrivateAddress *bool  `json:"bypass-private-address" yaml:"bypass-private-address" inbound:"bypass-private-address,omitempty"`
	// TCPSplice selected the removed kernel splice fast path. Accepted and
	// ignored with a warning.
	TCPSplice bool `json:"tcp-splice" yaml:"tcp-splice" inbound:"tcp-splice,omitempty"`
}

type EBPFLocal struct {
	// Enable is the sing-box spelling of Enabled. Either may be set; when both
	// are, they must agree.
	Enable               *bool          `json:"enable" yaml:"enable" inbound:"enable,omitempty"`
	Enabled              *bool          `json:"enabled" yaml:"enabled" inbound:"enabled,omitempty"`
	BypassRuleSet        []string       `json:"bypass-rule-set" yaml:"bypass-rule-set" inbound:"bypass-rule-set,omitempty"`
	BypassExclude        []netip.Prefix `json:"bypass-exclude" yaml:"bypass-exclude" inbound:"bypass-exclude,omitempty"`
	DataPlane            string         `json:"data-plane" yaml:"data-plane" inbound:"data-plane,omitempty"`
	CgroupPath           string         `json:"cgroup-path" yaml:"cgroup-path" inbound:"cgroup-path,omitempty"`
	DNSMode              string         `json:"dns-mode" yaml:"dns-mode" inbound:"dns-mode,omitempty"`
	IPv6                 *bool          `json:"ipv6" yaml:"ipv6" inbound:"ipv6,omitempty"`
	BypassPrivateAddress *bool          `json:"bypass-private-address" yaml:"bypass-private-address" inbound:"bypass-private-address,omitempty"`
	IncludeUID           []uint32       `json:"include-uid" yaml:"include-uid" inbound:"include-uid,omitempty"`
	IncludeUIDRange      []string       `json:"include-uid-range" yaml:"include-uid-range" inbound:"include-uid-range,omitempty"`
	ExcludeUID           []uint32       `json:"exclude-uid" yaml:"exclude-uid" inbound:"exclude-uid,omitempty"`
	ExcludeUIDRange      []string       `json:"exclude-uid-range" yaml:"exclude-uid-range" inbound:"exclude-uid-range,omitempty"`
	IncludeAndroidUser   []int          `json:"include-android-user" yaml:"include-android-user" inbound:"include-android-user,omitempty"`
	IncludePackage       []string       `json:"include-package" yaml:"include-package" inbound:"include-package,omitempty"`
	ExcludePackage       []string       `json:"exclude-package" yaml:"exclude-package" inbound:"exclude-package,omitempty"`
	BypassPort           []uint16       `json:"bypass-port" yaml:"bypass-port" inbound:"bypass-port,omitempty"`
	BypassPortRange      []string       `json:"bypass-port-range" yaml:"bypass-port-range" inbound:"bypass-port-range,omitempty"`

	// Legacy keys, see EBPF.
	IPv6Mode      string `json:"ipv6-mode" yaml:"ipv6-mode" inbound:"ipv6-mode,omitempty"`
	StateCapacity uint32 `json:"state-capacity" yaml:"state-capacity" inbound:"state-capacity,omitempty"`
}

type EBPFShared struct {
	Enable               *bool          `json:"enable" yaml:"enable" inbound:"enable,omitempty"`
	Enabled              *bool          `json:"enabled" yaml:"enabled" inbound:"enabled,omitempty"`
	BypassRuleSet        []string       `json:"bypass-rule-set" yaml:"bypass-rule-set" inbound:"bypass-rule-set,omitempty"`
	BypassExclude        []netip.Prefix `json:"bypass-exclude" yaml:"bypass-exclude" inbound:"bypass-exclude,omitempty"`
	DataPlane            string         `json:"data-plane" yaml:"data-plane" inbound:"data-plane,omitempty"`
	DNSMode              string         `json:"dns-mode" yaml:"dns-mode" inbound:"dns-mode,omitempty"`
	Interface            []string       `json:"interface" yaml:"interface" inbound:"interface,omitempty"`
	// AllowDefaultUpstream keeps entries of Interface attached even while the
	// interface is the default upstream. By default such an interface is
	// skipped, which guards a router whose WAN is also listed by mistake but
	// breaks a single-armed gateway whose one and only NIC is both the
	// downstream and the upstream.
	AllowDefaultUpstream  *bool          `json:"allow-default-upstream" yaml:"allow-default-upstream" inbound:"allow-default-upstream,omitempty"`
	IPv6                 *bool          `json:"ipv6" yaml:"ipv6" inbound:"ipv6,omitempty"`
	BypassPrivateAddress *bool          `json:"bypass-private-address" yaml:"bypass-private-address" inbound:"bypass-private-address,omitempty"`
	IncludeSourceCIDR    []netip.Prefix `json:"include-source-cidr" yaml:"include-source-cidr" inbound:"include-source-cidr,omitempty"`
	ExcludeSourceCIDR    []netip.Prefix `json:"exclude-source-cidr" yaml:"exclude-source-cidr" inbound:"exclude-source-cidr,omitempty"`
	IncludeMACAddress    []string       `json:"include-mac-address" yaml:"include-mac-address" inbound:"include-mac-address,omitempty"`
	ExcludeMACAddress    []string       `json:"exclude-mac-address" yaml:"exclude-mac-address" inbound:"exclude-mac-address,omitempty"`
	BypassPort           []uint16       `json:"bypass-port" yaml:"bypass-port" inbound:"bypass-port,omitempty"`
	BypassPortRange      []string       `json:"bypass-port-range" yaml:"bypass-port-range" inbound:"bypass-port-range,omitempty"`

	// Legacy keys, see EBPF.
	IPv6Mode      string             `json:"ipv6-mode" yaml:"ipv6-mode" inbound:"ipv6-mode,omitempty"`
	StateCapacity uint32             `json:"state-capacity" yaml:"state-capacity" inbound:"state-capacity,omitempty"`
	Advanced      EBPFSharedAdvanced `json:"advanced" yaml:"advanced" inbound:"advanced,omitempty"`
}

// EBPFSharedAdvanced is the legacy `shared.advanced` block. tc-priority moved
// to the top level and data-plane to `shared.data-plane`; the routing mark and
// table are now allocated automatically and can no longer be chosen.
type EBPFSharedAdvanced struct {
	TCPriority   uint16 `json:"tc-priority" yaml:"tc-priority" inbound:"tc-priority,omitempty"`
	DataPlane    string `json:"data-plane" yaml:"data-plane" inbound:"data-plane,omitempty"`
	RoutingMark  uint32 `json:"routing-mark" yaml:"routing-mark" inbound:"routing-mark,omitempty"`
	RoutingTable uint32 `json:"routing-table" yaml:"routing-table" inbound:"routing-table,omitempty"`
}

func (c EBPF) String() string {
	builder := &strings.Builder{}
	builder.WriteString("mode=")
	builder.WriteString(c.Mode)
	builder.WriteString(", network=")
	builder.WriteString(strings.Join(c.Network, ","))
	return builder.String()
}
