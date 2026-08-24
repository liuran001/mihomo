//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"errors"
	"net"
	"net/netip"

	E "github.com/metacubex/sing/common/exceptions"
	"github.com/sagernet/netlink"

	"golang.org/x/sys/unix"
)

const sharedNetworkRulePriority = 9000

type sharedNetworkPolicyRoute struct {
	rules  []netlink.Rule
	routes []netlink.Route
}

func installSharedNetworkPolicyRoute(mark uint32, table uint32, ipv4, ipv6 bool) (*sharedNetworkPolicyRoute, error) {
	if mark == 0 || table == 0 || table > 1<<31-1 {
		return nil, E.New("invalid shared-network socket-assignment policy route")
	}
	loopback, err := netlink.LinkByName("lo")
	if err != nil {
		return nil, E.Cause(err, "find loopback for shared-network socket assignment")
	}
	result := &sharedNetworkPolicyRoute{}
	fullMarkMask := ^uint32(0)
	cleanup := func(startErr error) (*sharedNetworkPolicyRoute, error) {
		return nil, E.Errors(startErr, result.Close())
	}
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		if (family == unix.AF_INET && !ipv4) || (family == unix.AF_INET6 && !ipv6) {
			continue
		}
		rule := netlink.NewRule()
		rule.Family = family
		rule.Priority = sharedNetworkRulePriority
		rule.Table = int(table)
		rule.Mark = mark
		rule.MarkSet = true
		rule.Mask = int(fullMarkMask)
		if err = netlink.RuleAdd(rule); err != nil {
			if !errors.Is(err, unix.EEXIST) {
				return cleanup(E.Cause(err, "add shared-network socket-assignment policy rule"))
			}
			if err = verifySharedNetworkPolicyRule(*rule); err != nil {
				return cleanup(err)
			}
		} else {
			result.rules = append(result.rules, *rule)
		}
		prefix := netip.MustParsePrefix("0.0.0.0/0")
		if family == unix.AF_INET6 {
			prefix = netip.MustParsePrefix("::/0")
		}
		route := netlink.Route{
			LinkIndex: loopback.Attrs().Index,
			Family:    family,
			Dst:       &net.IPNet{IP: net.IP(prefix.Addr().AsSlice()), Mask: net.CIDRMask(0, prefix.Addr().BitLen())},
			Scope:     netlink.Scope(unix.RT_SCOPE_HOST),
			Table:     int(table),
			Type:      unix.RTN_LOCAL,
		}
		if err = netlink.RouteAdd(&route); err != nil {
			if !errors.Is(err, unix.EEXIST) {
				return cleanup(E.Cause(err, "add shared-network socket-assignment local route"))
			}
			if err = verifySharedNetworkLocalRoute(route); err != nil {
				return cleanup(err)
			}
		} else {
			result.routes = append(result.routes, route)
		}
	}
	return result, nil
}

func verifySharedNetworkPolicyRule(expected netlink.Rule) error {
	rules, err := netlink.RuleList(expected.Family)
	if err != nil {
		return E.Cause(err, "list shared-network policy rules")
	}
	for _, current := range rules {
		if current.Priority == expected.Priority && current.Table == expected.Table &&
			current.Mark == expected.Mark && current.Mask == expected.Mask {
			return nil
		}
	}
	return E.New("shared-network policy rule priority ", expected.Priority, " is owned by incompatible state")
}

func verifySharedNetworkLocalRoute(expected netlink.Route) error {
	routes, err := netlink.RouteListFiltered(expected.Family, &netlink.Route{Table: expected.Table}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return E.Cause(err, "list shared-network policy routes")
	}
	for _, current := range routes {
		if current.Table == expected.Table && current.LinkIndex == expected.LinkIndex && current.Type == expected.Type &&
			equalSharedNetworkIPNet(current.Dst, expected.Dst) {
			return nil
		}
	}
	return E.New("shared-network routing table ", expected.Table, " is owned by incompatible state")
}

func equalSharedNetworkIPNet(left, right *net.IPNet) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.IP.Equal(right.IP) && string(left.Mask) == string(right.Mask)
}

func (r *sharedNetworkPolicyRoute) Close() error {
	if r == nil {
		return nil
	}
	var closeErr error
	for index := len(r.routes) - 1; index >= 0; index-- {
		if err := netlink.RouteDel(&r.routes[index]); err != nil && !errors.Is(err, unix.ENOENT) && !errors.Is(err, unix.ESRCH) {
			closeErr = E.Errors(closeErr, err)
		}
	}
	for index := len(r.rules) - 1; index >= 0; index-- {
		if err := netlink.RuleDel(&r.rules[index]); err != nil && !errors.Is(err, unix.ENOENT) && !errors.Is(err, unix.ESRCH) {
			closeErr = E.Errors(closeErr, err)
		}
	}
	return closeErr
}
