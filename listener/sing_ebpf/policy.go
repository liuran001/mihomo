//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"net/netip"
	"slices"

	ECommon "github.com/metacubex/mihomo/common/ebpf"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/log"

	E "github.com/metacubex/sing/common/exceptions"

	"go4.org/netipx"
)

type toIpCidr interface {
	ToIpCidr() *netipx.IPSet
}

func (i *Inbound) startBypassRuleSets() error {
	i.bypassRuleSetAccess.Lock()
	defer i.bypassRuleSetAccess.Unlock()
	if i.bypassRuleSetStarted {
		return nil
	}
	rp, ok := i.tunnel.(P.Tunnel)
	if !ok {
		return E.New("tunnel does not expose rule providers")
	}
	i.bypassRuleSetCallback = rp.RuleUpdateCallback().Register(i.updateBypassRuleSet)
	i.bypassRuleSetStarted = true
	updated, err := i.refreshBypassCIDRsLocked()
	if err != nil {
		i.stopBypassRuleSetsLocked()
		return err
	}
	if updated {
		i.logBypassCIDRUpdate()
	}
	return nil
}

func (i *Inbound) stopBypassRuleSets() {
	i.bypassRuleSetAccess.Lock()
	defer i.bypassRuleSetAccess.Unlock()
	i.stopBypassRuleSetsLocked()
}

func (i *Inbound) stopBypassRuleSetsLocked() {
	if !i.bypassRuleSetStarted {
		return
	}
	if i.bypassRuleSetCallback != nil {
		_ = i.bypassRuleSetCallback.Close()
		i.bypassRuleSetCallback = nil
	}
	i.bypassRuleSetStarted = false
}

func (i *Inbound) updateBypassRuleSet(P.RuleProvider) {
	i.bypassRuleSetAccess.Lock()
	defer i.bypassRuleSetAccess.Unlock()
	if !i.bypassRuleSetStarted {
		return
	}
	updated, err := i.refreshBypassCIDRsLocked()
	if err != nil {
		if backend := i.backendInstance(); backend != nil && !backend.IsClosed() {
			log.Errorln("[EBPF] refresh bypass_rule_set: %s", err.Error())
		}
		return
	}
	if updated {
		i.logBypassCIDRUpdate()
	}
}

func (i *Inbound) currentBypassCIDR() []netip.Prefix {
	i.bypassRuleSetAccess.Lock()
	defer i.bypassRuleSetAccess.Unlock()
	return slices.Clone(i.bypassCIDR)
}

func (i *Inbound) localInterfaceAddresses() []netip.Addr {
	prefixes := localInterfacePrefixes()
	addresses := make([]netip.Addr, 0, len(prefixes))
	for _, prefix := range prefixes {
		addresses = append(addresses, prefix.Addr())
	}
	return addresses
}

func (i *Inbound) refreshHostAddresses(backend *ECommon.CgroupBackend) error {
	if err := backend.UpdateHostAddresses(i.localInterfaceAddresses()); err != nil {
		return E.Cause(err, "update eBPF local interface host addresses")
	}
	return nil
}

// refreshBypassCIDRsLocked applies the effective bypass CIDR policy. Host
// interface addresses go to the dedicated host maps, while the bypass_rule_set
// prefixes go to the bypass CIDR maps; the two are intentionally separated so
// the LPM trie matches exactly the configured rules.
func (i *Inbound) refreshBypassCIDRsLocked() (bool, error) {
	var ruleSetPrefixes []netip.Prefix
	for _, ruleSet := range i.bypassRuleSet {
		strategy := ruleSet.Strategy()
		ipCidrStrategy, ok := strategy.(toIpCidr)
		if !ok {
			continue
		}
		ipSet := ipCidrStrategy.ToIpCidr()
		if ipSet == nil {
			continue
		}
		ruleSetPrefixes = append(ruleSetPrefixes, ipSet.Prefixes()...)
	}
	policy, err := ECommon.CompileBypassCIDRPolicy(ruleSetPrefixes)
	if err != nil {
		return false, E.Cause(err, "compile eBPF bypass CIDR policy")
	}
	i.bypassRuleSetPolicy = policy
	i.bypassRuleSetDirty = true
	return i.applyBypassCIDRLocked()
}

// applyBypassCIDRLocked pushes host addresses and, when the bypass rule-set
// policy changed, the compiled bypass CIDR policy to the backends.
func (i *Inbound) applyBypassCIDRLocked() (bool, error) {
	backend := i.backendInstance()
	if backend == nil {
		return false, E.New("eBPF backend is not initialized")
	}
	if err := i.refreshHostAddresses(backend); err != nil {
		return false, err
	}
	if !i.bypassRuleSetDirty {
		return false, nil
	}
	updated, err := backend.UpdateCompiledBypassCIDR(i.bypassRuleSetPolicy)
	if err != nil {
		return false, err
	}
	i.bypassRuleSetDirty = false
	i.bypassCIDR = i.bypassRuleSetPolicy.Prefixes()
	// Keep the shared-network backend's bypass flags in sync. It reuses the
	// cgroup backend's bypass maps, so only the control presence flags need to
	// follow the effective CIDR set (including runtime bypass_rule_set changes).
	if i.sharedNetwork != nil {
		if sharedBackend := i.sharedNetwork.sharedBackendInstance(); sharedBackend != nil && !sharedBackend.IsClosed() {
			ipv4Count, ipv6Count := backend.BypassCIDRCount()
			if stateErr := sharedBackend.SetBypassCIDRState(ipv4Count, ipv6Count); stateErr != nil {
				log.Errorln("[EBPF] refresh shared-network bypass CIDR state: %s", stateErr.Error())
			}
		}
	}
	// Recompute the set the DNS fake-ip middleware consults, so domains whose
	// real addresses fall inside it keep their real IP and the kernel eBPF
	// bypass can engage. Only bypass_rule_set feeds it; publishing the private
	// ranges here would make every A/AAAA query resolve for real before
	// fake-ip could answer it.
	i.dnsBypassSet = nil
	if len(i.bypassRuleSet) > 0 {
		var builder netipx.IPSetBuilder
		for _, prefix := range i.bypassCIDR {
			builder.AddPrefix(prefix)
		}
		if bypassSet, buildErr := builder.IPSet(); buildErr == nil {
			i.dnsBypassSet = bypassSet
		}
	}
	i.publishBypassPolicyLocked()
	return updated, nil
}
