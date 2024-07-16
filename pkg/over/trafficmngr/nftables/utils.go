package nftables

import (
	"context"

	log "k8s.io/klog/v2"
	"sigs.k8s.io/knftables"
)

const (
	masqueradeTestTable = "masqueradeTest"
)

// check whether masquerade fully-random is supported by the kernel
func (nftm *NFTablesManager) checkRandomfully(ctx context.Context) bool {
	result := true
	tx := nftm.nftv4.NewTransaction()
	tx.Add(&knftables.Chain{
		Name:     masqueradeTestTable,
		Comment:  knftables.PtrTo("chain to test if masquerade random fully is supported"),
		Type:     knftables.PtrTo(knftables.NATType),
		Hook:     knftables.PtrTo(knftables.PostroutingHook),
		Priority: knftables.PtrTo(knftables.SNATPriority),
	})
	tx.Flush(&knftables.Chain{
		Name: masqueradeTestTable,
	})
	// Masquerade anything headed towards flannel from the host
	tx.Add(&knftables.Rule{
		Chain: masqueradeTestTable,
		Rule: knftables.Concat(
			"ip saddr", "!=", "127.0.0.1",
			"masquerade fully-random",
		),
	})
	err := nftm.nftv4.Check(ctx, tx)
	if err != nil {
		log.Warningf("nftables: random fully unsupported")
		result = false
	}
	return result
}
