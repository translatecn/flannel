package backend

import (
	"github.com/flannel-io/flannel/pkg/over/lease"
	"golang.org/x/net/context"
)

type SimpleNetwork struct {
	SubnetLease *lease.Lease
	ExtIface    *ExternalInterface
}

func (n *SimpleNetwork) Lease() *lease.Lease {
	return n.SubnetLease
}

func (n *SimpleNetwork) MTU() int {
	return n.ExtIface.Iface.MTU
}

func (_ *SimpleNetwork) Run(ctx context.Context) {
	<-ctx.Done()
}
