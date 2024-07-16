package hostgw

import (
	"fmt"
	"github.com/flannel-io/flannel/pkg/over/lease"
	subnet2 "github.com/flannel-io/flannel/pkg/over/subnet"
	"sync"

	"github.com/flannel-io/flannel/pkg/backend"
	"github.com/flannel-io/flannel/pkg/ip"
	"github.com/vishvananda/netlink"
	"golang.org/x/net/context"
)

func init() {
	backend.Register("host-gw", New)
}

type HostgwBackend struct {
	sm       *subnet2.KubeSubnetManager
	extIface *backend.ExternalInterface
}

func New(sm *subnet2.KubeSubnetManager, extIface *backend.ExternalInterface) (backend.Backend, error) {
	if !extIface.ExtAddr.Equal(extIface.IfaceAddr) {
		return nil, fmt.Errorf("your PublicIP differs from interface IP, meaning that probably you're on a NAT, which is not supported by host-gw backend")
	}

	be := &HostgwBackend{
		sm:       sm,
		extIface: extIface,
	}
	return be, nil
}

func (be *HostgwBackend) RegisterNetwork(ctx context.Context, wg *sync.WaitGroup, config *subnet2.Config) (backend.Network, error) {
	n := &backend.RouteNetwork{
		SimpleNetwork: backend.SimpleNetwork{
			ExtIface: be.extIface,
		},
		SM:          be.sm,
		BackendType: "host-gw",
		Mtu:         be.extIface.Iface.MTU,
		LinkIndex:   be.extIface.Iface.Index,
	}

	attrs := lease.LeaseAttrs{
		BackendType: "host-gw",
	}

	if config.EnableIPv4 {
		attrs.PublicIP = ip.FromIP(be.extIface.ExtAddr)
		n.GetRoute = func(lease *lease.Lease) *netlink.Route {
			return &netlink.Route{
				Dst:       lease.Subnet.ToIPNet(),
				Gw:        lease.Attrs.PublicIP.ToIP(),
				LinkIndex: n.LinkIndex,
			}
		}
	}

	if config.EnableIPv6 {
		attrs.PublicIPv6 = ip.FromIP6(be.extIface.ExtV6Addr)
		n.GetV6Route = func(lease *lease.Lease) *netlink.Route {
			return &netlink.Route{
				Dst:       lease.IPv6Subnet.ToIPNet(),
				Gw:        lease.Attrs.PublicIPv6.ToIP(),
				LinkIndex: n.LinkIndex,
			}
		}
	}

	l, err := be.sm.AcquireLease(ctx, &attrs)
	switch err {
	case nil:
		n.SubnetLease = l

	case context.Canceled, context.DeadlineExceeded:
		return nil, err

	default:
		return nil, fmt.Errorf("failed to acquire lease: %v", err)
	}

	return n, nil
}
