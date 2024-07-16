package udp

import (
	"encoding/json"
	"fmt"
	"github.com/flannel-io/flannel/pkg/over/lease"
	subnet2 "github.com/flannel-io/flannel/pkg/over/subnet"
	"sync"

	"github.com/flannel-io/flannel/pkg/backend"
	"github.com/flannel-io/flannel/pkg/ip"
	"golang.org/x/net/context"
)

func init() {
	backend.Register("udp", New)
}

const (
	defaultPort = 8285
)

type UdpBackend struct {
	sm       *subnet2.KubeSubnetManager
	extIface *backend.ExternalInterface
}

func New(sm *subnet2.KubeSubnetManager, extIface *backend.ExternalInterface) (backend.Backend, error) {
	be := UdpBackend{
		sm:       sm,
		extIface: extIface,
	}
	return &be, nil
}

func (be *UdpBackend) RegisterNetwork(ctx context.Context, wg *sync.WaitGroup, config *subnet2.Config) (backend.Network, error) {
	cfg := struct {
		Port int
	}{
		Port: defaultPort,
	}

	// Parse our configuration
	if len(config.Backend) > 0 {
		if err := json.Unmarshal(config.Backend, &cfg); err != nil {
			return nil, fmt.Errorf("error decoding UDP backend config: %v", err)
		}
	}

	// Acquire the lease form subnet manager
	attrs := lease.LeaseAttrs{
		PublicIP: ip.FromIP(be.extIface.ExtAddr),
	}

	l, err := be.sm.AcquireLease(ctx, &attrs)
	switch err {
	case nil:

	case context.Canceled, context.DeadlineExceeded:
		return nil, err

	default:
		return nil, fmt.Errorf("failed to acquire lease: %v", err)
	}

	// Tunnel's subnet is that of the whole overlay network (e.g. /16)
	// and not that of the individual host (e.g. /24)
	tunNet := ip.IP4Net{
		IP:        l.Subnet.IP,
		PrefixLen: config.Network.PrefixLen,
	}

	return newNetwork(be.sm, be.extIface, cfg.Port, tunNet, l)
}
