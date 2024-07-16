package ipsec

import (
	"encoding/json"
	"fmt"
	"github.com/flannel-io/flannel/pkg/over/lease"
	subnet2 "github.com/flannel-io/flannel/pkg/over/subnet"
	"sync"

	"golang.org/x/net/context"

	"github.com/flannel-io/flannel/pkg/backend"
	"github.com/flannel-io/flannel/pkg/ip"
	log "k8s.io/klog/v2"
)

/*
	Flannel's approach to IPSec uses Strongswan to handle the key exchange (using IKEv2) and the kernel to handle the
	actual encryption.

	Flannel runs Strongswan's "charon" as a child process when the ipsec backend is selected and communicates with it
	using the "VICI" interface. Strongswan ships a utility "swanctl" which also uses the VICI interface. This utility
	is bundled in the flannel container and can help with debugging.

	The file "handle_charon.go" contains the logic for working with the charon. It supports creating a "CharonIKEDaemon"
	which supports loading the PSK into the charon and adding and removing connections.

	The file "handle_xfrm.go" contains functions for adding and removing the ipsec polcies.

	ipsec_network.go ties it all together, loading the PSK for current host on startu and as new hosts are added and
	removed it, adds/removes the PSK and connection details to strongswan and adds/remove the policy to the kernel.
*/

const (
	defaultESPProposal = "aes128gcm16-sha256-prfsha256-ecp256"
	minPasswordLength  = 96
)

func init() {
	backend.Register("ipsec", New)
}

type IPSECBackend struct {
	sm       *subnet2.KubeSubnetManager
	extIface *backend.ExternalInterface
}

func New(sm *subnet2.KubeSubnetManager, extIface *backend.ExternalInterface) (
	backend.Backend, error) {
	be := &IPSECBackend{
		sm:       sm,
		extIface: extIface,
	}

	return be, nil
}

func (be *IPSECBackend) RegisterNetwork(
	ctx context.Context, wg *sync.WaitGroup, config *subnet2.Config) (backend.Network, error) {

	cfg := struct {
		UDPEncap    bool
		ESPProposal string
		PSK         string
	}{
		UDPEncap:    false,
		ESPProposal: defaultESPProposal,
	}

	if len(config.Backend) > 0 {
		if err := json.Unmarshal(config.Backend, &cfg); err != nil {
			return nil, fmt.Errorf("error decoding IPSEC backend config: %v", err)
		}
	}

	if len(cfg.PSK) < minPasswordLength {
		return nil, fmt.Errorf("config error, password is too short")
	}

	log.Infof("IPSec config: UDPEncap=%v ESPProposal=%s", cfg.UDPEncap, cfg.ESPProposal)

	attrs := lease.LeaseAttrs{
		PublicIP:    ip.FromIP(be.extIface.ExtAddr),
		BackendType: "ipsec",
	}

	l, err := be.sm.AcquireLease(ctx, &attrs)

	switch err {
	case nil:

	case context.Canceled, context.DeadlineExceeded:
		return nil, err

	default:
		return nil, fmt.Errorf("failed to acquire lease: %v", err)
	}

	ikeDaemon, err := NewCharonIKEDaemon(ctx, wg, cfg.ESPProposal)
	if err != nil {
		return nil, fmt.Errorf("error creating CharonIKEDaemon struct: %v", err)
	}

	return newNetwork(be.sm, be.extIface, cfg.UDPEncap, cfg.PSK, ikeDaemon, l)
}
