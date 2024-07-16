package vxlan

import (
	"fmt"
	"github.com/containernetworking/plugins/pkg/utils/sysctl"
	"github.com/flannel-io/flannel/pkg/over/mac"
	"net"
	"syscall"

	"github.com/flannel-io/flannel/pkg/ip"
	"github.com/vishvananda/netlink"
	log "k8s.io/klog/v2"
)

type vxlanDeviceAttrs struct {
	vni       uint32
	name      string
	MTU       int
	vtepIndex int
	vtepAddr  net.IP
	vtepPort  int
	gbp       bool
	learning  bool
	hwAddr    net.HardwareAddr
}

type vxlanDevice struct {
	link          *netlink.Vxlan
	directRouting bool
}

func (dev *vxlanDevice) MACAddr() net.HardwareAddr {
	return dev.link.HardwareAddr
}

type neighbor struct {
	MAC net.HardwareAddr
	IP  ip.IP4
	IP6 *ip.IP6
}

func (dev *vxlanDevice) AddFDB(n neighbor) error {
	log.V(4).Infof("calling AddFDB: %v, %v", n.IP, n.MAC)
	return netlink.NeighSet(&netlink.Neigh{
		LinkIndex:    dev.link.Index,
		State:        netlink.NUD_PERMANENT,
		Family:       syscall.AF_BRIDGE,
		Flags:        netlink.NTF_SELF,
		IP:           n.IP.ToIP(),
		HardwareAddr: n.MAC,
	})
}

func (dev *vxlanDevice) AddV6FDB(n neighbor) error {
	log.V(4).Infof("calling AddV6FDB: %v, %v", n.IP6, n.MAC)
	return netlink.NeighSet(&netlink.Neigh{
		LinkIndex:    dev.link.Index,
		State:        netlink.NUD_PERMANENT,
		Family:       syscall.AF_BRIDGE,
		Flags:        netlink.NTF_SELF,
		IP:           n.IP6.ToIP(),
		HardwareAddr: n.MAC,
	})
}

func (dev *vxlanDevice) DelFDB(n neighbor) error {
	log.V(4).Infof("calling DelFDB: %v, %v", n.IP, n.MAC)
	return netlink.NeighDel(&netlink.Neigh{
		LinkIndex:    dev.link.Index,
		Family:       syscall.AF_BRIDGE,
		Flags:        netlink.NTF_SELF,
		IP:           n.IP.ToIP(),
		HardwareAddr: n.MAC,
	})
}

func (dev *vxlanDevice) DelV6FDB(n neighbor) error {
	log.V(4).Infof("calling DelV6FDB: %v, %v", n.IP6, n.MAC)
	return netlink.NeighDel(&netlink.Neigh{
		LinkIndex:    dev.link.Index,
		Family:       syscall.AF_BRIDGE,
		Flags:        netlink.NTF_SELF,
		IP:           n.IP6.ToIP(),
		HardwareAddr: n.MAC,
	})
}

func (dev *vxlanDevice) AddARP(n neighbor) error {
	log.V(4).Infof("calling AddARP: %v, %v", n.IP, n.MAC)
	return netlink.NeighSet(&netlink.Neigh{
		LinkIndex:    dev.link.Index,
		State:        netlink.NUD_PERMANENT,
		Type:         syscall.RTN_UNICAST,
		IP:           n.IP.ToIP(),
		HardwareAddr: n.MAC,
	})
}

func (dev *vxlanDevice) AddV6ARP(n neighbor) error {
	log.V(4).Infof("calling AddV6ARP: %v, %v", n.IP6, n.MAC)
	return netlink.NeighSet(&netlink.Neigh{
		LinkIndex:    dev.link.Index,
		State:        netlink.NUD_PERMANENT,
		Type:         syscall.RTN_UNICAST,
		IP:           n.IP6.ToIP(),
		HardwareAddr: n.MAC,
	})
}

func (dev *vxlanDevice) DelARP(n neighbor) error {
	log.V(4).Infof("calling DelARP: %v, %v", n.IP, n.MAC)
	return netlink.NeighDel(&netlink.Neigh{
		LinkIndex:    dev.link.Index,
		State:        netlink.NUD_PERMANENT,
		Type:         syscall.RTN_UNICAST,
		IP:           n.IP.ToIP(),
		HardwareAddr: n.MAC,
	})
}

func (dev *vxlanDevice) DelV6ARP(n neighbor) error {
	log.V(4).Infof("calling DelV6ARP: %v, %v", n.IP6, n.MAC)
	return netlink.NeighDel(&netlink.Neigh{
		LinkIndex:    dev.link.Index,
		State:        netlink.NUD_PERMANENT,
		Type:         syscall.RTN_UNICAST,
		IP:           n.IP6.ToIP(),
		HardwareAddr: n.MAC,
	})
}

func newVXLANDevice(devAttrs *vxlanDeviceAttrs) (*vxlanDevice, error) {
	var err error
	hardwareAddr := devAttrs.hwAddr
	if devAttrs.hwAddr == nil {
		hardwareAddr, err = mac.NewHardwareAddr()
		if err != nil {
			return nil, err
		}
	}

	link := &netlink.Vxlan{
		LinkAttrs: netlink.LinkAttrs{
			Name:         devAttrs.name,
			HardwareAddr: hardwareAddr,
			MTU:          devAttrs.MTU - 50,
		},
		VxlanId:      int(devAttrs.vni),
		VtepDevIndex: devAttrs.vtepIndex,
		SrcAddr:      devAttrs.vtepAddr,
		Port:         devAttrs.vtepPort,
		Learning:     devAttrs.learning,
		GBP:          devAttrs.gbp,
	}

	link, err = ensureLink(link)
	if err != nil {
		return nil, err
	}

	_, _ = sysctl.Sysctl(fmt.Sprintf("net/ipv6/conf/%s/accept_ra", devAttrs.name), "0")

	return &vxlanDevice{
		link: link,
	}, nil
}

//
//RA（Router Advertisement）报文是IPv6网络中路由器发送给主机的广播消息，用以告知主机关于网络的各项配置信息，如IPv6前缀、默认网关、MTU、以及是否支持SLAAC等。
//
//RA报文作为IPv6网络中的一个重要组成部分，其设计初衷是为了简化网络管理，并使网络设备能够快速适应不断变化的网络环境。在IPv6协议中
//，节点通过解析RA报文来自动配置网络参数，这一机制不仅提高了网络配置的效率，还增强了网络的灵活性和可扩展性。
//0表示不接受RA；
//1表示如果forwarding是关闭的就接受RA，如果forwarding是打开的则不接受RA（代表主机可能作为一个路由器）；
//2表示不论forwarding是打开还是关闭，都接受RA。
//echo '0' > /proc/sys/net/ipv6/conf/veth467bf51d/accept_ra

func ensureLink(vxlan *netlink.Vxlan) (*netlink.Vxlan, error) {
	err := netlink.LinkAdd(vxlan)
	if err == syscall.EEXIST {
		// it's ok if the device already exists as long as config is similar
		log.V(1).Infof("VXLAN device already exists")
		existing, err := netlink.LinkByName(vxlan.Name)
		if err != nil {
			return nil, err
		}

		incompat := vxlanLinksIncompat(vxlan, existing)
		if incompat == "" {
			log.V(1).Infof("Returning existing device")
			return existing.(*netlink.Vxlan), nil
		}

		// delete existing
		log.Warningf("%q already exists with incompatible configuration: %v; recreating device", vxlan.Name, incompat)
		if err = netlink.LinkDel(existing); err != nil {
			return nil, fmt.Errorf("failed to delete interface: %v", err)
		}

		// create new
		if err = netlink.LinkAdd(vxlan); err != nil {
			return nil, fmt.Errorf("failed to create vxlan interface: %v", err)
		}
	} else if err != nil {
		return nil, err
	}

	ifindex := vxlan.Index
	link, err := netlink.LinkByIndex(vxlan.Index)
	if err != nil {
		return nil, fmt.Errorf("can't locate created vxlan device with index %v", ifindex)
	}

	var ok bool
	if vxlan, ok = link.(*netlink.Vxlan); !ok {
		return nil, fmt.Errorf("created vxlan device with index %v is not vxlan", ifindex)
	}

	return vxlan, nil
}

func vxlanLinksIncompat(l1, l2 netlink.Link) string { // 兼容
	// vxlan
	if l1.Type() != l2.Type() {
		return fmt.Sprintf("link type: %v vs %v", l1.Type(), l2.Type())
	}

	v1 := l1.(*netlink.Vxlan)
	v2 := l2.(*netlink.Vxlan)

	if v1.VxlanId != v2.VxlanId {
		return fmt.Sprintf("vni: %v vs %v", v1.VxlanId, v2.VxlanId)
	}

	if v1.VtepDevIndex > 0 && v2.VtepDevIndex > 0 && v1.VtepDevIndex != v2.VtepDevIndex {
		return fmt.Sprintf("vtep (external) interface: %v vs %v", v1.VtepDevIndex, v2.VtepDevIndex)
	}

	if len(v1.SrcAddr) > 0 && len(v2.SrcAddr) > 0 && !v1.SrcAddr.Equal(v2.SrcAddr) {
		return fmt.Sprintf("vtep (external) IP: %v vs %v", v1.SrcAddr, v2.SrcAddr)
	}

	if len(v1.Group) > 0 && len(v2.Group) > 0 && !v1.Group.Equal(v2.Group) {
		return fmt.Sprintf("group address: %v vs %v", v1.Group, v2.Group)
	}

	if v1.L2miss != v2.L2miss {
		return fmt.Sprintf("l2miss: %v vs %v", v1.L2miss, v2.L2miss)
	}

	if v1.Port > 0 && v2.Port > 0 && v1.Port != v2.Port {
		return fmt.Sprintf("port: %v vs %v", v1.Port, v2.Port)
	}

	if v1.GBP != v2.GBP {
		return fmt.Sprintf("gbp: %v vs %v", v1.GBP, v2.GBP)
	}

	return ""
}

func (dev *vxlanDevice) Configure(ipa ip.IP4Net, flannelnet ip.IP4Net) error {
	if err := ip.EnsureV4AddressOnLink(ipa, flannelnet, dev.link); err != nil {
		return fmt.Errorf("failed to ensure address of interface %s: %s", dev.link.Attrs().Name, err)
	}

	if err := netlink.LinkSetUp(dev.link); err != nil {
		return fmt.Errorf("failed to set interface %s to UP state: %s", dev.link.Attrs().Name, err)
	}

	// ensure vxlan device hadware mac
	// See https://github.com/flannel-io/flannel/issues/1795
	nLink, err := netlink.LinkByName(dev.link.LinkAttrs.Name)
	if err == nil {
		if vxlan, ok := nLink.(*netlink.Vxlan); ok {
			if vxlan.Attrs().HardwareAddr.String() != dev.MACAddr().String() {
				return fmt.Errorf("%s's mac address wanted: %s, but got: %v", dev.link.Name, dev.MACAddr().String(), vxlan.HardwareAddr)
			}
		}
	}

	return nil
}

func (dev *vxlanDevice) ConfigureIPv6(ipn ip.IP6Net, flannelnet ip.IP6Net) error {
	if err := ip.EnsureV6AddressOnLink(ipn, flannelnet, dev.link); err != nil {
		return fmt.Errorf("failed to ensure v6 address of interface %s: %w", dev.link.Attrs().Name, err)
	}

	if err := netlink.LinkSetUp(dev.link); err != nil {
		return fmt.Errorf("failed to set v6 interface %s to UP state: %w", dev.link.Attrs().Name, err)
	}

	// ensure vxlan device hadware mac
	// See https://github.com/flannel-io/flannel/issues/1795
	nLink, err := netlink.LinkByName(dev.link.LinkAttrs.Name)
	if err == nil {
		if vxlan, ok := nLink.(*netlink.Vxlan); ok {
			if vxlan.Attrs().HardwareAddr.String() != dev.MACAddr().String() {
				return fmt.Errorf("%s's v6 mac address wanted: %s, but got: %v", dev.link.Name, dev.MACAddr().String(), vxlan.HardwareAddr)
			}
		}
	}

	return nil
}
