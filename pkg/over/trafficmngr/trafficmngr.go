// Copyright 2024 flannel authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package trafficmngr

import (
	"context"
	"github.com/flannel-io/flannel/pkg/over/lease"
	"sync"

	"github.com/flannel-io/flannel/pkg/ip"
)

type IPTablesRule struct {
	Table    string
	Action   string
	Chain    string
	Rulespec []string
}

const KubeProxyMark string = "0x4000/0x4000"

type TrafficManager interface {
	Init(ctx context.Context, wg *sync.WaitGroup) error
	// Install kernel rules to forward the traffic to and from the flannel network range.
	// This is done for IPv4 and/or IPv6 based on whether flannelIPv4Network and flannelIPv6Network are set.
	// SetupAndEnsureForwardRules starts a go routine that
	// rewrites these rules every resyncPeriod seconds if needed
	SetupAndEnsureForwardRules(ctx context.Context, flannelIPv4Network ip.IP4Net, flannelIPv6Network ip.IP6Net, resyncPeriod int)
	// SetupAndEnsureMasqRules 安装内核规则以设置将发送到flannel接口的数据包进行NAT。
	// 根据是否设置了flannelIPv4Network和flannelIPv6Network，这将针对IPv4和/或IPv6进行。
	// prevSubnet、prevNetworks、prevIPv6Subnet、prevIPv6Networks用于确定是否需要替换现有规则。
	// SetupAndEnsureMasqRules启动一个go例程，如果需要，每隔resyncPeriod秒就会重写这些规则。
	SetupAndEnsureMasqRules(ctx context.Context,
		flannelIPv4Net, prevSubnet, prevNetwork ip.IP4Net,
		flannelIPv6Net, prevIPv6Subnet, prevIPv6Network ip.IP6Net,
		currentlease *lease.Lease,
		resyncPeriod int) error
}
