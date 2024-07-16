// Copyright 2015 flannel authors
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

package subnet

import (
	"encoding/json"
	"fmt"
	"github.com/flannel-io/flannel/pkg/ip"
)

//	 {
//	  "Network": "100.64.0.0/17",
//	  "EnableNFTables": false,
//	  "Backend": {
//	    "Type": "vxlan"
//	  }
//	}

type Config struct {
	EnableIPv4     bool
	EnableIPv6     bool
	EnableNFTables bool
	Network        ip.IP4Net
	IPv6Network    ip.IP6Net
	SubnetMin      ip.IP4
	SubnetMax      ip.IP4
	IPv6SubnetMin  *ip.IP6
	IPv6SubnetMax  *ip.IP6
	SubnetLen      uint
	IPv6SubnetLen  uint
	BackendType    string          `json:"-"` // udp、alloc
	Backend        json.RawMessage `json:",omitempty"`
}

func parseBackendType(be json.RawMessage) (string, error) {
	var bt struct {
		Type string
	}

	if len(be) == 0 {
		return "udp", nil
	} else if err := json.Unmarshal(be, &bt); err != nil {
		return "", fmt.Errorf("error decoding Backend property of config: %v", err)
	}

	return bt.Type, nil
}
func ParseConfig(s string) (*Config, error) {
	cfg := new(Config)
	// Enable ipv4 by default
	cfg.EnableIPv4 = true
	err := json.Unmarshal([]byte(s), cfg)
	if err != nil {
		return nil, err
	}

	bt, err := parseBackendType(cfg.Backend)
	if err != nil {
		return nil, err
	}
	cfg.BackendType = bt

	return cfg, nil
}
