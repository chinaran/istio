// Copyright Istio Authors
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

package trafficmanager

import (
	"istio.io/istio/cni/pkg/config"
	"istio.io/istio/cni/pkg/iptables"
	istiolog "istio.io/istio/pkg/log"
)

// TrafficRuleManager defines the interface for managing traffic redirection rules
// in Ambient mode. This abstraction allows switching between iptables and nftables
// implementations without changing the higher-level logic.
type TrafficRuleManager interface {
	CreateInpodRules(log *istiolog.Scope, podOverrides config.PodLevelOverrides) error
	DeleteInpodRules(log *istiolog.Scope) error
	CreateHostRulesForHealthChecks() error
	DeleteHostRules()
	// EnsureHostRules 验证主机级规则是否仍与期望状态一致，并在规则发生漂移时
	// （例如被 firewalld 重载或外部 iptables-restore 删除）重新安装规则。
	// 该方法具备幂等性，供定期协调循环调用。repaired 返回值表示是否检测到漂移
	// 并执行了修复。无法验证状态时（例如发生瞬时读取故障），会返回错误且不尝试修复。
	EnsureHostRules() (repaired bool, err error)
	ReconcileModeEnabled() bool
}

type TrafficRuleManagerConfig struct {
	// Use native nftables instead of iptables
	NativeNftables bool

	// Host-level configuration
	HostConfig *config.AmbientConfig

	// Pod-level configuration
	PodConfig *config.AmbientConfig

	// Dependencies for iptables (host and pod)
	HostDeps interface{}
	PodDeps  interface{}

	NlDeps iptables.NetlinkDependencies
}

// NewTrafficRuleManager creates both host and pod traffic rule managers based on configuration
func NewTrafficRuleManager(cfg *TrafficRuleManagerConfig) (hostManager, podManager TrafficRuleManager, err error) {
	if cfg.NativeNftables {
		return NewNftablesTrafficManager(cfg)
	}
	return NewIptablesTrafficManager(cfg)
}
