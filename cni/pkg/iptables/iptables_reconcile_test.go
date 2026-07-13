// Copyright Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package iptables

import (
	"bytes"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"

	istiolog "istio.io/istio/pkg/log"
	"istio.io/istio/pkg/test/util/assert"
	iptablesconstants "istio.io/istio/tools/istio-iptables/pkg/constants"
	dep "istio.io/istio/tools/istio-iptables/pkg/dependencies"
)

// hostStateStub 在 DependenciesStub 的基础上模拟宿主机上已存在的 iptables 状态：
// iptables-save 返回预设快照，iptables -C 按 checkFails 决定成败，其余命令仅记录。
type hostStateStub struct {
	dep.DependenciesStub
	saveOutput string
	checkFails bool
}

func (s *hostStateStub) Run(logger *istiolog.Scope, quietLogging bool, cmd iptablesconstants.IptablesCmd,
	iptVer *dep.IptablesVersion, stdin io.ReadSeeker, args ...string,
) (*bytes.Buffer, error) {
	// 记录所有执行的命令，便于断言
	_, _ = s.DependenciesStub.Run(logger, quietLogging, cmd, iptVer, stdin, args...)
	if cmd == iptablesconstants.IPTablesSave {
		return bytes.NewBufferString(s.saveOutput), nil
	}
	if cmd == iptablesconstants.IPTables && slices.Contains(args, "-C") {
		if s.checkFails {
			return nil, errors.New("rule does not exist")
		}
	}
	return &bytes.Buffer{}, nil
}

// convergedHostState 是与期望的宿主机规则完全一致的 iptables-save 快照
// （POSTROUTING 跳转 + ISTIO_POSTRT 内一条 SNAT 规则）。
const convergedHostState = `*nat
:PREROUTING ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
:ISTIO_POSTRT - [0:0]
-A POSTROUTING -j ISTIO_POSTRT
-A ISTIO_POSTRT -m owner --socket-exists -p tcp -m set --match-set istio-inpod-probes-v4 dst -j SNAT --to-source 169.254.7.127
COMMIT
`

// driftedHostState 模拟外部 flush 后的状态：ISTIO_POSTRT 链仍在但规则被清空
// （对应 issue #60607 的复现步骤 `iptables -t nat -F ISTIO_POSTRT`）。
const driftedHostState = `*nat
:PREROUTING ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
:ISTIO_POSTRT - [0:0]
-A POSTROUTING -j ISTIO_POSTRT
COMMIT
`

func TestEnsureHostRulesNoopWhenConverged(t *testing.T) {
	cfg := constructTestConfig()
	ext := &hostStateStub{saveOutput: convergedHostState}
	iptConfigurator, _, err := NewIptablesConfigurator(cfg, cfg, ext, ext, EmptyNlDeps())
	assert.NoError(t, err)

	repaired, err := iptConfigurator.EnsureHostRules()
	assert.NoError(t, err)
	assert.Equal(t, false, repaired)

	// 收敛状态下必须是纯只读校验：不允许出现任何删除/重建/restore 写操作
	assert.Equal(t, 0, len(ext.ExecutedStdin))
	for _, cmd := range ext.ExecutedAll {
		for _, forbidden := range []string{" -D ", " -F ", " -X ", "iptables-restore"} {
			if strings.Contains(cmd, forbidden) {
				t.Fatalf("expected no mutating command when converged, got: %v", cmd)
			}
		}
	}
	// IPv6 未启用时不应触碰 ip6tables
	for _, cmd := range ext.ExecutedAll {
		if strings.Contains(cmd, "ip6tables") {
			t.Fatalf("expected no ip6tables invocation when IPv6 is disabled, got: %v", cmd)
		}
	}
}

func TestEnsureHostRulesRepairsDrift(t *testing.T) {
	cfg := constructTestConfig()
	ext := &hostStateStub{saveOutput: driftedHostState}
	iptConfigurator, _, err := NewIptablesConfigurator(cfg, cfg, ext, ext, EmptyNlDeps())
	assert.NoError(t, err)

	repaired, err := iptConfigurator.EnsureHostRules()
	assert.NoError(t, err)
	assert.Equal(t, true, repaired)

	// 修复动作必须与启动路径一致：先删（-D jump / -F / -X 链）后建（iptables-restore）
	joined := strings.Join(ext.ExecutedAll, "\n")
	for _, expected := range []string{
		"-t nat -D POSTROUTING -j ISTIO_POSTRT",
		"-t nat -F ISTIO_POSTRT",
		"-t nat -X ISTIO_POSTRT",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("expected delete command %q in executed commands:\n%v", expected, joined)
		}
	}
	// restore 载荷（stdin）中必须重建 SNAT 规则
	restorePayload := strings.Join(ext.ExecutedStdin, "\n")
	if !strings.Contains(restorePayload, "-j SNAT --to-source 169.254.7.127") {
		t.Fatalf("expected SNAT rule in restore payload:\n%v", restorePayload)
	}

	// 宿主机 netns 中绝不允许出现 guardrails DROP 规则（那会瞬断整个节点的流量）
	if strings.Contains(joined, "-j DROP") {
		t.Fatalf("host rules reconcile must never install guardrail DROP rules, got:\n%v", joined)
	}
}

func TestEnsureHostRulesRepairsMissingCheckedRule(t *testing.T) {
	// 链与规则数量看起来都对，但逐条 -C 校验失败（如 POSTROUTING jump 被外部删除后
	// 又被塞入了别的规则），也应触发修复
	cfg := constructTestConfig()
	ext := &hostStateStub{saveOutput: convergedHostState, checkFails: true}
	iptConfigurator, _, err := NewIptablesConfigurator(cfg, cfg, ext, ext, EmptyNlDeps())
	assert.NoError(t, err)

	repaired, err := iptConfigurator.EnsureHostRules()
	assert.NoError(t, err)
	assert.Equal(t, true, repaired)
}
