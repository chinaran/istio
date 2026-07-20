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

// hostStateStub 基于 DependenciesStub 模拟主机上预先存在的 iptables 状态：
// iptables-save 返回预设快照（或以 saveErr 失败），iptables -C 根据 checkFails
// 成功或失败，iptables-restore 的前 restoreFailures 次调用失败，其他命令仅被记录。
type hostStateStub struct {
	dep.DependenciesStub
	saveOutput string
	saveErr    error
	checkFails bool
	// restoreFailures 使前 N 次 iptables-restore 调用失败，用于测试修复重试。
	restoreFailures int
}

func (s *hostStateStub) Run(logger *istiolog.Scope, quietLogging bool, cmd iptablesconstants.IptablesCmd,
	iptVer *dep.IptablesVersion, stdin io.ReadSeeker, args ...string,
) (*bytes.Buffer, error) {
	// 记录每条已执行的命令，供测试进行断言。
	_, _ = s.DependenciesStub.Run(logger, quietLogging, cmd, iptVer, stdin, args...)
	if cmd == iptablesconstants.IPTablesSave {
		if s.saveErr != nil {
			return nil, s.saveErr
		}
		return bytes.NewBufferString(s.saveOutput), nil
	}
	if cmd == iptablesconstants.IPTablesRestore && s.restoreFailures > 0 {
		s.restoreFailures--
		return nil, errors.New("restore transiently failed")
	}
	if cmd == iptablesconstants.IPTables && slices.Contains(args, "-C") {
		if s.checkFails {
			return nil, errors.New("rule does not exist")
		}
	}
	return &bytes.Buffer{}, nil
}

// convergedHostState 是与期望主机规则完全一致的 iptables-save 快照，
// 包含 POSTROUTING 跳转规则和 ISTIO_POSTRT 中的一条 SNAT 规则。
const convergedHostState = `*nat
:PREROUTING ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
:ISTIO_POSTRT - [0:0]
-A POSTROUTING -j ISTIO_POSTRT
-A ISTIO_POSTRT -m owner --socket-exists -p tcp -m set --match-set istio-inpod-probes-v4 dst -j SNAT --to-source 169.254.7.127
COMMIT
`

// driftedHostState 模拟外部清空后的状态：ISTIO_POSTRT 链仍然存在，但链内规则已消失，
// 即问题 #60607 的复现步骤 `iptables -t nat -F ISTIO_POSTRT`。
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

	// 状态收敛时必须只执行只读验证，不允许执行删除、重建或恢复写操作。
	assert.Equal(t, 0, len(ext.ExecutedStdin))
	for _, cmd := range ext.ExecutedAll {
		for _, forbidden := range []string{" -D ", " -F ", " -X ", "iptables-restore"} {
			if strings.Contains(cmd, forbidden) {
				t.Fatalf("expected no mutating command when converged, got: %v", cmd)
			}
		}
	}
	// 禁用 IPv6 时不得操作 ip6tables。
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

	// 修复流程必须与启动路径一致：先删除（-D 跳转规则、-F/-X 链），
	// 再通过 iptables-restore 重建。
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
	// 恢复内容（标准输入）必须重新创建 SNAT 规则。
	restorePayload := strings.Join(ext.ExecutedStdin, "\n")
	if !strings.Contains(restorePayload, "-j SNAT --to-source 169.254.7.127") {
		t.Fatalf("expected SNAT rule in restore payload:\n%v", restorePayload)
	}

	// 主机网络命名空间中绝不能出现 DROP 防护规则，否则会丢弃整个节点的流量。
	if strings.Contains(joined, "-j DROP") {
		t.Fatalf("host rules reconcile must never install guardrail DROP rules, got:\n%v", joined)
	}
}

func TestEnsureHostRulesSkipsRepairWhenStateUnreadable(t *testing.T) {
	// iptables-save 瞬时失败表示无法验证状态，并不表示规则发生了漂移。
	// 若因读取失败而删除仍在生效且可能正常的规则，协调器自身反而会造成它本应避免的故障；
	// 因此 EnsureHostRules 必须返回错误且不执行任何写操作。
	cfg := constructTestConfig()
	ext := &hostStateStub{saveErr: errors.New("iptables-save failed transiently")}
	iptConfigurator, _, err := NewIptablesConfigurator(cfg, cfg, ext, ext, EmptyNlDeps())
	assert.NoError(t, err)

	repaired, err := iptConfigurator.EnsureHostRules()
	assert.Equal(t, false, repaired)
	if err == nil {
		t.Fatal("expected an error when the iptables state cannot be read")
	}

	// 验证本身失败时，不得执行任何修改命令。
	assert.Equal(t, 0, len(ext.ExecutedStdin))
	for _, cmd := range ext.ExecutedAll {
		for _, forbidden := range []string{" -D ", " -F ", " -X "} {
			if strings.Contains(cmd, forbidden) {
				t.Fatalf("expected no mutating command when state is unreadable, got: %v", cmd)
			}
		}
	}
}

// foreignChainHostState 在 convergedHostState 的基础上增加一个以 ISTIO_ 为前缀、
// 但不属于预期主机状态的链，例如其他 Istio 组件或版本留下的残留。
// 删除并重建的修复流程无法移除此类链；若将其视为漂移，协调循环会在每个周期
// 不断重复应用规则，且永远无法收敛。
const foreignChainHostState = `*nat
:PREROUTING ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
:ISTIO_POSTRT - [0:0]
:ISTIO_OUTPUT - [0:0]
-A POSTROUTING -j ISTIO_POSTRT
-A ISTIO_POSTRT -m owner --socket-exists -p tcp -m set --match-set istio-inpod-probes-v4 dst -j SNAT --to-source 169.254.7.127
-A ISTIO_OUTPUT -p tcp -j ACCEPT
COMMIT
`

func TestEnsureHostRulesIgnoresForeignIstioChains(t *testing.T) {
	cfg := constructTestConfig()
	ext := &hostStateStub{saveOutput: foreignChainHostState}
	iptConfigurator, _, err := NewIptablesConfigurator(cfg, cfg, ext, ext, EmptyNlDeps())
	assert.NoError(t, err)

	// 所有受管理的规则都存在，因此不得将外部 ISTIO_OUTPUT 链报告为漂移，
	// 也不得执行修复。
	repaired, err := iptConfigurator.EnsureHostRules()
	assert.NoError(t, err)
	assert.Equal(t, false, repaired)
	assert.Equal(t, 0, len(ext.ExecutedStdin))
}

func TestEnsureHostRulesRetriesFailedRepair(t *testing.T) {
	// 删除已漂移的规则后，如果重建发生瞬时失败，必须像启动路径一样立即重试，
	// 不能让节点在下一个协调周期前一直缺少探针 SNAT 规则。
	cfg := constructTestConfig()
	ext := &hostStateStub{saveOutput: driftedHostState, restoreFailures: 1}
	iptConfigurator, _, err := NewIptablesConfigurator(cfg, cfg, ext, ext, EmptyNlDeps())
	assert.NoError(t, err)

	repaired, err := iptConfigurator.EnsureHostRules()
	assert.NoError(t, err)
	assert.Equal(t, true, repaired)

	// 第一次恢复失败，因此恢复内容必须至少重发两次。
	snatAttempts := 0
	for _, line := range ext.ExecutedStdin {
		if strings.Contains(line, "-j SNAT --to-source 169.254.7.127") {
			snatAttempts++
		}
	}
	if snatAttempts < 2 {
		t.Fatalf("expected the repair to be retried after a failed restore, got %d restore attempts:\n%v",
			snatAttempts, strings.Join(ext.ExecutedStdin, "\n"))
	}
}

func TestEnsureHostRulesRepairsMissingCheckedRule(t *testing.T) {
	// 链和规则数量看似正确，但逐条执行 -C 检查失败，例如 POSTROUTING 跳转规则
	// 被外部删除并替换为其他规则；此情况也必须触发修复。
	cfg := constructTestConfig()
	ext := &hostStateStub{saveOutput: convergedHostState, checkFails: true}
	iptConfigurator, _, err := NewIptablesConfigurator(cfg, cfg, ext, ext, EmptyNlDeps())
	assert.NoError(t, err)

	repaired, err := iptConfigurator.EnsureHostRules()
	assert.NoError(t, err)
	assert.Equal(t, true, repaired)
}
