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

package nodeagent

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"

	set "istio.io/istio/cni/pkg/addressset"
	"istio.io/istio/cni/pkg/config"
	"istio.io/istio/cni/pkg/ipset"
	istiolog "istio.io/istio/pkg/log"
	"istio.io/istio/pkg/test/util/assert"
)

// fakeTrafficRuleManager 记录 EnsureHostRules/DeleteHostRules 的调用顺序，
// 用于验证主机规则协调循环的行为以及 Stop 的顺序保证。
type fakeTrafficRuleManager struct {
	mu     sync.Mutex
	events []string

	ensureCh chan struct{} // 每次调用 EnsureHostRules 时发送信号
	repaired bool
	err      error
}

func (f *fakeTrafficRuleManager) CreateInpodRules(*istiolog.Scope, config.PodLevelOverrides) error {
	return nil
}
func (f *fakeTrafficRuleManager) DeleteInpodRules(*istiolog.Scope) error { return nil }
func (f *fakeTrafficRuleManager) CreateHostRulesForHealthChecks() error  { return nil }
func (f *fakeTrafficRuleManager) ReconcileModeEnabled() bool             { return false }

func (f *fakeTrafficRuleManager) DeleteHostRules() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, "delete")
}

func (f *fakeTrafficRuleManager) EnsureHostRules() (bool, error) {
	f.mu.Lock()
	f.events = append(f.events, "ensure")
	f.mu.Unlock()
	select {
	case f.ensureCh <- struct{}{}:
	default:
	}
	return f.repaired, f.err
}

func (f *fakeTrafficRuleManager) snapshotEvents() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.events))
	copy(out, f.events)
	return out
}

func newReconcileTestDataplane(fakeTM *fakeTrafficRuleManager, interval time.Duration) *meshDataplane {
	// Stop(false) 会调用 hostAddrSet 的 Flush/DestroySet，因此使用模拟依赖。
	fakeIPSetDeps := ipset.FakeNLDeps()
	fakeIPSetDeps.On("flush", mock.Anything).Return(nil).Maybe()
	fakeIPSetDeps.On("destroySet", mock.Anything).Return(nil).Maybe()
	ipsetInstance := ipset.IPSet{V4Name: "foo-v4", Prefix: "foo", Deps: fakeIPSetDeps}

	return &meshDataplane{
		netServer:                  &fakeServer{},
		hostTrafficManager:         fakeTM,
		hostAddrSet:                set.NewIPSetWrapper(ipsetInstance),
		hostRulesReconcileInterval: interval,
	}
}

func waitForEnsureCalls(t *testing.T, fakeTM *fakeTrafficRuleManager, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		select {
		case <-fakeTM.ensureCh:
		case <-time.After(5 * time.Second):
			t.Fatalf("reconcile loop did not tick in time (got %d/%d calls)", i, n)
		}
	}
}

func TestHostRulesReconcileLoopTicksAndStops(t *testing.T) {
	fakeTM := &fakeTrafficRuleManager{ensureCh: make(chan struct{}, 64), repaired: true}
	dp := newReconcileTestDataplane(fakeTM, 5*time.Millisecond)

	dp.Start(context.Background())
	// 循环必须按照配置的间隔定期调用 EnsureHostRules。
	waitForEnsureCalls(t, fakeTM, 3)

	dp.Stop(false)

	// Stop 返回后循环必须已经退出：
	// 1. delete（清理）事件之后不得出现 ensure 事件，否则已清理的规则会被重新安装。
	events := fakeTM.snapshotEvents()
	deleteSeen := false
	for _, e := range events {
		if e == "delete" {
			deleteSeen = true
		} else if deleteSeen && e == "ensure" {
			t.Fatalf("EnsureHostRules was invoked after DeleteHostRules, cleanup would be undone: %v", events)
		}
	}
	assert.Equal(t, true, deleteSeen)

	// 2. 不再产生新的定时周期事件。
	before := len(fakeTM.snapshotEvents())
	time.Sleep(30 * time.Millisecond)
	assert.Equal(t, before, len(fakeTM.snapshotEvents()))
}

func TestHostRulesReconcileLoopToleratesErrors(t *testing.T) {
	// EnsureHostRules 持续失败时循环不得退出，必须在下一个周期重试。
	fakeTM := &fakeTrafficRuleManager{ensureCh: make(chan struct{}, 64), err: errors.New("boom")}
	dp := newReconcileTestDataplane(fakeTM, 5*time.Millisecond)

	dp.Start(context.Background())
	waitForEnsureCalls(t, fakeTM, 3)
	dp.Stop(true)
}

func TestHostRulesReconcileDisabled(t *testing.T) {
	fakeTM := &fakeTrafficRuleManager{ensureCh: make(chan struct{}, 1)}
	dp := newReconcileTestDataplane(fakeTM, 0)

	dp.Start(context.Background())
	// 间隔小于等于 0 时不得启动循环。
	assert.Equal(t, true, dp.stopHostRulesReconcile == nil)

	time.Sleep(20 * time.Millisecond)
	assert.Equal(t, 0, len(fakeTM.snapshotEvents()))

	// Stop 不得因等待从未启动的循环而阻塞。
	dp.Stop(true)
}

func TestHostRulesReconcileStopIsIdempotentWithSkipCleanup(t *testing.T) {
	// skipCleanup=true（升级场景）时仍必须先停止循环，且不得调用 DeleteHostRules。
	fakeTM := &fakeTrafficRuleManager{ensureCh: make(chan struct{}, 64)}
	dp := newReconcileTestDataplane(fakeTM, 5*time.Millisecond)

	dp.Start(context.Background())
	waitForEnsureCalls(t, fakeTM, 1)
	dp.Stop(true)

	events := fakeTM.snapshotEvents()
	for _, e := range events {
		if e == "delete" {
			t.Fatalf("DeleteHostRules must not be invoked when skipCleanup=true: %v", events)
		}
	}
	before := len(events)
	time.Sleep(30 * time.Millisecond)
	assert.Equal(t, before, len(fakeTM.snapshotEvents()))
}
