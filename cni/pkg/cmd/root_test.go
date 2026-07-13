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

package cmd

import (
	"testing"
	"time"

	"istio.io/istio/pkg/test/util/assert"
)

func TestParseReconcileHostRulesInterval(t *testing.T) {
	cases := []struct {
		name     string
		raw      string
		expected time.Duration
	}{
		{"空串回退默认值", "", defaultReconcileHostRulesInterval},
		{"合法间隔", "1m30s", 90 * time.Second},
		{"零值禁用", "0", 0},
		{"零秒禁用", "0s", 0},
		{"负值禁用", "-5s", 0},
		{"非法值回退默认值", "banana", defaultReconcileHostRulesInterval},
		{"缺单位回退默认值", "30", defaultReconcileHostRulesInterval},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, parseReconcileHostRulesInterval(tt.raw))
		})
	}
}
