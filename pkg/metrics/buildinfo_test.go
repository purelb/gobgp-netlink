// Copyright (C) 2026 Acnodal Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package metrics

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"

	"github.com/osrg/gobgp/v4/internal/pkg/version"
)

// TestBuildInfoIsScrapable is the point of the collector: the running binary's
// identity has to be reachable from a scrape, not just from --version. Without
// this an operator cannot answer "which build is on that node" from monitoring,
// which is exactly the question a staged rollout asks.
func TestBuildInfoIsScrapable(t *testing.T) {
	registry := prometheus.NewRegistry()
	registry.MustRegister(NewBuildInfoCollector())

	out, err := registry.Gather()
	assert.NoError(t, err)
	assert.Len(t, out, 1)
	assert.Equal(t, "bgp_build_info", out[0].GetName())

	labels := map[string]string{}
	for _, l := range out[0].GetMetric()[0].GetLabel() {
		labels[l.GetName()] = l.GetValue()
	}
	assert.Equal(t, version.ShortVersion(), labels["version"])
	assert.Equal(t, version.BaseVersion(), labels["base"])
	assert.Contains(t, labels, "commit", "commit label must exist even when unstamped")
	assert.True(t, strings.HasPrefix(labels["base"], "gobgp-"))
	assert.Equal(t, 1.0, out[0].GetMetric()[0].GetGauge().GetValue())
}
