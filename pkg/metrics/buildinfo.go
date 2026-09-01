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
	"github.com/prometheus/client_golang/prometheus"

	"github.com/osrg/gobgp/v4/internal/pkg/version"
)

// The version constants are compile-time, and COMMIT is injected only by
// build.sh, so a binary built any other way reports a fork version that may be
// many commits stale. Until now the only way to ask a running daemon what it
// was built from was --version or one startup log line, neither of which a
// scrape can reach: an operator could not answer "which build is on that node"
// from monitoring alone, and the deployment's :latest tag with
// imagePullPolicy: IfNotPresent means a retag does not necessarily change it.
var buildInfoDesc = prometheus.NewDesc(
	prometheus.BuildFQName(namespace, "", "build_info"),
	"Build identity of the running daemon. Always 1; read the labels. "+
		"An empty commit label means the binary was not built by build.sh.",
	[]string{"version", "commit", "base"}, nil)

type buildInfoCollector struct{}

// NewBuildInfoCollector exposes the running binary's identity as labels.
func NewBuildInfoCollector() prometheus.Collector { return &buildInfoCollector{} }

func (c *buildInfoCollector) Describe(out chan<- *prometheus.Desc) {
	out <- buildInfoDesc
}

func (c *buildInfoCollector) Collect(out chan<- prometheus.Metric) {
	out <- prometheus.MustNewConstMetric(buildInfoDesc, prometheus.GaugeValue, 1,
		version.ShortVersion(), version.COMMIT, version.BaseVersion())
}
