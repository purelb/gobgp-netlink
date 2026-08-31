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

	"github.com/osrg/gobgp/v4/pkg/server"
)

// The netlink subsystem programs the node's kernel FIB, and until now had no
// Prometheus surface at all: its counters were process-local and reachable only
// through the CLI. Several of these exist specifically so an operator can
// confirm a fix landed on a real node rather than inferring it from silence.
var (
	netlinkImportEnabledDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "netlink", "import_enabled"),
		"Whether netlink route import (kernel to BGP) is active.", nil, nil)
	netlinkImportedTotalDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "netlink", "imported_total"),
		"Routes imported from the kernel into the BGP RIB.", nil, nil)
	netlinkImportWithdrawnTotalDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "netlink", "import_withdrawn_total"),
		"Imported routes withdrawn from the BGP RIB.", nil, nil)
	netlinkImportErrorsTotalDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "netlink", "import_errors_total"),
		"Errors encountered while importing kernel routes.", nil, nil)
	netlinkImportLoopTicksTotalDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "netlink", "import_loop_ticks_total"),
		"Import scan iterations. Stops advancing once the scan loop exits, so a "+
			"flat value after shutdown confirms the loop actually stopped.", nil, nil)

	netlinkExportEnabledDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "netlink", "export_enabled"),
		"Whether netlink route export (BGP to kernel) is active.", nil, nil)
	netlinkExportedTotalDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "netlink", "exported_total"),
		"Routes programmed into the kernel FIB.", nil, nil)
	netlinkExportWithdrawnTotalDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "netlink", "export_withdrawn_total"),
		"Routes removed from the kernel FIB.", nil, nil)
	netlinkExportErrorsTotalDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "netlink", "export_errors_total"),
		"Errors encountered while programming the kernel FIB.", nil, nil)
	netlinkNexthopValidationTotalDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "netlink", "nexthop_validation_total"),
		"Nexthop reachability checks attempted before export.", nil, nil)
	netlinkNexthopFailedTotalDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "netlink", "nexthop_failed_total"),
		"Nexthop reachability checks that failed, suppressing an export.", nil, nil)
	netlinkDampenedUpdatesTotalDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "netlink", "dampened_updates_total"),
		"Route updates deferred by export dampening.", nil, nil)
	netlinkCleanupDeletedTotalDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "netlink", "cleanup_routes_deleted_total"),
		"Stale routes deleted by the startup sweep.", nil, nil)
	netlinkCleanupSkippedTotalDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "netlink", "cleanup_routes_skipped_total"),
		"Routes the startup sweep examined and deliberately left in place. "+
			"Non-zero on first boot after upgrade is the evidence that the sweep "+
			"is scoped rather than silently doing nothing.", nil, nil)
)

type netlinkCollector struct {
	server *server.BgpServer
}

// NewNetlinkCollector exposes the netlink import/export counters to Prometheus.
func NewNetlinkCollector(s *server.BgpServer) prometheus.Collector {
	return &netlinkCollector{server: s}
}

func (c *netlinkCollector) Describe(out chan<- *prometheus.Desc) {
	out <- netlinkImportEnabledDesc
	out <- netlinkImportedTotalDesc
	out <- netlinkImportWithdrawnTotalDesc
	out <- netlinkImportErrorsTotalDesc
	out <- netlinkImportLoopTicksTotalDesc

	out <- netlinkExportEnabledDesc
	out <- netlinkExportedTotalDesc
	out <- netlinkExportWithdrawnTotalDesc
	out <- netlinkExportErrorsTotalDesc
	out <- netlinkNexthopValidationTotalDesc
	out <- netlinkNexthopFailedTotalDesc
	out <- netlinkDampenedUpdatesTotalDesc
	out <- netlinkCleanupDeletedTotalDesc
	out <- netlinkCleanupSkippedTotalDesc
}

func (c *netlinkCollector) Collect(out chan<- prometheus.Metric) {
	s := c.server.NetlinkStats()

	gauge := func(d *prometheus.Desc, b bool) {
		v := 0.0
		if b {
			v = 1.0
		}
		out <- prometheus.MustNewConstMetric(d, prometheus.GaugeValue, v)
	}
	counter := func(d *prometheus.Desc, v uint64) {
		out <- prometheus.MustNewConstMetric(d, prometheus.CounterValue, float64(v))
	}

	gauge(netlinkImportEnabledDesc, s.ImportEnabled)
	counter(netlinkImportedTotalDesc, s.ImportImported)
	counter(netlinkImportWithdrawnTotalDesc, s.ImportWithdrawn)
	counter(netlinkImportErrorsTotalDesc, s.ImportErrors)
	counter(netlinkImportLoopTicksTotalDesc, s.ImportTicks)

	gauge(netlinkExportEnabledDesc, s.ExportEnabled)
	counter(netlinkExportedTotalDesc, s.ExportExported)
	counter(netlinkExportWithdrawnTotalDesc, s.ExportWithdrawn)
	counter(netlinkExportErrorsTotalDesc, s.ExportErrors)
	counter(netlinkNexthopValidationTotalDesc, s.ExportNexthopValidation)
	counter(netlinkNexthopFailedTotalDesc, s.ExportNexthopFailed)
	counter(netlinkDampenedUpdatesTotalDesc, s.ExportDampenedUpdates)
	counter(netlinkCleanupDeletedTotalDesc, s.ExportCleanupDeleted)
	counter(netlinkCleanupSkippedTotalDesc, s.ExportCleanupSkipped)
}
