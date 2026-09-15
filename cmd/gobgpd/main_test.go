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

package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// isLoopbackHostPort decides whether the operator gets told that an
// unauthenticated endpoint is reachable off-host, so a wrong answer is a
// warning that never fires. The wildcard forms matter most: ":6060" and
// "0.0.0.0:6060" look local and are not.
func Test_isLoopbackHostPort(t *testing.T) {
	for _, tc := range []struct {
		hostPort string
		want     bool
		why      string
	}{
		{"localhost:6060", true, "the default pprof host"},
		{"127.0.0.1:50051", true, "explicit v4 loopback"},
		{"[::1]:50051", true, "explicit v6 loopback"},
		{"127.0.0.53:53", true, "all of 127/8 is loopback, not just .1"},

		{":6060", false, "empty host is the wildcard, which is every interface"},
		{"0.0.0.0:7475", false, "wildcard spelled out"},
		{"[::]:7475", false, "v6 wildcard"},
		{"192.168.1.10:7475", false, "a node address is what hostNetwork exposes"},

		{"", false, "unparseable must not read as loopback"},
		{"localhost", false, "no port, so not a bind address"},
		{"not a host:7475", false, "unresolvable must not read as loopback"},
	} {
		if got := isLoopbackHostPort(tc.hostPort); got != tc.want {
			t.Errorf("isLoopbackHostPort(%q) = %v, want %v (%s)", tc.hostPort, got, tc.want, tc.why)
		}
	}
}

// blockingGatherer holds a gather open until released, standing in for a
// collection that is slow because it is walking the RIB under the BGP lock.
type blockingGatherer struct {
	release chan struct{}
	entered chan struct{}
	once    sync.Once
}

func (b *blockingGatherer) Gather() ([]*dto.MetricFamily, error) {
	b.once.Do(func() { close(b.entered) })
	<-b.release
	return nil, nil
}

// Surplus scrapes must be shed immediately, not queued. Queuing is what makes
// the endpoint a way to stall BGP: every scrape holds the write lock, and Go's
// RWMutex parks new readers behind a waiting writer, so a backlog compounds.
func Test_metricsHandler_ShedsSurplusScrapes(t *testing.T) {
	g := &blockingGatherer{release: make(chan struct{}), entered: make(chan struct{})}
	h := metricsHandlerFor(g, nil)

	go func() {
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/metrics", nil))
	}()
	<-g.entered // the single in-flight slot is now taken

	second := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.ServeHTTP(second, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("the second scrape queued behind the first instead of being rejected")
	}
	close(g.release)

	if second.Code != http.StatusServiceUnavailable {
		t.Errorf("second scrape returned %d, want %d", second.Code, http.StatusServiceUnavailable)
	}
}

// One failing collector must not blank the others. bgpCollector reports a
// collection failure as a prometheus.NewInvalidMetric, and the default
// HTTPErrorOnError turns that into a 500 with no body - so a transient error
// on one BGP peer would take the netlink and BFD families down with it, even
// though those are read from lock-free counters and were fine.
func Test_metricsHandler_KeepsGoodFamiliesWhenOneCollectorFails(t *testing.T) {
	reg := prometheus.NewRegistry()
	reg.MustRegister(&countingCollector{})
	reg.MustRegister(&failingCollector{})

	rec := httptest.NewRecorder()
	metricsHandlerFor(reg, nil).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("got %d, want 200: one bad collector must not blank the scrape", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "healthy_metric") {
		t.Errorf("the healthy family is missing from the response:\n%s", rec.Body.String())
	}
}

var healthyDesc = prometheus.NewDesc("healthy_metric", "collected fine", nil, nil)

type countingCollector struct{}

func (c *countingCollector) Describe(out chan<- *prometheus.Desc) { out <- healthyDesc }
func (c *countingCollector) Collect(out chan<- prometheus.Metric) {
	out <- prometheus.MustNewConstMetric(healthyDesc, prometheus.GaugeValue, 1)
}

var brokenDesc = prometheus.NewDesc("broken_metric", "fails to collect", nil, nil)

type failingCollector struct{}

func (c *failingCollector) Describe(out chan<- *prometheus.Desc) { out <- brokenDesc }
func (c *failingCollector) Collect(out chan<- prometheus.Metric) {
	out <- prometheus.NewInvalidMetric(brokenDesc, errors.New("peer unreachable"))
}
