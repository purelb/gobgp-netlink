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
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// cachingCollector runs the collector underneath it at most once per interval
// and replays the last result in between.
//
// This exists for one collector in particular. bgpCollector.Collect calls
// ListPeer, which runs as a mgmtOperation, and BgpServer.Serve holds the BGP
// *write* lock for the whole of it - so BGP message processing stops for the
// duration of every scrape. promhttp's MaxRequestsInFlight bounds how many
// scrapes run at once, but not what fraction of the time one is running: a
// single client looping request/response/request keeps the lock busy
// continuously, because mgmtCh is unbuffered and the next operation is already
// queued when the previous one releases it. Go's RWMutex also parks new readers
// behind a waiting writer, so the FSM is starved even in the gaps.
//
// A timeout cannot fix that. promhttp's Timeout is an http.TimeoutHandler,
// which gives up on the response but cannot stop the collection underneath it,
// and there is nowhere to plumb a context to: prometheus.Collector.Collect
// takes none, so the collector has to pass context.Background() to ListPeer,
// and mgmtOperation does not take one either.
//
// Bounding how *often* the expensive path runs is what is left, and it is
// enough: the write lock is held for at most T/interval of the time regardless
// of scrape rate or how many clients are scraping.
//
// The cost is staleness. Replayed metrics carry no timestamp of their own, so
// Prometheus stamps them at scrape time and a value can be up to one interval
// older than it appears. Keep the interval at or below the scrape interval and
// nothing is lost; that is the intended configuration.
type cachingCollector struct {
	inner    prometheus.Collector
	interval time.Duration
	now      func() time.Time // overridden in tests

	mu      sync.Mutex
	cached  []prometheus.Metric
	fetched time.Time
	valid   bool
}

// NewCachingCollector wraps a collector so it is run at most once per interval.
// An interval of zero or less disables caching and passes every collection
// straight through.
func NewCachingCollector(inner prometheus.Collector, interval time.Duration) prometheus.Collector {
	if interval <= 0 {
		return inner
	}
	return &cachingCollector{inner: inner, interval: interval, now: time.Now}
}

func (c *cachingCollector) Describe(out chan<- *prometheus.Desc) {
	c.inner.Describe(out)
}

func (c *cachingCollector) Collect(out chan<- prometheus.Metric) {
	// Held across the inner collection deliberately. Concurrent scrapes that
	// arrive while one is running wait for it and then replay its result,
	// rather than starting a second pass over the RIB behind the BGP lock.
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.valid || c.now().Sub(c.fetched) >= c.interval {
		c.cached = drain(c.inner)
		c.fetched = c.now()
		c.valid = true
	}

	// prometheus.Metric values are immutable once constructed, so handing the
	// same ones out again is safe.
	for _, m := range c.cached {
		out <- m
	}
}

// drain runs a collector and gathers everything it emits into a slice.
func drain(inner prometheus.Collector) []prometheus.Metric {
	ch := make(chan prometheus.Metric)
	done := make(chan []prometheus.Metric, 1)

	go func() {
		collected := make([]prometheus.Metric, 0, 64)
		for m := range ch {
			collected = append(collected, m)
		}
		done <- collected
	}()

	inner.Collect(ch)
	close(ch)
	return <-done
}
