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
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
)

var testDesc = prometheus.NewDesc("test_metric", "counts collections", nil, nil)

// countingCollector reports how many times it has been collected, both as the
// metric value and as a counter the test can read directly.
type countingCollector struct {
	collections atomic.Int64
	block       chan struct{} // if non-nil, Collect waits on it
}

func (c *countingCollector) Describe(out chan<- *prometheus.Desc) { out <- testDesc }

func (c *countingCollector) Collect(out chan<- prometheus.Metric) {
	if c.block != nil {
		<-c.block
	}
	n := c.collections.Add(1)
	out <- prometheus.MustNewConstMetric(testDesc, prometheus.GaugeValue, float64(n))
}

func collectCount(t *testing.T, c prometheus.Collector) int {
	t.Helper()
	return len(drain(c))
}

// The property the BGP write lock depends on: however often it is scraped, the
// collector underneath runs once per interval.
func Test_CachingCollector_RunsInnerOncePerInterval(t *testing.T) {
	assert := assert.New(t)

	inner := &countingCollector{}
	clock := time.Now()
	c := &cachingCollector{inner: inner, interval: 15 * time.Second, now: func() time.Time { return clock }}

	for range 50 {
		assert.Equal(1, collectCount(t, c), "every scrape still yields the full metric set")
	}
	assert.Equal(int64(1), inner.collections.Load(), "50 scrapes inside one interval collect once")

	clock = clock.Add(15 * time.Second)
	assert.Equal(1, collectCount(t, c))
	assert.Equal(int64(2), inner.collections.Load(), "the interval elapsing collects again")

	clock = clock.Add(14 * time.Second)
	assert.Equal(1, collectCount(t, c))
	assert.Equal(int64(2), inner.collections.Load(), "still inside the second interval")
}

// Concurrent scrapes must not each start a pass over the RIB. They wait for
// the one in flight and replay its result - the case promhttp's
// MaxRequestsInFlight does not cover, since it rejects rather than coalesces
// and says nothing about a single client scraping in a loop.
func Test_CachingCollector_ConcurrentScrapesCollectOnce(t *testing.T) {
	assert := assert.New(t)

	inner := &countingCollector{block: make(chan struct{})}
	c := NewCachingCollector(inner, time.Minute)

	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			drain(c)
		}()
	}

	// Let them all pile up on the mutex before the first collection finishes.
	time.Sleep(50 * time.Millisecond)
	close(inner.block)
	wg.Wait()

	assert.Equal(int64(1), inner.collections.Load(),
		"20 concurrent scrapes must collect once, not 20 times")
}

// Replay has to be a real replay: the same values, not an empty set.
func Test_CachingCollector_ReplaysTheSameValues(t *testing.T) {
	assert := assert.New(t)

	inner := &countingCollector{}
	clock := time.Now()
	c := &cachingCollector{inner: inner, interval: time.Minute, now: func() time.Time { return clock }}

	first := drain(c)
	second := drain(c)

	assert.Len(first, 1)
	assert.Len(second, 1)
	assert.Equal(int64(1), inner.collections.Load())

	var a, b dto.Metric
	assert.NoError(first[0].Write(&a))
	assert.NoError(second[0].Write(&b))
	assert.Equal(a.GetGauge().GetValue(), b.GetGauge().GetValue())
}

// A zero interval is the escape hatch and must not cache at all.
func Test_CachingCollector_ZeroIntervalDisablesCaching(t *testing.T) {
	assert := assert.New(t)

	inner := &countingCollector{}
	c := NewCachingCollector(inner, 0)
	assert.Same(inner, c, "no wrapper at all, so there is nothing to go stale")

	drain(c)
	drain(c)
	assert.Equal(int64(2), inner.collections.Load())
}
