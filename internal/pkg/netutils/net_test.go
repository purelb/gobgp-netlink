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

package netutils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExpandInterfacePatternsLiteralsPassThrough(t *testing.T) {
	// Literal names must survive untouched even when they do not exist on the
	// host: the caller reports "failed to find interface X", which is the
	// behaviour operators have always seen. This is the path PureLB uses
	// ("kube-lb0"), so it must not regress.
	// Configured order is preserved for literals.
	got, err := ExpandInterfacePatterns([]string{"kube-lb0", "definitely-not-here"}, nil)
	assert.NoError(t, err)
	assert.Equal(t, []string{"kube-lb0", "definitely-not-here"}, got)
}

func TestExpandInterfacePatternsLiteralsComeFirst(t *testing.T) {
	// Literals keep configured order and precede glob matches, so mixing a glob
	// into the list cannot reorder the interfaces an operator named explicitly.
	got, err := ExpandInterfacePatterns([]string{"zzz-literal-b", "l*", "zzz-literal-a"}, nil)
	assert.NoError(t, err)
	assert.Equal(t, "zzz-literal-b", got[0])
	assert.Equal(t, "zzz-literal-a", got[1])
	assert.Contains(t, got[2:], "lo")
}

func TestExpandInterfacePatternsMatchesLoopback(t *testing.T) {
	// "lo" is the one interface we can rely on existing in any environment the
	// unit tests run in, including a CI container.
	got, err := ExpandInterfacePatterns([]string{"l*"}, nil)
	assert.NoError(t, err)
	assert.Contains(t, got, "lo")
}

func TestExpandInterfacePatternsNoMatchIsNotAnError(t *testing.T) {
	// A glob matching nothing is legitimate - the interface may appear later.
	// It must not fail the whole import scan.
	got, err := ExpandInterfacePatterns([]string{"zzz-no-such-iface*"}, nil)
	assert.NoError(t, err)
	assert.Empty(t, got)
}

func TestExpandInterfacePatternsDeduplicatesAndSorts(t *testing.T) {
	// Two patterns matching the same device must yield one entry, so the
	// interface is scanned once.
	got, err := ExpandInterfacePatterns([]string{"lo", "l*", "lo"}, nil)
	assert.NoError(t, err)

	seen := 0
	for _, name := range got {
		if name == "lo" {
			seen++
		}
	}
	assert.Equal(t, 1, seen, "lo should appear exactly once, got %v", got)
}

func TestExpandInterfacePatternsRejectsMalformedPattern(t *testing.T) {
	// An unterminated character class must be reported, not silently treated as
	// "matches nothing" - that would import no routes with no explanation.
	_, err := ExpandInterfacePatterns([]string{"eth[0-"}, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid interface pattern")
}

func TestExpandInterfacePatternsEmpty(t *testing.T) {
	got, err := ExpandInterfacePatterns(nil, nil)
	assert.NoError(t, err)
	assert.Empty(t, got)
}
