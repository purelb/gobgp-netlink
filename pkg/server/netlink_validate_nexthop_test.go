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

package server

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/osrg/gobgp/v4/api"
)

// validate_nexthop documents itself as defaulting to true, and the config file
// delivers that - the config model spells it skip-nexthop-validation and
// inverts, so a TOML user who says nothing gets validation on.
//
// The API said nothing and got it off. It was a plain proto3 bool, so an
// omitted field and an explicit false were the same value, and the converter
// read that as "skip". A client following the documented default therefore
// exported routes to the kernel without checking the nexthop was reachable.
func TestNetlinkValidateNexthopDefaultsToOn(t *testing.T) {
	setRule := func(t *testing.T, validate *bool) bool {
		t.Helper()
		s := newPanicTestServer(t)
		ctx := context.Background()
		require.NoError(t, s.EnableNetlinkExport(ctx, &api.EnableNetlinkExportRequest{
			Rules: []*api.NetlinkExportRuleConfig{{
				Name:            "r1",
				TableId:         254,
				ValidateNexthop: validate,
			}},
		}))

		rsp, err := s.ListNetlinkExportRules(ctx, &api.ListNetlinkExportRulesRequest{})
		require.NoError(t, err)
		for _, er := range rsp.GetRules() {
			if er.GetName() == "r1" {
				return er.GetValidateNexthop()
			}
		}
		t.Fatal("the rule was not reported back")
		return false
	}

	t.Run("omitted means validate", func(t *testing.T) {
		assert.True(t, setRule(t, nil),
			"a client that says nothing must get the documented default, not its opposite")
	})

	t.Run("explicit true means validate", func(t *testing.T) {
		assert.True(t, setRule(t, proto.Bool(true)))
	})

	t.Run("explicit false turns it off", func(t *testing.T) {
		assert.False(t, setRule(t, proto.Bool(false)),
			"opting out must still work; presence is what makes it expressible")
	})
}
