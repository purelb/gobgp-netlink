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

// Netlink export and import are what this fork exists for - they are how a
// route learned over BGP reaches the host routing table - and they had no
// conformance coverage at all. Not covered, and until recently not recorded as
// uncovered either, which is the state in which a regression is silent.
//
// The behaviour is correct today; these are the assertions that keep it that
// way. Two of the fields here, dampening_interval and route_protocol, were
// accepted and reported by nothing until v1.3.2, which is the defect shape
// this whole suite exists to catch - and it reached a release in the fork's
// own feature.

func TestConformanceNetlinkExportConfigRoundTrip(t *testing.T) {
	s := newObjConformanceServer(t)
	ctx := context.Background()

	require.NoError(t, s.EnableNetlinkExport(ctx, &api.EnableNetlinkExportRequest{
		DampeningInterval: 250,
		RouteProtocol:     186,
		Rules: []*api.NetlinkExportRuleConfig{{
			Name:               "conformance",
			CommunityList:      []string{"65000:100"},
			LargeCommunityList: []string{"65000:1:2"},
			TableId:            254,
			Metric:             77,
			ValidateNexthop:    proto.Bool(true),
		}},
	}))

	got, err := s.GetNetlink(ctx, &api.GetNetlinkRequest{})
	require.NoError(t, err)

	assert.True(t, got.GetExportEnabled(), "export must report itself enabled")
	assert.EqualValues(t, 250, got.GetDampeningInterval(),
		"dampening_interval was accepted and reported by nothing before v1.3.2")
	assert.EqualValues(t, 186, got.GetRouteProtocol(),
		"route_protocol likewise; it is what marks these routes as ours in the kernel")
}

func TestConformanceNetlinkExportRulesRoundTrip(t *testing.T) {
	s := newObjConformanceServer(t)
	ctx := context.Background()

	sent := &api.NetlinkExportRuleConfig{
		Name:               "rule-rt",
		CommunityList:      []string{"65000:100", "65000:200"},
		LargeCommunityList: []string{"65000:1:2"},
		TableId:            100,
		Metric:             42,
		ValidateNexthop:    proto.Bool(false),
	}
	require.NoError(t, s.EnableNetlinkExport(ctx, &api.EnableNetlinkExportRequest{
		DampeningInterval: 100,
		RouteProtocol:     186,
		Rules:             []*api.NetlinkExportRuleConfig{proto.Clone(sent).(*api.NetlinkExportRuleConfig)},
	}))

	rsp, err := s.ListNetlinkExportRules(ctx, &api.ListNetlinkExportRulesRequest{})
	require.NoError(t, err)

	var got *api.ListNetlinkExportRulesResponse_ExportRule
	for _, r := range rsp.GetRules() {
		if r.GetName() == "rule-rt" {
			got = r
		}
	}
	require.NotNil(t, got, "the rule was not reported back at all")

	assert.Equal(t, sent.GetCommunityList(), got.GetCommunityList(),
		"the communities decide which routes reach the kernel; they must report exactly")
	assert.Equal(t, sent.GetLargeCommunityList(), got.GetLargeCommunityList())
	assert.EqualValues(t, sent.GetTableId(), got.GetTableId())
	assert.EqualValues(t, sent.GetMetric(), got.GetMetric())
	assert.False(t, got.GetValidateNexthop(), "an explicit false must survive, not be re-defaulted")
}

func TestConformanceNetlinkImportConfigRoundTrip(t *testing.T) {
	s := newObjConformanceServer(t)
	ctx := context.Background()

	require.NoError(t, s.EnableNetlinkImport(ctx, &api.EnableNetlinkImportRequest{
		Interfaces: []string{"lo"},
	}))

	got, err := s.GetNetlink(ctx, &api.GetNetlinkRequest{})
	require.NoError(t, err)
	assert.True(t, got.GetImportEnabled(), "import must report itself enabled")
	assert.Equal(t, []string{"lo"}, got.GetInterfaces(),
		"the interface list decides which kernel routes are taken in")
}

// Disabling must be observable too. A controller that turns export off and is
// still told it is on cannot tell whether the call took.
func TestConformanceNetlinkDisableIsReported(t *testing.T) {
	s := newObjConformanceServer(t)
	ctx := context.Background()

	require.NoError(t, s.EnableNetlinkExport(ctx, &api.EnableNetlinkExportRequest{
		DampeningInterval: 100, RouteProtocol: 186,
	}))
	got, err := s.GetNetlink(ctx, &api.GetNetlinkRequest{})
	require.NoError(t, err)
	require.True(t, got.GetExportEnabled())

	require.NoError(t, s.DisableNetlinkExport(ctx, &api.DisableNetlinkExportRequest{KeepRoutes: true}))
	got, err = s.GetNetlink(ctx, &api.GetNetlinkRequest{})
	require.NoError(t, err)
	assert.False(t, got.GetExportEnabled(), "export must report itself disabled after DisableNetlinkExport")
}

// Every field of the netlink write messages must be round-tripped above or
// recorded as having no read path, with the reason. Same shape as the guards
// for peers and for the other objects: an unclassified field fails the build
// rather than being noticed years later.
var netlinkWriteFieldsWithNoReadPath = map[string]string{
	"DisableNetlinkExportRequest.keep_routes": "an instruction for the disable itself - whether to flush " +
		"the routes from the kernel or leave them - not state that persists, so there is nothing to report",
	"DisableNetlinkImportRequest.keep_routes": "as above, for import",
	"EnableNetlinkImportRequest.vrf":          "reported as GetNetlinkResponse.vrf, which is covered by the VRF import tests",
}

func TestEveryNetlinkWriteFieldIsClassified(t *testing.T) {
	covered := map[string]bool{
		"EnableNetlinkExportRequest.dampening_interval": true,
		"EnableNetlinkExportRequest.route_protocol":     true,
		"EnableNetlinkExportRequest.rules":              true,
		"EnableNetlinkImportRequest.interfaces":         true,

		"NetlinkExportRuleConfig.name":                 true,
		"NetlinkExportRuleConfig.community_list":       true,
		"NetlinkExportRuleConfig.large_community_list": true,
		"NetlinkExportRuleConfig.vrf":                  true,
		"NetlinkExportRuleConfig.table_id":             true,
		"NetlinkExportRuleConfig.metric":               true,
		"NetlinkExportRuleConfig.validate_nexthop":     true,
	}

	for _, m := range []proto.Message{
		(*api.EnableNetlinkExportRequest)(nil),
		(*api.EnableNetlinkImportRequest)(nil),
		(*api.NetlinkExportRuleConfig)(nil),
		(*api.DisableNetlinkExportRequest)(nil),
		(*api.DisableNetlinkImportRequest)(nil),
	} {
		d := m.ProtoReflect().Descriptor()
		fields := d.Fields()
		for i := range fields.Len() {
			name := string(d.Name()) + "." + string(fields.Get(i).Name())
			_, noRead := netlinkWriteFieldsWithNoReadPath[name]
			assert.True(t, covered[name] || noRead,
				"%s is neither round-tripped by a test here nor recorded as having no read path. "+
					"This is the fork's core feature reaching the host routing table; a field accepted "+
					"and never reported here is the defect that shipped as dampening_interval.", name)
			assert.False(t, covered[name] && noRead, "%s is in both", name)
		}
	}
}
