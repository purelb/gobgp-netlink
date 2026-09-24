package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"

	"github.com/BurntSushi/toml"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
)

func main() {
	out, err := example()
	if err != nil {
		panic(err)
	}
	fmt.Printf("%v\n", out)
}

// example is the example configuration as TOML.
//
// The model's structs name their config keys only in mapstructure and json
// tags, and the TOML encoder reads neither, so encoding the structs directly
// printed Go field names - "RouterId" for "router-id" - and gobgpd refused the
// file. The json tags match the loader's mapstructure names, so the structs go
// through JSON first.
func example() (string, error) {
	var buffer bytes.Buffer
	encoder := toml.NewEncoder(&buffer)
	for _, v := range []any{bgp(), policy()} {
		tree, err := configTree(v)
		if err != nil {
			return "", err
		}
		if err := encoder.Encode(tree); err != nil {
			return "", err
		}
	}
	return buffer.String(), nil
}

// configTree is v as the tree of keys a config file holds.
func configTree(v any) (map[string]any, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var tree map[string]any
	if err := d.Decode(&tree); err != nil {
		return nil, err
	}
	pruned, _ := prune(tree).(map[string]any)
	return pruned, nil
}

// prune drops what JSON writes for a setting left unset - omitempty does not
// apply to structs, so an unset block is {} and an unset address "", which the
// loader cannot parse - and turns JSON numbers back into integers rather than
// floats.
func prune(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, e := range t {
			if p := prune(e); p != nil && p != "" {
				out[k] = p
			}
		}
		if len(out) == 0 {
			return nil
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = prune(e)
		}
		return out
	case json.Number:
		if i, err := t.Int64(); err == nil {
			return i
		}
		f, _ := t.Float64()
		return f
	}
	return v
}

func bgp() oc.Bgp {
	return oc.Bgp{
		Global: oc.Global{
			Config: oc.GlobalConfig{
				As:       12332,
				RouterId: netip.MustParseAddr("10.0.0.1"),
			},
			// Global, not on the neighbor: per-peer policy applies only to
			// route-server clients, and gobgpd refuses it on any other peer.
			ApplyPolicy: oc.ApplyPolicy{
				Config: oc.ApplyPolicyConfig{
					ImportPolicyList:    []string{"pd1"},
					DefaultImportPolicy: oc.DEFAULT_POLICY_TYPE_ACCEPT_ROUTE,
				},
			},
		},
		Neighbors: []oc.Neighbor{
			{
				Config: oc.NeighborConfig{
					PeerAs:          12333,
					AuthPassword:    "apple",
					NeighborAddress: netip.MustParseAddr("192.168.177.33"),
				},
				AfiSafis: []oc.AfiSafi{
					{
						Config: oc.AfiSafiConfig{
							AfiSafiName: "ipv4-unicast",
						},
					},
					{
						Config: oc.AfiSafiConfig{
							AfiSafiName: "ipv6-unicast",
						},
					},
				},
			},

			{
				Config: oc.NeighborConfig{
					PeerAs:          12334,
					AuthPassword:    "orange",
					NeighborAddress: netip.MustParseAddr("192.168.177.32"),
				},
			},

			{
				Config: oc.NeighborConfig{
					PeerAs:          12335,
					AuthPassword:    "grape",
					NeighborAddress: netip.MustParseAddr("192.168.177.34"),
				},
			},
		},
	}
}

func policy() oc.RoutingPolicy {
	ps := oc.PrefixSet{
		PrefixSetName: "ps1",
		PrefixList: []oc.Prefix{
			{
				IpPrefix:        netip.MustParsePrefix("10.3.192.0/21"),
				MasklengthRange: "21..24",
			},
		},
	}

	rps := oc.PrefixSet{
		PrefixSetName: "rtc1",
		PrefixList: []oc.Prefix{
			// /96: full NLRI (origin-AS + Route Target).
			{
				RtcPrefix:       "65000:65000:100/96",
				MasklengthRange: "96..96",
			},
			// /32: origin-AS only; Route Target is outside the prefix, use 0.
			{
				RtcPrefix:       "65000:0:0/32",
				MasklengthRange: "32..96",
			},
			// /64: origin-AS + 2-octet-AS Route Target AS (local-admin ignored).
			{
				RtcPrefix:       "65000:65000:0/64",
				MasklengthRange: "64..96",
			},
			// /80: + 4-octet/IPv4 Route Target AS (local-admin ignored).
			{
				RtcPrefix:       "65000:100.1000:0/80",
				MasklengthRange: "80..96",
			},
		},
	}

	ns := oc.NeighborSet{
		NeighborSetName:  "ns1",
		NeighborInfoList: []string{"10.0.0.2"},
	}

	cs := oc.CommunitySet{
		CommunitySetName: "community1",
		CommunityList:    []string{"65100:10"},
	}

	ecs := oc.ExtCommunitySet{
		ExtCommunitySetName: "ecommunity1",
		ExtCommunityList:    []string{"RT:65001:200"},
	}

	as := oc.AsPathSet{
		AsPathSetName: "aspath1",
		AsPathList:    []string{"^65100"},
	}

	bds := oc.BgpDefinedSets{
		CommunitySets:    []oc.CommunitySet{cs},
		ExtCommunitySets: []oc.ExtCommunitySet{ecs},
		AsPathSets:       []oc.AsPathSet{as},
	}

	ds := oc.DefinedSets{
		PrefixSets:     []oc.PrefixSet{ps, rps},
		NeighborSets:   []oc.NeighborSet{ns},
		BgpDefinedSets: bds,
	}

	al := oc.AsPathLength{
		Operator: "eq",
		Value:    2,
	}

	s := oc.Statement{
		Name: "statement1",
		Conditions: oc.Conditions{
			MatchPrefixSet: oc.MatchPrefixSet{
				PrefixSet:       "ps1",
				MatchSetOptions: oc.MATCH_SET_OPTIONS_RESTRICTED_TYPE_ANY,
			},

			MatchNeighborSet: oc.MatchNeighborSet{
				NeighborSet:     "ns1",
				MatchSetOptions: oc.MATCH_SET_OPTIONS_RESTRICTED_TYPE_ANY,
			},

			BgpConditions: oc.BgpConditions{
				MatchCommunitySet: oc.MatchCommunitySet{
					CommunitySet:    "community1",
					MatchSetOptions: oc.MATCH_SET_OPTIONS_TYPE_ANY,
				},

				MatchExtCommunitySet: oc.MatchExtCommunitySet{
					ExtCommunitySet: "ecommunity1",
					MatchSetOptions: oc.MATCH_SET_OPTIONS_TYPE_ANY,
				},

				MatchAsPathSet: oc.MatchAsPathSet{
					AsPathSet:       "aspath1",
					MatchSetOptions: oc.MATCH_SET_OPTIONS_TYPE_ANY,
				},
				AsPathLength: al,
			},
		},
		Actions: oc.Actions{
			RouteDisposition: "reject-route",
			BgpActions: oc.BgpActions{
				SetCommunity: oc.SetCommunity{
					SetCommunityMethod: oc.SetCommunityMethod{
						CommunitiesList: []string{"65100:20"},
					},
					Options: "ADD",
				},
				SetMed: "-200",
			},
		},
	}

	pd := oc.PolicyDefinition{
		Name:       "pd1",
		Statements: []oc.Statement{s},
	}

	p := oc.RoutingPolicy{
		DefinedSets:       ds,
		PolicyDefinitions: []oc.PolicyDefinition{pd},
	}

	return p
}
