// Copyright (C) 2014-2021 Nippon Telegraph and Telephone Corporation.
// Copyright (C) 2025 Acnodal Inc.
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

package oc

import (
	"log/slog"

	"github.com/fsnotify/fsnotify"
	"github.com/go-viper/mapstructure/v2"
	"github.com/spf13/viper"
)

type BgpConfigSet struct {
	Global            Global             `mapstructure:"global"`
	Neighbors         []Neighbor         `mapstructure:"neighbors"`
	PeerGroups        []PeerGroup        `mapstructure:"peer-groups"`
	RpkiServers       []RpkiServer       `mapstructure:"rpki-servers"`
	BmpServers        []BmpServer        `mapstructure:"bmp-servers"`
	Vrfs              []Vrf              `mapstructure:"vrfs"`
	MrtDump           []Mrt              `mapstructure:"mrt-dump"`
	Zebra             Zebra              `mapstructure:"zebra"`
	Netlink           Netlink            `mapstructure:"netlink"`
	Collector         Collector          `mapstructure:"collector"`
	DefinedSets       DefinedSets        `mapstructure:"defined-sets"`
	PolicyDefinitions []PolicyDefinition `mapstructure:"policy-definitions"`
	DynamicNeighbors  []DynamicNeighbor  `mapstructure:"dynamic-neighbors"`
}

func ReadConfigfile(path, format string) (*BgpConfigSet, error) {
	// Update config file type, if detectable
	format = detectConfigFileType(path, format)
	opts := viper.DecodeHook(mapstructure.ComposeDecodeHookFunc(mapstructure.StringToNetIPAddrHookFunc(), mapstructure.StringToNetIPPrefixHookFunc()))

	config := &BgpConfigSet{}
	v := viper.New()
	v.SetConfigFile(path)
	v.SetConfigType(format)
	var err error
	if err = v.ReadInConfig(); err != nil {
		return nil, err
	}
	if err = v.UnmarshalExact(config, opts); err != nil {
		return nil, err
	}
	if err = setDefaultConfigValuesWithViper(v, config); err != nil {
		return nil, err
	}
	return config, nil
}

func WatchConfigFile(path, format string, callBack func()) {
	v := viper.New()
	v.SetConfigFile(path)
	v.SetConfigType(format)

	v.OnConfigChange(func(e fsnotify.Event) {
		callBack()
	})

	v.WatchConfig()
}

func ConfigSetToRoutingPolicy(c *BgpConfigSet) *RoutingPolicy {
	return &RoutingPolicy{
		DefinedSets:       c.DefinedSets,
		PolicyDefinitions: c.PolicyDefinitions,
	}
}

func UpdatePeerGroupConfig(logger *slog.Logger, curC, newC *BgpConfigSet) ([]PeerGroup, []PeerGroup, []PeerGroup) {
	addedPg := []PeerGroup{}
	deletedPg := []PeerGroup{}
	updatedPg := []PeerGroup{}

	for _, n := range newC.PeerGroups {
		if idx := existPeerGroup(n.Config.PeerGroupName, curC.PeerGroups); idx < 0 {
			addedPg = append(addedPg, n)
		} else if !n.Equal(&curC.PeerGroups[idx]) {
			logger.Debug("Current peer-group config", slog.String("Topic", "Config"), slog.Any("Key", n))
			updatedPg = append(updatedPg, n)
		}
	}

	for _, n := range curC.PeerGroups {
		if existPeerGroup(n.Config.PeerGroupName, newC.PeerGroups) < 0 {
			deletedPg = append(deletedPg, n)
		}
	}
	return addedPg, deletedPg, updatedPg
}

// UpdateVrfConfig reports which VRFs were added, deleted, or structurally
// changed between two configurations.
//
// "Updated" means the identity fields changed - RD, route targets, id. Those
// cannot be applied in place, because AddVrf refuses a name that already
// exists, so the caller has to delete and re-add, which moves every route in
// the VRF.
//
// A VRF whose netlink-import or netlink-export block changed is deliberately
// NOT reported here. Vrf.Equal covers those too, and treating them as an update
// would tear down and rebuild a VRF over a changed metric. They are applied
// separately by StartNetlinkWithConfig, which does not disturb routing.
func UpdateVrfConfig(logger *slog.Logger, curC, newC *BgpConfigSet) ([]Vrf, []Vrf, []Vrf) {
	added := []Vrf{}
	deleted := []Vrf{}
	updated := []Vrf{}

	for _, v := range newC.Vrfs {
		idx := inVrfSlice(v, curC.Vrfs)
		if idx < 0 {
			added = append(added, v)
			continue
		}
		if !v.Config.Equal(&curC.Vrfs[idx].Config) {
			logger.Debug("Current vrf config", slog.String("Topic", "Config"), slog.Any("Key", curC.Vrfs[idx].Config))
			logger.Debug("New vrf config", slog.String("Topic", "Config"), slog.Any("Key", v.Config))
			updated = append(updated, v)
		}
	}

	for _, v := range curC.Vrfs {
		if inVrfSlice(v, newC.Vrfs) < 0 {
			deleted = append(deleted, v)
		}
	}
	return added, deleted, updated
}

func UpdateNeighborConfig(logger *slog.Logger, curC, newC *BgpConfigSet) ([]Neighbor, []Neighbor, []Neighbor) {
	added := []Neighbor{}
	deleted := []Neighbor{}
	updated := []Neighbor{}

	for _, n := range newC.Neighbors {
		if idx := inSlice(n, curC.Neighbors); idx < 0 {
			added = append(added, n)
		} else if !n.Equal(&curC.Neighbors[idx]) {
			logger.Debug("Current neighbor config", slog.String("Topic", "Config"), slog.Any("Key", curC.Neighbors[idx]))
			logger.Debug("New neighbor config", slog.String("Topic", "Config"), slog.Any("Key", n))
			updated = append(updated, n)
		}
	}

	for _, n := range curC.Neighbors {
		if inSlice(n, newC.Neighbors) < 0 {
			deleted = append(deleted, n)
		}
	}
	return added, deleted, updated
}

func CheckPolicyDifference(logger *slog.Logger, currentPolicy *RoutingPolicy, newPolicy *RoutingPolicy) bool {
	logger.Debug("Current policy", slog.String("Topic", "Config"), slog.Any("Key", currentPolicy))
	logger.Debug("New policy", slog.String("Topic", "Config"), slog.Any("Key", newPolicy))

	var result bool
	if currentPolicy == nil && newPolicy == nil {
		result = false
	} else {
		if currentPolicy != nil && newPolicy != nil {
			result = !currentPolicy.Equal(newPolicy)
		} else {
			result = true
		}
	}
	return result
}
