package main

import (
	"strings"
	"testing"

	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The example gobgpd could not read went unnoticed because nothing ever loaded
// it. This loads it the way gobgpd does, and checks it says what it was built
// to say rather than merely parsing.
func TestExampleLoads(t *testing.T) {
	out, err := example()
	require.NoError(t, err)

	c, err := oc.ReadConfig(strings.NewReader(out), "toml")
	require.NoError(t, err)

	assert.Equal(t, uint32(12332), c.Global.Config.As)
	assert.Equal(t, "10.0.0.1", c.Global.Config.RouterId.String())
	assert.Equal(t, []string{"pd1"}, c.Global.ApplyPolicy.Config.ImportPolicyList)
	require.Len(t, c.Neighbors, 3)
	assert.Equal(t, "192.168.177.33", c.Neighbors[0].Config.NeighborAddress.String())
	assert.Len(t, c.Neighbors[0].AfiSafis, 2)
	assert.Len(t, c.DefinedSets.PrefixSets, 2)
	require.Len(t, c.PolicyDefinitions, 1)
	assert.Equal(t, "ecommunity1",
		c.PolicyDefinitions[0].Statements[0].Conditions.BgpConditions.MatchExtCommunitySet.ExtCommunitySet)

	// An example is read by people: integers, not the floats JSON decodes to.
	assert.Contains(t, out, "as = 12332\n")
}
