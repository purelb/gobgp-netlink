package config

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type ErrorCaptureHandler struct {
	mu           *sync.Mutex
	configErrors *[]string
	baseHandler  slog.Handler
}

func newErrorCaptureHandler() *ErrorCaptureHandler {
	configErrors := []string{}
	return &ErrorCaptureHandler{
		mu:           &sync.Mutex{},
		configErrors: &configErrors,
		baseHandler:  slog.NewJSONHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug}),
	}
}

func (h *ErrorCaptureHandler) Enabled(_ context.Context, level slog.Level) bool {
	return h.baseHandler.Enabled(context.Background(), level)
}

func (h *ErrorCaptureHandler) Handle(ctx context.Context, record slog.Record) error {
	if record.Level >= slog.LevelError {
		h.mu.Lock()
		*h.configErrors = append(*h.configErrors, record.Message)
		h.mu.Unlock()
	}
	return h.baseHandler.Handle(ctx, record)
}

func (h *ErrorCaptureHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &ErrorCaptureHandler{
		mu:           h.mu,
		configErrors: h.configErrors,
		baseHandler:  h.baseHandler.WithAttrs(attrs),
	}
}

func (h *ErrorCaptureHandler) WithGroup(name string) slog.Handler {
	return &ErrorCaptureHandler{
		mu:           h.mu,
		configErrors: h.configErrors,
		baseHandler:  h.baseHandler.WithGroup(name),
	}
}

func (h *ErrorCaptureHandler) Errors() []string {
	h.mu.Lock()
	defer h.mu.Unlock()

	return append([]string(nil), *h.configErrors...)
}

func newTestBgpServer(t *testing.T) (*server.BgpServer, *ErrorCaptureHandler) {
	t.Helper()

	handler := newErrorCaptureHandler()
	logger := slog.New(handler)
	bgpServer := server.NewBgpServer(server.LoggerOption(logger, &slog.LevelVar{}))
	go bgpServer.Serve()
	t.Cleanup(bgpServer.Stop)
	return bgpServer, handler
}

func testGlobalConfig() oc.Global {
	return oc.Global{
		Config: oc.GlobalConfig{
			As:       1,
			RouterId: netip.MustParseAddr("1.1.1.1"),
			Port:     -1,
		},
	}
}

func validConfig() *oc.BgpConfigSet {
	return &oc.BgpConfigSet{
		Global: testGlobalConfig(),
	}
}

func configWithValidPeerGroup() *oc.BgpConfigSet {
	cfg := validConfig()
	cfg.Neighbors = []oc.Neighbor{
		{
			Config: oc.NeighborConfig{
				PeerGroup:       "router",
				NeighborAddress: netip.MustParseAddr("1.1.1.2"),
			},
		},
	}
	cfg.PeerGroups = []oc.PeerGroup{
		{
			Config: oc.PeerGroupConfig{
				PeerGroupName: "router",
				PeerAs:        2,
			},
		},
	}
	return cfg
}

func configWithMissingPeerGroup() *oc.BgpConfigSet {
	cfg := validConfig()
	cfg.Neighbors = []oc.Neighbor{
		{
			Config: oc.NeighborConfig{
				PeerGroup:       "not-exists",
				NeighborAddress: netip.MustParseAddr("1.1.1.2"),
			},
		},
	}
	return cfg
}

func configWithMissingPolicySet() *oc.BgpConfigSet {
	cfg := validConfig()
	cfg.PolicyDefinitions = []oc.PolicyDefinition{
		{
			Name: "policy-without-a-set",
			Statements: []oc.Statement{
				{
					Conditions: oc.Conditions{
						MatchNeighborSet: oc.MatchNeighborSet{
							NeighborSet: "not-existing-neighbor-set",
						},
					},
				},
			},
		},
	}
	return cfg
}

func TestInitialConfigAppliesValidConfig(t *testing.T) {
	ctx := context.Background()
	bgpServer, handler := newTestBgpServer(t)

	_, err := InitialConfig(ctx, bgpServer, configWithValidPeerGroup(), false)
	require.NoError(t, err)
	assert.Empty(t, handler.Errors())
}

func TestInitialConfigReturnsConfigErrors(t *testing.T) {
	for _, tt := range []struct {
		name        string
		expectedErr string
		expectedLog string
		cfg         *oc.BgpConfigSet
	}{
		{
			name:        "peer without peer-group",
			expectedErr: "failed to add peer",
			expectedLog: "failed to add peer",
			cfg:         configWithMissingPeerGroup(),
		},
		{
			name:        "policy without a set",
			expectedErr: "failed to set policies",
			expectedLog: "failed to set policies",
			cfg:         configWithMissingPolicySet(),
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			bgpServer, handler := newTestBgpServer(t)

			_, err := InitialConfig(ctx, bgpServer, tt.cfg, false)
			require.ErrorContains(t, err, tt.expectedErr)
			assert.Contains(t, handler.Errors(), tt.expectedLog)
		})
	}
}

func TestUpdateConfigKeepsConfigErrorsNonFatal(t *testing.T) {
	ctx := context.Background()
	bgpServer, handler := newTestBgpServer(t)

	currentConfig, err := InitialConfig(ctx, bgpServer, validConfig(), false)
	require.NoError(t, err)

	_, err = UpdateConfig(ctx, bgpServer, currentConfig, configWithMissingPolicySet())
	require.NoError(t, err)

	assert.Contains(t, handler.Errors(), "failed to set policies")
}

// A reload that changes a [global] setting says so instead of ignoring it.
//
// StartBgp is the only writer of the server's global config and of
// table.SelectionOptions/table.UseMultiplePaths, and UpdateConfig touches
// neither - so editing [global] and sending SIGHUP changed nothing, with no
// error and no log line, while `gobgp global` went on reporting the old value.
//
// Route selection is restart-only by necessity rather than omission: the
// comparators read those globals and a destination's knownPathList is
// maintained sorted rather than re-sorted, so changing them on a running
// daemon would leave every existing destination ordered by the old relation
// while new insertions binary-search with the new one.
func TestUpdateConfigReportsGlobalChangesItCannotApply(t *testing.T) {
	ctx := context.Background()

	var reported []string
	logger := slog.New(&settingCaptureHandler{seen: &reported})
	bgpServer := server.NewBgpServer(server.LoggerOption(logger, &slog.LevelVar{}))
	go bgpServer.Serve()
	t.Cleanup(bgpServer.Stop)

	currentConfig, err := InitialConfig(ctx, bgpServer, validConfig(), false)
	require.NoError(t, err)

	// An unchanged global must stay silent, or the message is noise on every
	// reload and an operator learns to ignore it.
	_, err = UpdateConfig(ctx, bgpServer, currentConfig, validConfig())
	require.NoError(t, err)
	require.Empty(t, reported, "an unchanged [global] block must produce no complaint")

	changed := validConfig()
	changed.Global.RouteSelectionOptions.Config.AlwaysCompareMed = true
	changed.Global.UseMultiplePaths.Config.Enabled = true
	changed.Global.Config.RouterId = netip.MustParseAddr("2.2.2.2")
	// Applied on reload, so it must not be reported as ignored.
	changed.Global.ApplyPolicy.Config.DefaultImportPolicy = oc.DEFAULT_POLICY_TYPE_REJECT_ROUTE

	// The reload must still succeed: returning an error here makes main.go log
	// a warning and continue, abandoning every other change in the file.
	_, err = UpdateConfig(ctx, bgpServer, currentConfig, changed)
	require.NoError(t, err)

	assert.Contains(t, reported, "global.route-selection-options")
	assert.Contains(t, reported, "global.use-multiple-paths")
	assert.Contains(t, reported, "global.config")
	assert.NotContains(t, reported, "global.apply-policy",
		"apply-policy is applied on reload and must not be reported as ignored")
	assert.NotContains(t, reported, "global.state", "state is read-only")
}

// settingCaptureHandler records the Setting attribute of every log record, so
// the assertions above name the settings rather than matching on prose.
type settingCaptureHandler struct {
	mu   sync.Mutex
	seen *[]string
}

func (h *settingCaptureHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *settingCaptureHandler) Handle(_ context.Context, r slog.Record) error {
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == "Setting" {
			h.mu.Lock()
			*h.seen = append(*h.seen, a.Value.String())
			h.mu.Unlock()
		}
		return true
	})
	return nil
}

func (h *settingCaptureHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *settingCaptureHandler) WithGroup(string) slog.Handler      { return h }

// maximum-paths set in a config file reaches the daemon.
//
// The file is not handed to StartBgp directly: InitialConfig converts it to an
// api.Global first. A setting that conversion does not carry is parsed,
// validated and then dropped before the daemon sees it - which is exactly what
// happened to three neighbor blocks. GetBgp reports what StartBgp stored, so
// asserting on it is asserting on the far side of that conversion.
func TestMaximumPathsFromAConfigFileReachesTheDaemon(t *testing.T) {
	ctx := context.Background()
	bgpServer, _ := newTestBgpServer(t)

	cfg, err := oc.ReadConfig(strings.NewReader(`
[global.config]
  as = 65001
  router-id = "10.0.0.1"
  port = -1
[global.use-multiple-paths.config]
  enabled = true
[global.use-multiple-paths.ebgp.config]
  maximum-paths = 4
[global.use-multiple-paths.ibgp.config]
  maximum-paths = 2
`), "toml")
	require.NoError(t, err)

	_, err = InitialConfig(ctx, bgpServer, cfg, false)
	require.NoError(t, err)
	t.Cleanup(func() { _ = bgpServer.StopBgp(ctx, &api.StopBgpRequest{}) })

	rsp, err := bgpServer.GetBgp(ctx, &api.GetBgpRequest{})
	require.NoError(t, err)
	assert.True(t, rsp.Global.UseMultiplePaths)
	assert.EqualValues(t, 4, rsp.Global.EbgpMaximumPaths)
	assert.EqualValues(t, 2, rsp.Global.IbgpMaximumPaths)
}

// A config file attaching a per-peer policy to an ordinary neighbor fails to
// start rather than running with a policy that is never applied. The file
// reaches the daemon through AddPeer, so this is the same refusal the API gets.
func TestInitialConfigRefusesPolicyOnAnOrdinaryPeer(t *testing.T) {
	cfg, err := oc.ReadConfig(strings.NewReader(`
[global.config]
  as = 65001
  router-id = "10.0.0.1"
  port = -1
[[neighbors]]
  [neighbors.config]
    neighbor-address = "10.0.0.2"
    peer-as = 65002
  [neighbors.apply-policy.config]
    default-import-policy = "reject-route"
`), "toml")
	require.NoError(t, err, "the file itself is well formed")

	bgpServer, _ := newTestBgpServer(t)
	_, err = InitialConfig(context.Background(), bgpServer, cfg, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "route-server client")
	t.Cleanup(func() { _ = bgpServer.StopBgp(context.Background(), &api.StopBgpRequest{}) })
}
