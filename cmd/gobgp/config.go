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
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/osrg/gobgp/v4/api"
)

func showRunningConfig(format string, provenance bool) error {
	var f api.ConfigFormat
	switch format {
	case "", "json":
		f = api.ConfigFormat_CONFIG_FORMAT_JSON
	case "toml":
		f = api.ConfigFormat_CONFIG_FORMAT_TOML
	default:
		return fmt.Errorf("invalid format %q: json or toml", format)
	}

	rsp, err := client.GetRunningConfig(context.Background(), &api.GetRunningConfigRequest{
		Format:            f,
		IncludeProvenance: provenance,
	})
	if err != nil {
		return err
	}
	fmt.Println(rsp.Config)
	return nil
}

func newConfigCmd() *cobra.Command {
	var format string
	var provenance bool

	runningCmd := &cobra.Command{
		Use:   "running",
		Short: "show the daemon's complete running configuration",
		Long: `Print the running configuration: the global config plus every live
peer and peer group, as gobgpd currently holds them.

This is the applied configuration, not the submitted one - defaults and
peer-group inheritance are already resolved - and it includes settings that no
other RPC reports. Auth passwords are shown as "<redacted>" when set, so the
output is not directly loadable as a config file when authentication is in use.

--provenance additionally reports which of each peer's configuration blocks
were inherited rather than set on the peer, and whether they came from its peer
group or from the global block. Because the output above is the resolved
configuration, a value that was set and a value that was inherited otherwise
look identical. The report is appended as comments (TOML) or a trailing object
(JSON), so it does not affect loading the config back.

It is a debugging and verification surface. The shape is gobgpd's internal
configuration model, which is generated from YANG and can change without a
proto version bump, so do not build control logic against its field layout.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return showRunningConfig(format, provenance)
		},
	}
	runningCmd.Flags().StringVarP(&format, "format", "f", "json", "output format: json or toml")
	runningCmd.Flags().BoolVar(&provenance, "provenance", false,
		"also report which peer configuration blocks were inherited, and from where")

	configCmd := &cobra.Command{
		Use:   "config",
		Short: "inspect gobgpd's configuration",
	}
	configCmd.AddCommand(runningCmd)
	return configCmd
}
