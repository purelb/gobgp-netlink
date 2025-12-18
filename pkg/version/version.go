// Copyright (C) 2025 The GoBGP Authors.
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

package version

import (
	"fmt"
	"runtime"
)

var (
	// Version is the semantic version
	Version = "01.01.00"

	// Commit is the git commit hash (set by build flags)
	Commit = "unknown"

	// BuildDate is the build date (set by build flags)
	BuildDate = "unknown"

	// ForkName is the fork identifier
	ForkName = "PureLB-fork"
)

// GetVersion returns the version string
func GetVersion() string {
	return fmt.Sprintf("%s:%s", ForkName, Version)
}

// GetFullVersion returns detailed version information
func GetFullVersion() string {
	return fmt.Sprintf("%s:%s (commit: %s, built: %s, go: %s)",
		ForkName, Version, Commit, BuildDate, runtime.Version())
}

// GetShortVersion returns version with commit
func GetShortVersion() string {
	if Commit != "unknown" && len(Commit) > 7 {
		return fmt.Sprintf("%s:%s-%s", ForkName, Version, Commit[:7])
	}
	return fmt.Sprintf("%s:%s-%s", ForkName, Version, Commit)
}
