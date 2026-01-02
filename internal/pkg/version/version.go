// Copyright (C) 2018 Nippon Telegraph and Telephone Corporation.
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

import "fmt"

const (
	// Original GoBGP version this fork is based on
	MAJOR uint = 4
	MINOR uint = 0
	PATCH uint = 0

	// PureLB fork version
	FORK_NAME  string = "PureLB-fork"
	FORK_MAJOR uint   = 1
	FORK_MINOR uint   = 1
	FORK_PATCH uint   = 1
)

var (
	COMMIT     string = ""
	IDENTIFIER string = ""
	METADATA   string = ""
)

func Version() string {
	// Base fork version
	baseVersion := fmt.Sprintf("%s:%02d.%02d.%02d", FORK_NAME, FORK_MAJOR, FORK_MINOR, FORK_PATCH)

	// Add commit if available
	if len(COMMIT) > 0 {
		if len(COMMIT) > 7 {
			baseVersion = fmt.Sprintf("%s (commit: %s)", baseVersion, COMMIT[:7])
		} else {
			baseVersion = fmt.Sprintf("%s (commit: %s)", baseVersion, COMMIT)
		}
	}

	// Add original GoBGP base version
	baseVersion = fmt.Sprintf("%s [base: gobgp-%d.%d.%d]", baseVersion, MAJOR, MINOR, PATCH)

	return baseVersion
}

// ShortVersion returns just the fork version without details
func ShortVersion() string {
	return fmt.Sprintf("%s:%02d.%02d.%02d", FORK_NAME, FORK_MAJOR, FORK_MINOR, FORK_PATCH)
}
