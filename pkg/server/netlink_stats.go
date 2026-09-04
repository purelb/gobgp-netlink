//go:build linux

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

// NetlinkStatsSnapshot is a point-in-time copy of the netlink subsystem's
// counters, for monitoring.
//
// This is a plain Go type rather than an addition to the gRPC stats messages on
// purpose: the fork's API protobufs have diverged from upstream's, and appending
// fields there risks a future field-number collision. Nothing here crosses the
// wire.
type NetlinkStatsSnapshot struct {
	// Import (kernel -> BGP). Enabled reports whether the import client exists.
	ImportEnabled   bool
	ImportImported  uint64
	ImportWithdrawn uint64
	ImportErrors    uint64
	// ImportTicks stops advancing when the scan loop exits, which is how an
	// operator can tell the loop actually stopped after StopBgp.
	ImportTicks uint64
	// ImportAddrEvents counts kernel address changes that triggered an import.
	// Flat while addresses are appearing means the subscription is dead and the
	// daemon has silently fallen back to polling, which is otherwise
	// indistinguishable from a quiet node.
	ImportAddrEvents uint64

	// Export (BGP -> kernel). Enabled reports whether the export client exists.
	ExportEnabled           bool
	ExportExported          uint64
	ExportWithdrawn         uint64
	ExportErrors            uint64
	ExportNexthopValidation uint64
	ExportNexthopFailed     uint64
	ExportDampenedUpdates   uint64
	// CleanupDeleted/CleanupSkipped come from the startup stale-route sweep.
	// A non-zero Skipped on first boot after upgrade is the evidence that the
	// sweep narrowed rather than silently doing nothing.
	ExportCleanupDeleted uint64
	ExportCleanupSkipped uint64
}

// netlinkExportClientRef returns the current export client, or nil.
//
// The read-only netlink RPCs go through this. They used to nil-check the field
// and then dereference it, while DisableNetlinkExport nils it on the Serve
// goroutine - a TOCTOU crash reachable from any client polling these endpoints.
//
// Taking a local reference rather than wrapping the whole RPC in mgmtOperation
// is deliberate: ListNetlinkExport invokes a streaming callback per route, and
// FlushNetlinkExport issues one netlink delete per exported route. Serialising
// either against BGP processing would let a slow client stall every session on
// the node.
//
// Callers MUST NOT hold shared.mu.
func (s *BgpServer) netlinkExportClientRef() *netlinkExportClient {
	s.shared.mu.Lock()
	defer s.shared.mu.Unlock()
	return s.netlinkExportClient
}

// netlinkClientRef returns the current import client, or nil.
// Callers MUST NOT hold shared.mu.
func (s *BgpServer) netlinkClientRef() *netlinkClient {
	s.shared.mu.Lock()
	defer s.shared.mu.Unlock()
	return s.netlinkClient
}

// NetlinkStats returns a snapshot of the netlink import and export counters.
//
// It takes shared.mu directly rather than going through mgmtOperation. The
// client pointers are written on the Serve goroutine (DisableNetlinkExport nils
// them), so reading them unsynchronised would be a data race; but routing a
// metrics scrape through mgmtOperation would serialise it against all BGP
// message processing. Taking the mutex for the few microseconds needed to copy
// two counter structs is the right trade, and matches how handleFSMMessage
// acquires it.
//
// Lock order is shared.mu then each client's stats mutex, which are leaf locks.
func (s *BgpServer) NetlinkStats() NetlinkStatsSnapshot {
	var out NetlinkStatsSnapshot

	s.shared.mu.Lock()
	defer s.shared.mu.Unlock()

	if n := s.netlinkClient; n != nil {
		st := n.getStats()
		out.ImportEnabled = true
		out.ImportImported = st.Imported
		out.ImportWithdrawn = st.Withdrawn
		out.ImportErrors = st.Errors
		out.ImportTicks = st.Ticks
		out.ImportAddrEvents = st.AddrEvents
	}

	if e := s.netlinkExportClient; e != nil {
		st := e.getStats()
		out.ExportEnabled = true
		out.ExportExported = st.Exported
		out.ExportWithdrawn = st.Withdrawn
		out.ExportErrors = st.Errors
		out.ExportNexthopValidation = st.NexthopValidation
		out.ExportNexthopFailed = st.NexthopFailed
		out.ExportDampenedUpdates = st.DampenedUpdates
		out.ExportCleanupDeleted = st.CleanupDeleted
		out.ExportCleanupSkipped = st.CleanupSkipped
	}

	return out
}
