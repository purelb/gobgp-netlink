#!/bin/bash
#
# Automated Netlink Feature Test Suite
# Tests GoBGP netlink import/export functionality
#
# Usage: sudo ./test-netlink.sh
#
# Requirements:
#   - Root/sudo access
#   - Linux kernel 4.3+ (for VRF support)
#   - GoBGP binary (./gobgpd and ./gobgp)
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Directories
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_DIR="/tmp/gobgp-test-$$"
mkdir -p "$TEST_DIR"

# Binaries - check if running in container or host
if [ -f "/go/bin/gobgpd" ]; then
    # Running in container
    GOBGPD="/go/bin/gobgpd"
    GOBGP="/go/bin/gobgp"
else
    # Running on host - look in repository root
    REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
    GOBGPD="$REPO_ROOT/gobgpd"
    GOBGP="$REPO_ROOT/gobgp"
fi

# Test configuration
AS_NUMBER=64512
ROUTER_ID="10.0.0.1"
VRF_NAME="test-vrf"
VRF_TABLE=100
VRF_RD="64512:100"

# Test interfaces
IFACE_GLOBAL="test-eth0"
IFACE_VRF="test-eth1"

# Helper functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

assert_success() {
    TESTS_RUN=$((TESTS_RUN + 1))
    if [ $? -eq 0 ]; then
        log_info "✅ $1"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        log_error "❌ $1"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
}

assert_route_exists() {
    local route="$1"
    local description="$2"
    TESTS_RUN=$((TESTS_RUN + 1))

    if ip route show | grep -q "$route"; then
        log_info "✅ $description"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        log_error "❌ $description (route not found: $route)"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

assert_vrf_route_exists() {
    local vrf="$1"
    local route="$2"
    local description="$3"
    TESTS_RUN=$((TESTS_RUN + 1))

    if ip route show vrf "$vrf" | grep -q "$route"; then
        log_info "✅ $description"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        log_error "❌ $description (route not found in VRF $vrf: $route)"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

# Cleanup function
cleanup() {
    log_info "Cleaning up test environment..."

    # Stop GoBGP
    pkill gobgpd 2>/dev/null || true
    sleep 1

    # Remove interfaces
    ip link del "$IFACE_GLOBAL" 2>/dev/null || true
    ip link del "$IFACE_VRF" 2>/dev/null || true
    ip link del "$VRF_NAME" 2>/dev/null || true

    # Remove test directory
    rm -rf "$TEST_DIR"

    log_info "Cleanup complete"
}

# Setup test environment
setup_environment() {
    log_info "Setting up test environment..."

    # Ensure test directory exists
    mkdir -p "$TEST_DIR"

    # Load VRF kernel module if not loaded
    modprobe vrf 2>/dev/null || true

    # Try to create VRF (optional - tests will skip VRF tests if this fails)
    VRF_AVAILABLE=false
    if ip link add "$VRF_NAME" type vrf table "$VRF_TABLE" 2>/dev/null; then
        ip link set "$VRF_NAME" up
        VRF_AVAILABLE=true
        log_info "VRF $VRF_NAME created successfully"
    else
        log_info "VRF creation failed - VRF tests will be skipped"
    fi

    # Create test interfaces
    ip link add "$IFACE_GLOBAL" type dummy
    ip link set "$IFACE_GLOBAL" up
    assert_success "Global test interface created"

    # Add IP addresses to global interface
    ip addr add 192.168.100.1/24 dev "$IFACE_GLOBAL"
    ip addr add fd00:100::1/64 dev "$IFACE_GLOBAL"
    assert_success "IP addresses assigned to global interface"

    # Create VRF interface only if VRF is available
    if [ "$VRF_AVAILABLE" = true ]; then
        ip link add "$IFACE_VRF" type dummy
        ip link set "$IFACE_VRF" master "$VRF_NAME"
        ip link set "$IFACE_VRF" up
        ip addr add 192.168.101.1/24 dev "$IFACE_VRF"
        ip addr add fd00:101::1/64 dev "$IFACE_VRF"
        assert_success "VRF interface configured"
    fi

    log_info "Test environment setup complete"
}

# Test 1: Import from global interface
test_import_global() {
    log_info "=== Test 1: Import from Global Interface ==="

    cat > "$TEST_DIR/config-import.toml" <<EOF
[global.config]
  as = $AS_NUMBER
  router-id = "$ROUTER_ID"
  local-address-list = ["127.0.0.1"]

[netlink]
  [netlink.import]
    enabled = true
    interface-list = ["$IFACE_GLOBAL"]
EOF

    # Start GoBGP
    "$GOBGPD" -f "$TEST_DIR/config-import.toml" -t error --log-plain > "$TEST_DIR/gobgpd.log" 2>&1 &
    sleep 3

    # Check if routes are imported
    TESTS_RUN=$((TESTS_RUN + 1))
    if "$GOBGP" global rib | grep -q "192.168.100.0/24"; then
        log_info "✅ IPv4 route imported from global interface"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        log_error "❌ IPv4 route NOT imported from global interface"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi

    TESTS_RUN=$((TESTS_RUN + 1))
    if "$GOBGP" global rib -a ipv6 | grep -q "fd00:100::/64"; then
        log_info "✅ IPv6 route imported from global interface"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        log_error "❌ IPv6 route NOT imported from global interface"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi

    pkill gobgpd
    sleep 1
}

# Test 2: Import to VRF
test_import_vrf() {
    log_info "=== Test 2: Import to VRF ==="

    cat > "$TEST_DIR/config-import-vrf.toml" <<EOF
[global.config]
  as = $AS_NUMBER
  router-id = "$ROUTER_ID"
  local-address-list = ["127.0.0.1"]

[[vrfs]]
  [vrfs.config]
    name = "$VRF_NAME"
    rd = "$VRF_RD"
    import-rt-list = ["$VRF_RD"]
    export-rt-list = ["$VRF_RD"]

  [vrfs.netlink-import]
    enabled = true
    interface-list = ["$IFACE_VRF"]
EOF

    # Start GoBGP
    "$GOBGPD" -f "$TEST_DIR/config-import-vrf.toml" -t error --log-plain > "$TEST_DIR/gobgpd.log" 2>&1 &
    sleep 3

    # Check if routes are imported to VRF
    TESTS_RUN=$((TESTS_RUN + 1))
    if "$GOBGP" vrf "$VRF_NAME" rib | grep -q "192.168.101.0/24"; then
        log_info "✅ IPv4 route imported to VRF"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        log_error "❌ IPv4 route NOT imported to VRF"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi

    TESTS_RUN=$((TESTS_RUN + 1))
    if "$GOBGP" vrf "$VRF_NAME" rib -a ipv6 | grep -q "fd00:101::/64"; then
        log_info "✅ IPv6 route imported to VRF"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        log_error "❌ IPv6 route NOT imported to VRF"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi

    pkill gobgpd
    sleep 1
}

# Test 3: Export from global table
test_export_global() {
    log_info "=== Test 3: Export from Global Table ==="

    cat > "$TEST_DIR/config-export.toml" <<EOF
[global.config]
  as = $AS_NUMBER
  router-id = "$ROUTER_ID"
  local-address-list = ["127.0.0.1"]

[netlink]
  [netlink.export]
    enabled = true
    route-protocol = 201

[[netlink.export.rules]]
  name = "test-export"
  vrf = ""
  table-id = 0
  metric = 100
  skip-nexthop-validation = false
  community-list = []
EOF

    # Start GoBGP
    "$GOBGPD" -f "$TEST_DIR/config-export.toml" -t error --log-plain > "$TEST_DIR/gobgpd.log" 2>&1 &
    sleep 3

    # Add a test route
    "$GOBGP" global rib add 10.1.0.0/24 nexthop 192.168.100.1
    sleep 2

    # Check if route is exported
    assert_route_exists "10.1.0.0/24 via 192.168.100.1" "IPv4 route exported to global table"

    # Add IPv6 route
    "$GOBGP" global rib add fd00:200::/64 nexthop fd00:100::100 -a ipv6
    sleep 2

    TESTS_RUN=$((TESTS_RUN + 1))
    if ip -6 route show | grep -q "fd00:200::/64 via fd00:100::100"; then
        log_info "✅ IPv6 route exported to global table"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        log_error "❌ IPv6 route NOT exported to global table"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi

    pkill gobgpd
    sleep 1
}

# Test 4: VRF export with ONLINK
test_export_vrf_onlink() {
    log_info "=== Test 4: VRF Export with ONLINK Flag ==="

    cat > "$TEST_DIR/config-export-vrf.toml" <<EOF
[global.config]
  as = $AS_NUMBER
  router-id = "$ROUTER_ID"
  local-address-list = ["127.0.0.1"]

[netlink]
  [netlink.export]
    enabled = true
    route-protocol = 201

[[vrfs]]
  [vrfs.config]
    name = "$VRF_NAME"
    rd = "$VRF_RD"
    import-rt-list = ["$VRF_RD"]
    export-rt-list = ["$VRF_RD"]

  [vrfs.netlink-export]
    enabled = true
    linux-vrf = "$VRF_NAME"
    linux-table-id = $VRF_TABLE
    metric = 50
    skip-nexthop-validation = true
    community-list = []
EOF

    # Start GoBGP
    "$GOBGPD" -f "$TEST_DIR/config-export-vrf.toml" -t error --log-plain > "$TEST_DIR/gobgpd.log" 2>&1 &
    sleep 3

    # Add route with unreachable nexthop
    "$GOBGP" vrf "$VRF_NAME" rib add 10.2.0.0/24 nexthop 1.1.1.1
    sleep 2

    # Check if route is exported with ONLINK flag
    TESTS_RUN=$((TESTS_RUN + 1))
    if ip route show vrf "$VRF_NAME" | grep -q "10.2.0.0/24 via 1.1.1.1.*onlink"; then
        log_info "✅ IPv4 VRF route exported with ONLINK flag"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        log_error "❌ IPv4 VRF route NOT exported with ONLINK flag"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi

    # Add IPv6 route with unreachable nexthop
    "$GOBGP" vrf "$VRF_NAME" rib add fd00:300::/64 nexthop 2001:db8::1 -a ipv6
    sleep 2

    TESTS_RUN=$((TESTS_RUN + 1))
    if ip -6 route show vrf "$VRF_NAME" | grep -q "fd00:300::/64 via 2001:db8::1.*onlink"; then
        log_info "✅ IPv6 VRF route exported with ONLINK flag"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        log_error "❌ IPv6 VRF route NOT exported with ONLINK flag"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi

    pkill gobgpd
    sleep 1
}

# Test 5: CLI commands
test_cli_commands() {
    log_info "=== Test 5: CLI Commands ==="

    # Start GoBGP with both import and export
    cat > "$TEST_DIR/config-full.toml" <<EOF
[global.config]
  as = $AS_NUMBER
  router-id = "$ROUTER_ID"
  local-address-list = ["127.0.0.1"]

[netlink]
  [netlink.import]
    enabled = true
    interface-list = ["$IFACE_GLOBAL"]

  [netlink.export]
    enabled = true
    route-protocol = 201

[[netlink.export.rules]]
  name = "test-export"
  vrf = ""
  table-id = 0
  metric = 100
  skip-nexthop-validation = false
  community-list = []

[[vrfs]]
  [vrfs.config]
    name = "$VRF_NAME"
    rd = "$VRF_RD"
    import-rt-list = ["$VRF_RD"]
    export-rt-list = ["$VRF_RD"]

  [vrfs.netlink-import]
    enabled = true
    interface-list = ["$IFACE_VRF"]
EOF

    "$GOBGPD" -f "$TEST_DIR/config-full.toml" -t error --log-plain > "$TEST_DIR/gobgpd.log" 2>&1 &
    sleep 3

    # Test gobgp netlink
    TESTS_RUN=$((TESTS_RUN + 1))
    if "$GOBGP" netlink | grep -q "Import: true"; then
        log_info "✅ 'gobgp netlink' command working"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        log_error "❌ 'gobgp netlink' command failed"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi

    # Test gobgp netlink import stats
    TESTS_RUN=$((TESTS_RUN + 1))
    if "$GOBGP" netlink import stats | grep -q "Total Imported"; then
        log_info "✅ 'gobgp netlink import stats' command working"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        log_error "❌ 'gobgp netlink import stats' command failed"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi

    # Test gobgp netlink export rules
    TESTS_RUN=$((TESTS_RUN + 1))
    if "$GOBGP" netlink export rules | grep -q "test-export"; then
        log_info "✅ 'gobgp netlink export rules' command working"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        log_error "❌ 'gobgp netlink export rules' command failed"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi

    pkill gobgpd
    sleep 1
}

# Main test execution
main() {
    log_info "Starting GoBGP Netlink Test Suite"
    log_info "=================================="

    # Check for root
    if [ "$EUID" -ne 0 ]; then
        log_error "This script must be run as root (sudo)"
        exit 1
    fi

    # Check for binaries
    if [ ! -f "$GOBGPD" ] || [ ! -f "$GOBGP" ]; then
        log_error "GoBGP binaries not found. Please build first: go build ./cmd/gobgpd && go build ./cmd/gobgp"
        exit 1
    fi

    # Setup
    trap cleanup EXIT
    cleanup  # Clean up any previous test artifacts
    setup_environment

    # Run tests
    test_import_global

    if [ "$VRF_AVAILABLE" = true ]; then
        test_import_vrf
    else
        log_info "⏭️  Skipping test_import_vrf (VRF not available)"
    fi

    test_export_global

    if [ "$VRF_AVAILABLE" = true ]; then
        test_export_vrf_onlink
    else
        log_info "⏭️  Skipping test_export_vrf_onlink (VRF not available)"
    fi

    test_cli_commands

    # Summary
    echo ""
    log_info "=================================="
    log_info "Test Summary"
    log_info "=================================="
    log_info "Tests Run:    $TESTS_RUN"
    log_info "Tests Passed: ${GREEN}$TESTS_PASSED${NC}"

    if [ $TESTS_FAILED -gt 0 ]; then
        log_error "Tests Failed: $TESTS_FAILED"
        exit 1
    else
        log_info "${GREEN}All tests passed!${NC}"
        exit 0
    fi
}

# Run main
main "$@"
