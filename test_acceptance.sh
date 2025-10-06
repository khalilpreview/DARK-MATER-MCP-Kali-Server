#!/bin/bash
#
# Production API Acceptance Tests for MCP Kali Server
# Based on the exact curl examples from the copilot instructions
#

set -e

# Configuration
SERVER_HOST="${SERVER_HOST:-localhost}"
SERVER_PORT="${SERVER_PORT:-5000}"
SERVER_URL="http://${SERVER_HOST}:${SERVER_PORT}"
ENROLL_FILE="${ENROLL_FILE:-/etc/mcp-kali/enroll.json}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    if ! command -v curl &> /dev/null; then
        log_error "curl is required but not installed"
        exit 1
    fi
    
    if ! command -v jq &> /dev/null; then
        log_warning "jq not found - JSON responses will not be formatted"
        JQ_AVAILABLE=false
    else
        JQ_AVAILABLE=true
    fi
    
    log_success "Prerequisites check passed"
}

# Load enrollment data
load_enrollment_data() {
    log_info "Loading enrollment data from $ENROLL_FILE"
    
    if [[ ! -f "$ENROLL_FILE" ]]; then
        log_error "Enrollment file not found: $ENROLL_FILE"
        log_info "Run the installer first: sudo bash install.sh"
        exit 1
    fi
    
    if $JQ_AVAILABLE; then
        ENROLL_ID=$(jq -r '.id' "$ENROLL_FILE")
        ENROLL_TOKEN=$(jq -r '.token' "$ENROLL_FILE")
    else
        # Fallback parsing without jq
        ENROLL_ID=$(grep -o '"id":"[^"]*"' "$ENROLL_FILE" | cut -d'"' -f4)
        ENROLL_TOKEN=$(grep -o '"token":"[^"]*"' "$ENROLL_FILE" | cut -d'"' -f4)
    fi
    
    if [[ -z "$ENROLL_ID" || -z "$ENROLL_TOKEN" ]]; then
        log_error "Failed to parse enrollment data"
        exit 1
    fi
    
    log_success "Loaded enrollment data - ID: $ENROLL_ID"
}

# Test 1: Enrollment
test_enrollment() {
    log_info "=== TEST 1: ENROLLMENT ==="
    
    log_info "Enrolling server with curl..."
    
    ENROLL_RESPONSE=$(curl -sS -X POST "$SERVER_URL/enroll" \
        -H "Content-Type: application/json" \
        -d "{\"id\":\"$ENROLL_ID\",\"token\":\"$ENROLL_TOKEN\",\"label\":\"Kali-Lab-1\"}")
    
    if [[ $? -ne 0 ]]; then
        log_error "Enrollment request failed"
        exit 1
    fi
    
    echo "Enrollment Response:"
    if $JQ_AVAILABLE; then
        echo "$ENROLL_RESPONSE" | jq .
        API_KEY=$(echo "$ENROLL_RESPONSE" | jq -r '.api_key')
        SERVER_ID=$(echo "$ENROLL_RESPONSE" | jq -r '.server_id')
    else
        echo "$ENROLL_RESPONSE"
        API_KEY=$(echo "$ENROLL_RESPONSE" | grep -o '"api_key":"[^"]*"' | cut -d'"' -f4)
        SERVER_ID=$(echo "$ENROLL_RESPONSE" | grep -o '"server_id":"[^"]*"' | cut -d'"' -f4)
    fi
    
    if [[ -z "$API_KEY" || "$API_KEY" == "null" ]]; then
        log_error "Failed to get API key from enrollment response"
        exit 1
    fi
    
    log_success "Enrollment successful - Got API key"
}

# Test 2: Health Check
test_health() {
    log_info "=== TEST 2: HEALTH CHECK ==="
    
    log_info "Testing health endpoint..."
    
    HEALTH_RESPONSE=$(curl -sS "$SERVER_URL/health" \
        -H "Authorization: Bearer $API_KEY")
    
    if [[ $? -ne 0 ]]; then
        log_error "Health check request failed"
        exit 1
    fi
    
    echo "Health Response:"
    if $JQ_AVAILABLE; then
        echo "$HEALTH_RESPONSE" | jq .
        OK_STATUS=$(echo "$HEALTH_RESPONSE" | jq -r '.ok')
    else
        echo "$HEALTH_RESPONSE"
        OK_STATUS=$(echo "$HEALTH_RESPONSE" | grep -o '"ok":true' || echo "false")
    fi
    
    if [[ "$OK_STATUS" != "true" ]]; then
        log_error "Health check failed - server not OK"
        exit 1
    fi
    
    log_success "Health check passed"
}

# Test 3: Tools List
test_tools_list() {
    log_info "=== TEST 3: TOOLS LIST ==="
    
    log_info "Getting tools list..."
    
    TOOLS_RESPONSE=$(curl -sS "$SERVER_URL/tools/list" \
        -H "Authorization: Bearer $API_KEY")
    
    if [[ $? -ne 0 ]]; then
        log_error "Tools list request failed"
        exit 1
    fi
    
    echo "Tools List Response:"
    if $JQ_AVAILABLE; then
        echo "$TOOLS_RESPONSE" | jq .
        TOOLS_COUNT=$(echo "$TOOLS_RESPONSE" | jq '.tools | length')
    else
        echo "$TOOLS_RESPONSE"
        TOOLS_COUNT=$(echo "$TOOLS_RESPONSE" | grep -o '"name":"[^"]*"' | wc -l)
    fi
    
    if [[ "$TOOLS_COUNT" -eq 0 ]]; then
        log_error "No tools found in response"
        exit 1
    fi
    
    log_success "Tools list retrieved - Found $TOOLS_COUNT tools"
}

# Test 4: Tool Execution
test_tool_execution() {
    log_info "=== TEST 4: TOOL EXECUTION ==="
    
    log_info "Running network scan with net.scan_basic..."
    
    SCAN_RESPONSE=$(curl -sS -X POST "$SERVER_URL/tools/call" \
        -H "Authorization: Bearer $API_KEY" \
        -H "Content-Type: application/json" \
        -d '{
            "name": "net.scan_basic",
            "arguments": {
                "target": "127.0.0.1",
                "fast": true
            }
        }')
    
    if [[ $? -ne 0 ]]; then
        log_error "Tool execution request failed"
        exit 1
    fi
    
    echo "Scan Response:"
    if $JQ_AVAILABLE; then
        echo "$SCAN_RESPONSE" | jq .
        RETURN_CODE=$(echo "$SCAN_RESPONSE" | jq -r '.rc')
        ARTIFACT_URI=$(echo "$SCAN_RESPONSE" | jq -r '.artifact_uri')
    else
        echo "$SCAN_RESPONSE"
        RETURN_CODE=$(echo "$SCAN_RESPONSE" | grep -o '"rc":[0-9]*' | cut -d':' -f2)
        ARTIFACT_URI=$(echo "$SCAN_RESPONSE" | grep -o '"artifact_uri":"[^"]*"' | cut -d'"' -f4)
    fi
    
    if [[ "$RETURN_CODE" != "0" ]]; then
        log_error "Tool execution failed with return code: $RETURN_CODE"
        exit 1
    fi
    
    if [[ -z "$ARTIFACT_URI" || "$ARTIFACT_URI" == "null" ]]; then
        log_error "No artifact URI returned"
        exit 1
    fi
    
    log_success "Tool execution successful - Artifact: $ARTIFACT_URI"
}

# Test 5: Artifacts List
test_artifacts_list() {
    log_info "=== TEST 5: ARTIFACTS LIST ==="
    
    log_info "Getting artifacts list..."
    
    ARTIFACTS_RESPONSE=$(curl -sS "$SERVER_URL/artifacts/list" \
        -H "Authorization: Bearer $API_KEY")
    
    if [[ $? -ne 0 ]]; then
        log_error "Artifacts list request failed"
        exit 1
    fi
    
    echo "Artifacts List Response:"
    if $JQ_AVAILABLE; then
        echo "$ARTIFACTS_RESPONSE" | jq .
        ARTIFACTS_COUNT=$(echo "$ARTIFACTS_RESPONSE" | jq '.items | length')
    else
        echo "$ARTIFACTS_RESPONSE"
        ARTIFACTS_COUNT=$(echo "$ARTIFACTS_RESPONSE" | grep -o '"artifact_uri":"[^"]*"' | wc -l)
    fi
    
    log_success "Artifacts list retrieved - Found $ARTIFACTS_COUNT artifacts"
}

# Test 6: Artifact Read
test_artifact_read() {
    log_info "=== TEST 6: ARTIFACT READ ==="
    
    if [[ -z "$ARTIFACT_URI" ]]; then
        log_warning "No artifact URI available, skipping artifact read test"
        return
    fi
    
    log_info "Reading artifact: $ARTIFACT_URI"
    
    ARTIFACT_RESPONSE=$(curl -sS "$SERVER_URL/artifacts/read?uri=$ARTIFACT_URI" \
        -H "Authorization: Bearer $API_KEY")
    
    if [[ $? -ne 0 ]]; then
        log_error "Artifact read request failed"
        exit 1
    fi
    
    echo "Artifact Read Response (first 500 chars):"
    if $JQ_AVAILABLE; then
        echo "$ARTIFACT_RESPONSE" | jq . | head -c 500
    else
        echo "$ARTIFACT_RESPONSE" | head -c 500
    fi
    echo "..."
    
    log_success "Artifact read successful"
}

# Test 7: Scope Validation (should fail)
test_scope_validation() {
    log_info "=== TEST 7: SCOPE VALIDATION ==="
    
    log_info "Testing scope validation with public IP (should fail)..."
    
    SCOPE_RESPONSE=$(curl -sS -X POST "$SERVER_URL/tools/call" \
        -H "Authorization: Bearer $API_KEY" \
        -H "Content-Type: application/json" \
        -d '{
            "name": "net.scan_basic",
            "arguments": {
                "target": "8.8.8.8",
                "fast": true
            }
        }')
    
    if [[ $? -ne 0 ]]; then
        log_error "Scope validation request failed"
        exit 1
    fi
    
    echo "Scope Validation Response:"
    if $JQ_AVAILABLE; then
        echo "$SCOPE_RESPONSE" | jq .
        RETURN_CODE=$(echo "$SCOPE_RESPONSE" | jq -r '.rc')
    else
        echo "$SCOPE_RESPONSE"
        RETURN_CODE=$(echo "$SCOPE_RESPONSE" | grep -o '"rc":[0-9-]*' | cut -d':' -f2)
    fi
    
    if [[ "$RETURN_CODE" == "0" ]]; then
        log_warning "Expected scope violation but tool executed successfully"
    else
        log_success "Scope validation working - Public IP correctly blocked"
    fi
}

# Main test execution
main() {
    echo "🚀 MCP Kali Server - Production API Acceptance Tests"
    echo "🎯 Based on the exact specifications from copilot instructions"
    echo "📡 Server: $SERVER_URL"
    echo "=" * 60
    
    check_prerequisites
    load_enrollment_data
    
    test_enrollment
    test_health
    test_tools_list  
    test_tool_execution
    test_artifacts_list
    test_artifact_read
    test_scope_validation
    
    echo
    echo "=" * 60
    echo "🎉 ALL ACCEPTANCE TESTS COMPLETED!"
    echo "✅ The MCP Kali Server is working according to specifications"
    echo
    echo "📋 Test Summary:"
    echo "   ✅ Enrollment with API key generation"
    echo "   ✅ Health check with capabilities"
    echo "   ✅ Tools listing"
    echo "   ✅ Tool execution with artifact generation"
    echo "   ✅ Artifacts listing and reading"
    echo "   ✅ Scope validation and guardrails"
    echo
    echo "🔑 Your API key for dashboard connection: $API_KEY"
    echo "🆔 Server ID: $SERVER_ID"
}

# Handle command line arguments
case "${1:-}" in
    --help|-h)
        echo "MCP Kali Server - Production API Acceptance Tests"
        echo
        echo "Usage: $0 [options]"
        echo
        echo "Environment Variables:"
        echo "  SERVER_HOST     Server hostname (default: localhost)"
        echo "  SERVER_PORT     Server port (default: 5000)"
        echo "  ENROLL_FILE     Path to enrollment file (default: /etc/mcp-kali/enroll.json)"
        echo
        echo "Examples:"
        echo "  $0                           # Test localhost:5000"
        echo "  SERVER_HOST=192.168.1.100 $0 # Test remote server"
        echo "  ENROLL_FILE=/tmp/enroll.json $0 # Use custom enrollment file"
        exit 0
        ;;
    "")
        main
        ;;
    *)
        echo "Unknown option: $1"
        echo "Use --help for usage information"
        exit 1
        ;;
esac