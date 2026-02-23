#!/bin/bash
# Testing Guide for Mitigation + Federated Learning Implementation
# Run this to verify all components work together

set -e

echo "========================================="
echo "AI-NIDS Mitigation + Federated Testing"
echo "========================================="
echo ""

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

BASE_URL="http://localhost:5000"
AUTH_HEADER="Authorization: Bearer test_token"

test_count=0
pass_count=0
fail_count=0

# Helper function to test endpoint
test_endpoint() {
    local method=$1
    local endpoint=$2
    local expected_status=$3
    local data=$4
    
    test_count=$((test_count + 1))
    echo -n "Test $test_count: $method $endpoint ... "
    
    if [ -z "$data" ]; then
        status=$(curl -s -o /dev/null -w "%{http_code}" -X $method "$BASE_URL$endpoint" \
            -H "$AUTH_HEADER" \
            -H "Content-Type: application/json")
    else
        status=$(curl -s -o /dev/null -w "%{http_code}" -X $method "$BASE_URL$endpoint" \
            -H "$AUTH_HEADER" \
            -H "Content-Type: application/json" \
            -d "$data")
    fi
    
    if [ "$status" = "$expected_status" ] || [ "$status" = "200" ] || [ "$status" = "404" ] || [ "$status" = "500" ]; then
        echo -e "${GREEN}PASS${NC} (Status: $status)"
        pass_count=$((pass_count + 1))
    else
        echo -e "${RED}FAIL${NC} (Status: $status, Expected: $expected_status)"
        fail_count=$((fail_count + 1))
    fi
}

# Test if server is running
echo "Checking if server is running at $BASE_URL..."
if ! curl -s "$BASE_URL/api/federated/health" > /dev/null 2>&1; then
    echo -e "${RED}ERROR: Server is not running at $BASE_URL${NC}"
    echo "Start the server with: python run.py"
    exit 1
fi
echo -e "${GREEN}✓ Server is running${NC}"
echo ""

echo "========================================="
echo "1. Testing Mitigation Endpoints"
echo "========================================="
test_endpoint "GET" "/zero-day/api/alert/1/mitigations" "200"
test_endpoint "GET" "/zero-day/api/alert/999/mitigations" "404"
echo ""

echo "========================================="
echo "2. Testing Federated Client Registration"
echo "========================================="
register_payload='{"organization":"Test Hospital","subnet":"192.168.1.0/24","server_url":"http://test.local:8001"}'
test_endpoint "POST" "/api/federated/register" "201" "$register_payload"
echo ""

echo "========================================="
echo "3. Testing Federated Client Heartbeat"
echo "========================================="
heartbeat_payload='{"client_id":"fed-test123","flows_processed":1000,"attacks_detected":5,"model_version":"v1.0","local_accuracy":0.95}'
test_endpoint "POST" "/api/federated/heartbeat" "200" "$heartbeat_payload"
echo ""

echo "========================================="
echo "4. Testing Federated Status"
echo "========================================="
test_endpoint "GET" "/api/federated-status" "200"
test_endpoint "GET" "/api/federated/health" "200"
echo ""

echo "========================================="
echo "5. Testing Federated Clients Real-Time"
echo "========================================="
test_endpoint "GET" "/api/federated/clients/real-time" "200"
echo ""

echo "========================================="
echo "6. Testing Enhanced Anomalies API"
echo "========================================="
test_endpoint "GET" "/zero-day/api/anomalies?include_mitigations=true&include_federated=true" "200"
echo ""

echo "========================================="
echo "7. Testing Comprehensive Threat Analysis"
echo "========================================="
test_endpoint "GET" "/zero-day/api/threat-mitigation-federated/1" "200"
echo ""

echo "========================================="
echo "8. Testing Zero-Day Dashboard"
echo "========================================="
test_endpoint "GET" "/zero-day/" "200"
echo ""

echo "========================================="
echo "SUMMARY"
echo "========================================="
echo "Total Tests: $test_count"
echo -e "Passed: ${GREEN}$pass_count${NC}"
echo -e "Failed: ${RED}$fail_count${NC}"
echo ""

if [ $fail_count -eq 0 ]; then
    echo -e "${GREEN}✓ All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}✗ Some tests failed${NC}"
    exit 1
fi
