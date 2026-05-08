#!/usr/bin/env bash
# ==============================================================================
# security-test.sh — Automated Security Verification Suite
# ==============================================================================
#
# Tests that your security controls are actually working.
# Run after deployment to verify: WAF, rate limiting, headers, injection protection.
#
# WHY TEST YOUR OWN SECURITY CONTROLS?
#   Security theater is common — configs that look secure but aren't.
#   This script proves each layer is operational.
#   Run it after every deployment.
#
# REQUIRES: curl, jq
# ==============================================================================

set -uo pipefail

BASE_URL=${BASE_URL:-"http://localhost:8080"}
PASS=0
FAIL=0

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass() { echo -e "${GREEN}✅ PASS${NC} — $1"; ((PASS++)); return 0; }
fail() { echo -e "${RED}❌ FAIL${NC} — $1"; ((FAIL++)); return 1; }
info() { echo -e "${YELLOW}[TEST]${NC} $1"; }

echo "======================================================="
echo "  Zero-Trust Architecture Security Test Suite"
echo "======================================================="
echo "Target: $BASE_URL"
echo ""

# ==============================================================================
# TEST 1: Health Check
# ==============================================================================
info "Health endpoint should return 200"
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/health")
[ "$STATUS" = "200" ] && pass "Health endpoint returns 200" || fail "Health endpoint returned $STATUS"

# ==============================================================================
# TEST 2: Security Headers Present
# ==============================================================================
info "Checking security headers..."
HEADERS=$(curl -s -I "$BASE_URL/")

check_header() {
    local header="$1"
    local expected="$2"
    if echo "$HEADERS" | grep -qi "$header"; then
        pass "Header present: $header"
    else
        fail "Header MISSING: $header (should contain: $expected)"
    fi
}

check_header "Strict-Transport-Security"   "max-age="
check_header "X-Frame-Options"             "DENY"
check_header "X-Content-Type-Options"      "nosniff"
check_header "Content-Security-Policy"     "default-src"
check_header "Referrer-Policy"             "strict-origin"
check_header "Permissions-Policy"          "geolocation"

# Verify server version is hidden
if echo "$HEADERS" | grep -q "nginx/"; then
    fail "Server version EXPOSED in Server header (should be hidden)"
else
    pass "Server version hidden"
fi

# ==============================================================================
# TEST 3: SQL Injection — WAF should block these
# ==============================================================================
info "Testing SQL injection protection..."

test_waf_blocks() {
    local description="$1"
    local url="$2"
    local status
    status=$(curl -s -o /dev/null -w "%{http_code}" "$url")
    # WAF should return 403 Forbidden or 400 Bad Request
    if [ "$status" = "403" ] || [ "$status" = "400" ]; then
        pass "WAF blocked: $description (HTTP $status)"
    else
        fail "WAF DID NOT BLOCK: $description (HTTP $status — should be 403/400)"
    fi
}

# Classic SQL injection
test_waf_blocks "SQL injection (OR 1=1)" \
    "${BASE_URL}/api/search?q=test%27+OR+%271%27%3D%271"

# UNION-based SQL injection
test_waf_blocks "SQL UNION injection" \
    "${BASE_URL}/api/search?q=1+UNION+SELECT+username,password+FROM+users--"

# Error-based SQL injection
test_waf_blocks "SQL error injection" \
    "${BASE_URL}/api/search?q=1%27%3BSELECT+pg_sleep(5)--"

# ==============================================================================
# TEST 4: XSS — WAF should block these
# ==============================================================================
info "Testing XSS protection..."

test_waf_blocks "Basic XSS script tag" \
    "${BASE_URL}/api/search?q=%3Cscript%3Ealert%28%27xss%27%29%3C%2Fscript%3E"

test_waf_blocks "XSS event handler" \
    "${BASE_URL}/api/search?q=%3Cimg+src%3Dx+onerror%3Dalert%281%29%3E"

test_waf_blocks "JavaScript protocol XSS" \
    "${BASE_URL}/api/search?q=javascript%3Aalert%281%29"

# ==============================================================================
# TEST 5: Path Traversal — WAF + Nginx should block these
# ==============================================================================
info "Testing path traversal protection..."

test_waf_blocks "Path traversal (../)" \
    "${BASE_URL}/api/files?path=../../etc/passwd"

test_waf_blocks "Path traversal (encoded)" \
    "${BASE_URL}/api/files?path=..%2F..%2Fetc%2Fpasswd"

# .env file access (Nginx blocks this)
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/.env")
[ "$STATUS" = "404" ] && pass "Nginx blocks .env access (404)" || fail ".env accessible (HTTP $STATUS)"

STATUS=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/.git/config")
[ "$STATUS" = "404" ] && pass "Nginx blocks .git access (404)" || fail ".git accessible (HTTP $STATUS)"

# ==============================================================================
# TEST 6: WordPress/Admin scanner blocks
# ==============================================================================
info "Testing scanner trap paths..."

for path in /wp-admin /wp-login.php /phpmyadmin /adminer /admin.php; do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}${path}")
    [ "$STATUS" = "404" ] && pass "Scanner path blocked: $path" || fail "Scanner path accessible: $path (HTTP $STATUS)"
done

# ==============================================================================
# TEST 7: Rate Limiting
# ==============================================================================
info "Testing rate limiting (sends 15 rapid requests to /login)..."
BLOCKED=0
for i in $(seq 1 15); do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${BASE_URL}/login" \
        -H "Content-Type: application/json" \
        -d '{"username":"test","password":"test"}')
    [ "$STATUS" = "429" ] && ((BLOCKED++))
done

if [ "$BLOCKED" -gt 0 ]; then
    pass "Rate limiting active: $BLOCKED/15 requests rate-limited"
else
    fail "Rate limiting NOT working: 0 requests blocked in 15 rapid requests"
fi

# ==============================================================================
# TEST 8: No User-Agent rejection
# ==============================================================================
info "Testing empty User-Agent rejection..."
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -A "" "${BASE_URL}/")
# Nginx returns 444 (closes connection) or 0 if connection is closed immediately
[ "$STATUS" = "000" ] || [ "$STATUS" = "444" ] && pass "Empty User-Agent blocked" || \
    fail "Empty User-Agent not blocked (HTTP $STATUS)"

# ==============================================================================
# TEST 9: Application Input Validation
# ==============================================================================
info "Testing application-level input validation..."

# Register with invalid username (contains SQL chars)
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${BASE_URL}/api/users/register" \
    -H "Content-Type: application/json" \
    -d '{"username":"admin'"'"'; DROP TABLE users;--","email":"test@test.com","password":"test"}')
[ "$STATUS" = "422" ] || [ "$STATUS" = "400" ] || [ "$STATUS" = "403" ] && \
    pass "App rejects SQL injection in username (HTTP $STATUS)" || \
    fail "App ACCEPTED malicious username (HTTP $STATUS)"

# Register with too-short password
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${BASE_URL}/api/users/register" \
    -H "Content-Type: application/json" \
    -d '{"username":"testuser","email":"test@test.com","password":"short"}')
[ "$STATUS" = "422" ] || [ "$STATUS" = "400" ] && \
    pass "App rejects short password (HTTP $STATUS)" || \
    fail "App accepted too-short password (HTTP $STATUS)"

# ==============================================================================
# TEST 10: Network Isolation — Data tier should not be reachable from host
# ==============================================================================
info "Testing network isolation..."

# PostgreSQL should NOT be accessible from the host
if curl -s --connect-timeout 2 "http://localhost:5432" >/dev/null 2>&1; then
    fail "PostgreSQL port 5432 is accessible from host (data tier should be isolated)"
else
    pass "PostgreSQL NOT accessible from host (correct — data tier isolated)"
fi

# Vault should NOT be accessible from the host
if curl -s --connect-timeout 2 "http://localhost:8200" >/dev/null 2>&1; then
    fail "Vault port 8200 is accessible from host (should be internal only)"
else
    pass "Vault NOT accessible from host (correct — data tier isolated)"
fi

# ==============================================================================
# RESULTS
# ==============================================================================
echo ""
echo "======================================================="
echo "  Test Results"
echo "======================================================="
echo -e "  ${GREEN}Passed: $PASS${NC}"
echo -e "  ${RED}Failed: $FAIL${NC}"
echo ""

if [ "$FAIL" -gt 0 ]; then
    echo -e "${RED}⚠️  $FAIL tests failed. Review the output above.${NC}"
    exit 1
else
    echo -e "${GREEN}✅ All security tests passed!${NC}"
    exit 0
fi
