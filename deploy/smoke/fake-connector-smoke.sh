#!/usr/bin/env bash
# Compose smoke for the fake connector's confirmed and ledgered writes
# (quirk enqgtw5y, task sougju69). Against `make compose-up`:
#
#   1. signs in as dev@example.com through the Compose dex (authorization
#      code + PKCE, scripted with curl and a cookie jar),
#   2. sets the member role to fake.* allow + fake.create_item confirm,
#   3. mints a harness token on /tokens/new,
#   4. drives /mcp with curl: tools/list, fake.list_accounts (the seeded
#      connections row), fake.post_note twice (ledgered, then replayed),
#      fake.create_item (approval required after the bounded wait),
#      approves it on /approvals/{id}/approve with the session cookie and
#      CSRF token, retries with approval_id and drifted arguments (the
#      stored ones run), and lists /operations.
#
# Usage: deploy/smoke/fake-connector-smoke.sh   (GW=http://localhost:18080)
# Takes ~35 s: the confirmed call waits GATEWAY_APPROVAL_WAIT (30 s) first.
set -euo pipefail
GW=${GW:-http://localhost:18080}
DEX=${DEX:-http://localhost:15556}
JAR=$(mktemp)
trap 'rm -f "$JAR"' EXIT

# 1. Sign in through dex.
loc=$(curl -sS -c "$JAR" -b "$JAR" -o /dev/null -w '%{redirect_url}' "$GW/auth/dex/start?return_to=/account")
page=$(curl -sS -L -c "$JAR" -b "$JAR" "$loc")
action=$(printf '%s' "$page" | grep -o 'action="[^"]*"' | head -1 | sed 's/action="//;s/"$//' | sed 's/&amp;/\&/g')
case "$action" in /*) action="$DEX$action";; esac
curl -sS -L -c "$JAR" -b "$JAR" -o /dev/null --data-urlencode 'login=dev@example.com' --data-urlencode 'password=password' "$action"
acct=$(curl -sS -b "$JAR" "$GW/account")
printf '%s' "$acct" | grep -q 'admin' || { echo "sign-in failed"; exit 1; }
csrf=$(printf '%s' "$acct" | grep -o 'name="_csrf" value="[^"]*"' | head -1 | sed 's/.*value="//;s/"$//')
echo "signed in as dev@example.com"

# 2. Role: fake.* allow, fake.create_item confirm.
curl -sS -b "$JAR" -o /dev/null -w 'role save: %{http_code}\n' -X POST "$GW/admin/roles/member" \
  --data-urlencode "_csrf=$csrf" --data-urlencode 'outcome.fake.*=allow' --data-urlencode 'outcome.fake.create_item=confirm'

# 3. Token (shown once on the page that follows creation).
tok_page=$(curl -sS -b "$JAR" -L -X POST "$GW/tokens/new" --data-urlencode "_csrf=$csrf" --data-urlencode 'name=smoke')
T=$(printf '%s' "$tok_page" | grep -o 'mgw_[A-Za-z0-9]\{8\}_[A-Za-z0-9]\{43\}' | head -1)
[ -n "$T" ] || { echo "no token"; exit 1; }
echo "token: ${T:0:12}..."

# 4. /mcp. The item id is unique per run so the script can be re-run on
# the same stack; the note is not, so the second run replays it as well.
ITEM="it-$(date +%s)"
mcp() { curl -sS "$GW/mcp" -H "Authorization: Bearer $T" -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' -d "$1"; echo; }
echo "--- tools/list"; mcp '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | grep -o '"name":"fake\.[a-z_]*"' | tr '\n' ' '; echo
echo "--- fake.list_accounts (a connections row, seeded on first use)"
mcp '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"fake.list_accounts","arguments":{}}}'
echo "--- fake.post_note (unconfirmed write: ledgered)"
mcp '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"fake.post_note","arguments":{"text":"hello"}}}'
echo "--- fake.post_note again (same arguments inside the window: replayed)"
mcp '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"fake.post_note","arguments":{"text":"hello"}}}'
echo "--- fake.create_item (confirm: approval required after the bounded wait)"
out=$(mcp "{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"tools/call\",\"params\":{\"name\":\"fake.create_item\",\"arguments\":{\"id\":\"$ITEM\",\"name\":\"first\"}}}")
echo "$out"
aid=$(printf '%s' "$out" | grep -o '"approval_id":"[^"]*"' | head -1 | sed 's/.*:"//;s/"$//')
[ -n "$aid" ] || { echo "no approval id"; exit 1; }
echo "--- approve $aid in the portal (session cookie + CSRF)"
curl -sS -b "$JAR" -o /dev/null -w 'approve: %{http_code}\n' -X POST "$GW/approvals/$aid/approve" --data-urlencode "_csrf=$csrf"
echo "--- retry with approval_id and drifted arguments (the stored name \"first\" runs)"
mcp "{\"jsonrpc\":\"2.0\",\"id\":6,\"method\":\"tools/call\",\"params\":{\"name\":\"fake.create_item\",\"arguments\":{\"id\":\"$ITEM\",\"name\":\"drifted\",\"approval_id\":\"$aid\"}}}"
echo "--- /operations"
curl -sS -b "$JAR" "$GW/operations" | grep -o 'fake\.[a-z_]*\|succeeded' | sort | uniq -c
