#!/usr/bin/env bash
set -euo pipefail

base_url="${1:?usage: smoke-test.sh BASE_URL}"
base_url="${base_url%/}"

curl --fail --silent --show-error --output /dev/null "$base_url/health/live"
curl --fail --silent --show-error --output /dev/null "$base_url/health/ready"
curl --fail --silent --show-error --output /dev/null "$base_url/openapi/v1.json"

response="$(curl --fail --silent --show-error \
  --header 'content-type: application/json' \
  --data '{"query":"BehaviorInfo | invoke GetFirstSeenBehaviors() | project Timestamp, BehaviorId, Insights","environment":"xdr","profile":"hunting"}' \
  "$base_url/api/v1/validate")"

if command -v jq >/dev/null 2>&1; then
  jq --exit-status '.valid == true and (.outputColumns | any(.name == "Insights"))' <<<"$response" >/dev/null
else
  grep -q '"valid":true' <<<"$response"
fi

initialize="$(curl --fail --silent --show-error \
  --header 'accept: application/json, text/event-stream' \
  --header 'content-type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"smoke-test","version":"1.0"}}}' \
  "$base_url/mcp")"
grep -q 'kql-validator' <<<"$initialize"

echo "REST, OpenAPI, health, validation, and MCP smoke tests passed for $base_url"
