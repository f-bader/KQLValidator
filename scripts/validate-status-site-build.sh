#!/usr/bin/env bash
set -euo pipefail

output_root="$(mktemp -d)"
trap 'rm -rf "$output_root"' EXIT

dotnet publish src/KqlValidator.Api/KqlValidator.Api.csproj \
  --configuration Release \
  --no-restore \
  --output "$output_root/enabled" \
  /p:UseAppHost=false \
  /p:EnableStatusSite=true

test -f "$output_root/enabled/wwwroot/status/index.html"
test -f "$output_root/enabled/wwwroot/status/site.css"
test -f "$output_root/enabled/wwwroot/status/site.js"

dotnet publish src/KqlValidator.Api/KqlValidator.Api.csproj \
  --configuration Release \
  --no-restore \
  --output "$output_root/disabled" \
  /p:UseAppHost=false \
  /p:EnableStatusSite=false

test ! -e "$output_root/disabled/wwwroot/status"

echo "Status site enabled/disabled publish checks passed."
