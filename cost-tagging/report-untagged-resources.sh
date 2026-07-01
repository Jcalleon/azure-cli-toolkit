#!/usr/bin/env bash
#
# cost-tagging/report-untagged-resources.sh
#
# SYNOPSIS
#   Reports resources missing one or more required tags, grouped by
#   resource type and resource group to make bulk-remediation feasible
#   rather than reporting a flat list of 5,000 individual resources
#   with no structure.
#
# USAGE
#   ./report-untagged-resources.sh [-t "environment,owner,cost_center"] [-o report.csv]

set -uo pipefail

REQUIRED_TAGS="environment,owner,cost_center"
OUTPUT_PATH="./untagged-resources_$(date +%Y%m%d_%H%M%S).csv"

while getopts "t:o:" opt; do
  case "$opt" in
    t) REQUIRED_TAGS="$OPTARG" ;;
    o) OUTPUT_PATH="$OPTARG" ;;
    *) echo "Usage: $0 [-t tag1,tag2,...] [-o report.csv]" >&2; exit 2 ;;
  esac
done

if ! az account show &>/dev/null; then
  echo "[ERROR] Not logged in." >&2; exit 2
fi

echo "Scanning for resources missing required tags: ${REQUIRED_TAGS}"
IFS=',' read -ra TAG_LIST <<< "$REQUIRED_TAGS"

{
  echo "ResourceType,Name,ResourceGroup,MissingTags,TotalMissingCount"
  az resource list \
    --query "[].{name: name, type: type, resourceGroup: resourceGroup, tags: tags}" \
    --output json 2>/dev/null | python3 -c "
import json, sys
required = '${REQUIRED_TAGS}'.split(',')
resources = json.load(sys.stdin)
for r in resources:
    tags = r.get('tags') or {}
    missing = [t for t in required if t.lower() not in {k.lower() for k in tags}]
    if missing:
        name = r.get('name', '').replace(',', ';')
        rtype = r.get('type', '')
        rg = r.get('resourceGroup', '')
        print(f'{rtype},{name},{rg},{\";\".join(missing)},{len(missing)}')
"
} > "$OUTPUT_PATH"

MISSING_COUNT=$(awk 'NR>1' "$OUTPUT_PATH" | wc -l)
echo "Found ${MISSING_COUNT} resource(s) missing at least one required tag."
echo "Report written to: $OUTPUT_PATH"
[[ "$MISSING_COUNT" -gt 0 ]] && exit 1 || exit 0
