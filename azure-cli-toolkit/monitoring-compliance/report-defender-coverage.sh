#!/usr/bin/env bash
#
# monitoring-compliance/report-defender-coverage.sh
#
# SYNOPSIS
#   Reports the current Microsoft Defender for Cloud plan coverage
#   across all supported resource types in the subscription — which
#   resource types have Defender enabled (and at which tier), and which
#   are unprotected — as a compliance artifact and a gap analysis for
#   security operations.
#
# USAGE
#   ./report-defender-coverage.sh [-o report.csv]

set -uo pipefail

OUTPUT_PATH="./defender-coverage_$(date +%Y%m%d_%H%M%S).csv"
while getopts "o:" opt; do
  case "$opt" in
    o) OUTPUT_PATH="$OPTARG" ;;
    *) echo "Usage: $0 [-o report.csv]" >&2; exit 2 ;;
  esac
done

if ! az account show &>/dev/null; then
  echo "[ERROR] Not logged in." >&2; exit 2
fi

echo "Fetching Defender for Cloud plan status..."

az security pricing list \
  --query "[].{name: name, pricingTier: pricingTier, subPlan: subPlan, extensions: extensions}" \
  --output json 2>/dev/null | python3 -c "
import json, sys

plans = json.load(sys.stdin)

print('ResourceType,PricingTier,SubPlan,IsEnabled,ExtensionCount,Flag')
for plan in plans:
    name = plan.get('name', '')
    tier = plan.get('pricingTier', 'Free')
    sub_plan = plan.get('subPlan') or 'N/A'
    extensions = plan.get('extensions') or []
    enabled = tier != 'Free'
    ext_count = len(extensions)

    # Flag specific resource types where being on Free tier is a
    # meaningful security gap vs. types where Standard tier adds
    # limited real-world value (e.g. DNS is generally lower priority
    # than VirtualMachines or KeyVaults)
    high_priority_types = {
        'VirtualMachines', 'SqlServers', 'SqlServerVirtualMachines',
        'StorageAccounts', 'KeyVaults', 'Arm', 'Containers'
    }
    is_high_priority = name in high_priority_types

    if not enabled and is_high_priority:
        flag = 'NOT_ENABLED_HIGH_PRIORITY'
    elif not enabled:
        flag = 'NOT_ENABLED'
    else:
        flag = 'ok'

    print(f'{name},{tier},{sub_plan},{enabled},{ext_count},{flag}')
" > "$OUTPUT_PATH"

UNPROTECTED=$(awk -F, 'NR>1 && $6!="ok"' "$OUTPUT_PATH" | wc -l)
HIGH_PRIORITY_UNPROTECTED=$(awk -F, 'NR>1 && $6=="NOT_ENABLED_HIGH_PRIORITY"' "$OUTPUT_PATH" | wc -l)

echo ""
echo "Defender coverage: ${HIGH_PRIORITY_UNPROTECTED} high-priority resource type(s) on Free tier, ${UNPROTECTED} total without Standard protection."
echo "Report written to: $OUTPUT_PATH"
[[ "$HIGH_PRIORITY_UNPROTECTED" -gt 0 ]] && exit 1 || exit 0
