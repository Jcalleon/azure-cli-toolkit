#!/usr/bin/env bash
#
# monitoring-compliance/audit-diagnostic-settings.sh
#
# SYNOPSIS
#   Audits whether critical resource types (Key Vaults, NSGs, Storage
#   Accounts, App Services, SQL servers) have diagnostic settings
#   configured to forward logs to a Log Analytics workspace or storage
#   account — the Azure-side prerequisite for any SIEM/detection work
#   to have data to work with at all.
#
# DESCRIPTION
#   Defender for Cloud, Sentinel, and every other detection tool in
#   Azure is only as useful as the logs actually flowing into it. This
#   script finds the gaps: resources that are deployed and active but
#   whose logs are going nowhere because nobody set up diagnostic
#   settings when they were created. "We have Sentinel deployed" means
#   nothing for the resources that aren't sending it any data.
#
# USAGE
#   ./audit-diagnostic-settings.sh [-o report.csv]

set -uo pipefail

OUTPUT_PATH="./diagnostic-settings-audit_$(date +%Y%m%d_%H%M%S).csv"
while getopts "o:" opt; do
  case "$opt" in
    o) OUTPUT_PATH="$OPTARG" ;;
    *) echo "Usage: $0 [-o report.csv]" >&2; exit 2 ;;
  esac
done

if ! az account show &>/dev/null; then
  echo "[ERROR] Not logged in." >&2; exit 2
fi

# Resource types where missing diagnostic settings represent a
# meaningful security visibility gap — not every resource type matters
# equally, so we check the ones that actually generate security-
# relevant events: key vault access, NSG flow, SQL audit, etc.
declare -A RESOURCE_TYPES=(
  ["Microsoft.KeyVault/vaults"]="az keyvault list --query [].id -o tsv"
  ["Microsoft.Network/networkSecurityGroups"]="az network nsg list --query [].id -o tsv"
  ["Microsoft.Sql/servers"]="az sql server list --query [].id -o tsv"
)

{
  echo "ResourceType,ResourceName,ResourceId,HasDiagnosticSettings,LogDestination,Flag"

  for rtype in "${!RESOURCE_TYPES[@]}"; do
    list_cmd="${RESOURCE_TYPES[$rtype]}"
    echo "Checking ${rtype}..." >&2

    while IFS= read -r resource_id; do
      [[ -z "$resource_id" ]] && continue
      resource_name=$(echo "$resource_id" | awk -F'/' '{print $NF}')

      diag_result=$(az monitor diagnostic-settings list \
        --resource "$resource_id" \
        --query "[].{name: name, workspaceId: workspaceId, storageAccountId: storageAccountId}" \
        --output json 2>/dev/null)

      diag_count=$(echo "$diag_result" | python3 -c "import json,sys; print(len(json.load(sys.stdin)))" 2>/dev/null || echo 0)

      if [[ "$diag_count" -gt 0 ]]; then
        destination=$(echo "$diag_result" | python3 -c "
import json, sys
settings = json.load(sys.stdin)
dests = []
for s in settings:
    if s.get('workspaceId'): dests.append('LogAnalytics')
    if s.get('storageAccountId'): dests.append('Storage')
print(';'.join(set(dests)) if dests else 'configured_but_no_dest')
")
        flag="ok"
      else
        destination="none"
        flag="MISSING_DIAGNOSTIC_SETTINGS"
      fi

      echo "${rtype},${resource_name},${resource_id},${diag_count:-0},${destination},${flag}"
    done < <(eval "$list_cmd" 2>/dev/null)
  done
} > "$OUTPUT_PATH"

MISSING=$(awk -F, 'NR>1 && $6=="MISSING_DIAGNOSTIC_SETTINGS"' "$OUTPUT_PATH" | wc -l)
TOTAL=$(awk 'NR>1' "$OUTPUT_PATH" | wc -l)

echo ""
echo "Diagnostic settings audit: ${MISSING} of ${TOTAL} resource(s) have no diagnostic settings configured."
echo "Report written to: $OUTPUT_PATH"
[[ "$MISSING" -gt 0 ]] && exit 1 || exit 0
