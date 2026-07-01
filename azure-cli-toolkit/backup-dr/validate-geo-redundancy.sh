#!/usr/bin/env bash
#
# backup-dr/validate-geo-redundancy.sh
#
# SYNOPSIS
#   Verifies that critical data resources (Storage Accounts, SQL
#   databases, Key Vaults) are configured for geo-redundant replication,
#   not just locally-redundant storage that would be lost in a regional
#   outage alongside the primary resources.
#
# USAGE
#   ./validate-geo-redundancy.sh [-o report.csv]

set -uo pipefail

OUTPUT_PATH="./geo-redundancy-audit_$(date +%Y%m%d_%H%M%S).csv"
while getopts "o:" opt; do
  case "$opt" in
    o) OUTPUT_PATH="$OPTARG" ;;
    *) echo "Usage: $0 [-o report.csv]" >&2; exit 2 ;;
  esac
done

if ! az account show &>/dev/null; then
  echo "[ERROR] Not logged in." >&2; exit 2
fi

{
  echo "ResourceType,Name,ResourceGroup,ReplicationConfig,IsGeoRedundant,Flag"

  # Storage accounts: LRS/ZRS = not geo-redundant, GRS/GZRS/RA-GRS/RA-GZRS = geo-redundant
  echo "Checking storage accounts..." >&2
  az storage account list \
    --query "[].{name: name, resourceGroup: resourceGroup, sku: sku.name}" \
    --output json 2>/dev/null | python3 -c "
import json, sys
accounts = json.load(sys.stdin)
geo_skus = {'GRS', 'RAGRS', 'GZRS', 'RAGZRS'}
for a in accounts:
    name = a.get('name', '')
    rg = a.get('resourceGroup', '')
    sku = a.get('sku', 'Unknown')
    is_geo = sku in geo_skus
    flag = 'ok' if is_geo else 'NOT_GEO_REDUNDANT'
    print(f'StorageAccount,{name},{rg},{sku},{is_geo},{flag}')
"

  # SQL: check if geo-replication or failover group is configured
  echo "Checking Azure SQL servers..." >&2
  az sql server list \
    --query "[].{name: name, resourceGroup: resourceGroup}" \
    --output json 2>/dev/null | python3 -c "
import json, sys, subprocess
servers = json.load(sys.stdin)
for s in servers:
    name = s.get('name', '')
    rg = s.get('resourceGroup', '')
    # Check for failover groups — the clearest DR signal for SQL
    fg_result = subprocess.run(
        ['az', 'sql', 'failover-group', 'list', '--server', name, '--resource-group', rg,
         '--query', 'length(@)', '--output', 'tsv'],
        capture_output=True, text=True, timeout=20
    )
    fg_count = int(fg_result.stdout.strip()) if fg_result.returncode == 0 and fg_result.stdout.strip().isdigit() else 0
    is_geo = fg_count > 0
    flag = 'ok' if is_geo else 'NO_FAILOVER_GROUP'
    print(f'SQLServer,{name},{rg},FailoverGroups:{fg_count},{is_geo},{flag}')
"

  # Key Vault: soft-delete + purge protection are the KV DR controls
  echo "Checking Key Vaults..." >&2
  az keyvault list \
    --query "[].{name: name, resourceGroup: resourceGroup, softDeleteEnabled: properties.enableSoftDelete, purgeProtection: properties.enablePurgeProtection}" \
    --output json 2>/dev/null | python3 -c "
import json, sys
vaults = json.load(sys.stdin)
for v in vaults:
    name = v.get('name', '')
    rg = v.get('resourceGroup', '')
    soft_delete = bool(v.get('softDeleteEnabled', True))  # enabled by default since 2020
    purge_protect = bool(v.get('purgeProtection', False))
    is_protected = soft_delete and purge_protect
    config = f'SoftDelete:{soft_delete},PurgeProtection:{purge_protect}'
    flag = 'ok' if is_protected else 'MISSING_PURGE_PROTECTION' if soft_delete else 'MISSING_SOFT_DELETE'
    print(f'KeyVault,{name},{rg},{config},{is_protected},{flag}')
"
} > "$OUTPUT_PATH"

NOT_GEO=$(awk -F, 'NR>1 && $6!="ok"' "$OUTPUT_PATH" | wc -l)
echo ""
echo "Geo-redundancy check complete: ${NOT_GEO} resource(s) not fully geo-redundant/protected."
echo "Report written to: $OUTPUT_PATH"
[[ "$NOT_GEO" -gt 0 ]] && exit 1 || exit 0
