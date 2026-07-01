#!/usr/bin/env bash
#
# network-security/check-private-endpoint-compliance.sh
#
# SYNOPSIS
#   Checks Key Vaults, Storage Accounts, and SQL servers for private
#   endpoint compliance: do they have a private endpoint deployed, and
#   critically, is public network access actually disabled rather than
#   just having a private endpoint added alongside continued public
#   access.
#
# DESCRIPTION
#   Adding a private endpoint to a resource without disabling public
#   access is a common misconfiguration that provides almost none of
#   the security benefit of private connectivity — the resource is
#   reachable from the private endpoint as intended, but it's ALSO
#   still reachable from the public internet unless the
#   publicNetworkAccess property is explicitly set to Disabled. This
#   script checks both conditions, since a resource that has a private
#   endpoint deployed but still has publicNetworkAccess=Enabled is
#   often worse from a compliance standpoint than one with no private
#   endpoint at all, because it creates false confidence.
#
# USAGE
#   ./check-private-endpoint-compliance.sh [-o report.csv]

set -uo pipefail

OUTPUT_PATH="./private-endpoint-compliance_$(date +%Y%m%d_%H%M%S).csv"
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
  echo "ResourceType,Name,ResourceGroup,HasPrivateEndpoint,PublicAccessEnabled,Flag,Reason"

  # ---- Key Vaults ----
  echo "Checking Key Vaults..." >&2
  az keyvault list \
    --query "[].{name: name, resourceGroup: resourceGroup, publicNetworkAccess: properties.publicNetworkAccess, privateEndpointConnections: properties.privateEndpointConnections}" \
    --output json 2>/dev/null | python3 -c "
import json, sys

vaults = json.load(sys.stdin)
for v in vaults:
    name = v.get('name', '').replace(',', ';')
    rg = v.get('resourceGroup', '')
    # publicNetworkAccess can be 'Enabled', 'Disabled', or null (defaults to Enabled)
    public_access = (v.get('publicNetworkAccess') or 'Enabled') == 'Enabled'
    pecs = v.get('privateEndpointConnections') or []
    has_pe = len(pecs) > 0

    if has_pe and not public_access:
        flag, reason = 'ok', 'Private endpoint configured and public access disabled'
    elif has_pe and public_access:
        flag, reason = 'MISCONFIGURED', 'Has private endpoint but public access is STILL ENABLED — private endpoint provides no protection'
    elif not has_pe and not public_access:
        flag, reason = 'REVIEW', 'Public access disabled but no private endpoint — verify connectivity exists'
    else:
        flag, reason = 'MISSING_PE', 'No private endpoint — Key Vault accessible from public internet'

    print(f'KeyVault,{name},{rg},{has_pe},{public_access},{flag},{reason}')
"

  # ---- Storage Accounts ----
  echo "Checking Storage Accounts..." >&2
  az storage account list \
    --query "[].{name: name, resourceGroup: resourceGroup, publicNetworkAccess: publicNetworkAccess, allowBlobPublicAccess: allowBlobPublicAccess, privateEndpointConnections: privateEndpointConnections}" \
    --output json 2>/dev/null | python3 -c "
import json, sys

accounts = json.load(sys.stdin)
for a in accounts:
    name = a.get('name', '').replace(',', ';')
    rg = a.get('resourceGroup', '')
    public_access = (a.get('publicNetworkAccess') or 'Enabled') == 'Enabled'
    blob_public = a.get('allowBlobPublicAccess', False)
    pecs = a.get('privateEndpointConnections') or []
    has_pe = len(pecs) > 0

    if has_pe and not public_access and not blob_public:
        flag, reason = 'ok', 'Private endpoint configured, public access and blob public access disabled'
    elif has_pe and public_access:
        flag, reason = 'MISCONFIGURED', 'Has private endpoint but public network access still enabled'
    elif blob_public:
        flag, reason = 'HIGH', 'Anonymous blob public access is enabled'
    else:
        flag, reason = 'REVIEW', 'No private endpoint configured'

    print(f'StorageAccount,{name},{rg},{has_pe},{public_access},{flag},{reason}')
"

  # ---- Azure SQL Servers ----
  echo "Checking SQL Servers..." >&2
  az sql server list \
    --query "[].{name: name, resourceGroup: resourceGroup, publicNetworkAccess: publicNetworkAccess, privateEndpointConnections: privateEndpointConnections}" \
    --output json 2>/dev/null | python3 -c "
import json, sys

servers = json.load(sys.stdin)
for s in servers:
    name = s.get('name', '').replace(',', ';')
    rg = s.get('resourceGroup', '')
    public_access = (s.get('publicNetworkAccess') or 'Enabled') == 'Enabled'
    pecs = s.get('privateEndpointConnections') or []
    has_pe = len(pecs) > 0

    if has_pe and not public_access:
        flag, reason = 'ok', 'Private endpoint configured and public access disabled'
    elif has_pe and public_access:
        flag, reason = 'MISCONFIGURED', 'Has private endpoint but publicNetworkAccess is still Enabled'
    else:
        flag, reason = 'MISSING_PE', 'SQL Server has no private endpoint — accessible from public internet'

    print(f'SQLServer,{name},{rg},{has_pe},{public_access},{flag},{reason}')
"
} > "$OUTPUT_PATH"

CRITICAL=$(awk -F, 'NR>1 && ($6=="MISCONFIGURED" || $6=="HIGH")' "$OUTPUT_PATH" | wc -l)
MISSING=$(awk -F, 'NR>1 && $6=="MISSING_PE"' "$OUTPUT_PATH" | wc -l)

echo ""
echo "Private endpoint compliance check complete: ${CRITICAL} misconfigured, ${MISSING} without private endpoints."
echo "Report written to: $OUTPUT_PATH"

[[ "$((CRITICAL + MISSING))" -gt 0 ]] && exit 1 || exit 0
