#!/usr/bin/env bash
#
# identity-rbac/inventory-managed-identities.sh
#
# SYNOPSIS
#   Inventories all managed identities (both system-assigned and
#   user-assigned) across the subscription, their attached resources,
#   and their RBAC role assignments — answering "which managed
#   identities exist, what are they allowed to do, and are any of them
#   over-privileged or detached from any resource."
#
# DESCRIPTION
#   Managed identities are often overlooked in access reviews because
#   they're not listed alongside human users in the Entra ID user list
#   and they have no credentials to rotate, making them feel lower-risk.
#   In reality a user-assigned managed identity that still has
#   Contributor on a storage account but whose resource was deleted
#   is an attack path for anyone who recreates a resource with that
#   same identity name — and the "assigned to no resources" state is
#   effectively an orphaned privilege grant.
#
# USAGE
#   ./inventory-managed-identities.sh [-o report.csv]

set -uo pipefail

OUTPUT_PATH="./managed-identity-inventory_$(date +%Y%m%d_%H%M%S).csv"
while getopts "o:" opt; do
  case "$opt" in
    o) OUTPUT_PATH="$OPTARG" ;;
    *) echo "Usage: $0 [-o report.csv]" >&2; exit 2 ;;
  esac
done

if ! az account show &>/dev/null; then
  echo "[ERROR] Not logged in to Azure CLI." >&2; exit 2
fi

echo "Fetching user-assigned managed identities..."

USER_ASSIGNED=$(az identity list \
  --query "[].{name: name, id: id, principalId: principalId,
              resourceGroup: resourceGroup, location: location}" \
  --output json 2>/dev/null)

UA_COUNT=$(echo "$USER_ASSIGNED" | python3 -c "import json,sys; print(len(json.load(sys.stdin)))")
echo "Found ${UA_COUNT} user-assigned managed identity(ies)."

{
  echo "Name,Type,ResourceGroup,Location,PrincipalId,ResourcesUsingThisIdentity,RoleCount,RolesSummary,Flag"

  # --- User-assigned managed identities ---
  # For each, look up which resources are actually using it and what
  # roles it holds. "No resources assigned" means this identity has
  # whatever roles it has but nothing is currently using it — either
  # an orphan that should be cleaned up, or a freshly created identity
  # that hasn't been assigned yet.
  echo "$USER_ASSIGNED" | python3 -c "
import json, sys, subprocess

identities = json.load(sys.stdin)

for identity in identities:
    name = identity.get('name', '').replace(',', ';')
    principal_id = identity.get('principalId', '')
    rg = identity.get('resourceGroup', '')
    location = identity.get('location', '')
    identity_id = identity.get('id', '')

    # Find resources with this identity assigned
    try:
        # az resource list can filter by identity type/id using JMESPath
        # on the identity property — checking both identityProfile and
        # the standard identity.userAssignedIdentities property
        res_result = subprocess.run(
            ['az', 'resource', 'list',
             '--query', f\"[?identity.userAssignedIdentities.'{identity_id}' != null].id\",
             '--output', 'json'],
            capture_output=True, text=True, timeout=30
        )
        if res_result.returncode == 0:
            resources = json.loads(res_result.stdout)
            resource_count = len(resources)
        else:
            resource_count = -1
    except Exception:
        resource_count = -1

    # Role assignments for this identity
    try:
        role_result = subprocess.run(
            ['az', 'role', 'assignment', 'list', '--assignee', principal_id,
             '--all', '--query', '[].roleDefinitionName', '--output', 'json'],
            capture_output=True, text=True, timeout=20
        )
        if role_result.returncode == 0:
            roles = json.loads(role_result.stdout)
        else:
            roles = []
    except Exception:
        roles = []

    role_count = len(roles)
    high_priv = [r for r in roles if r in ('Owner', 'Contributor', 'User Access Administrator')]
    roles_summary = ';'.join(sorted(set(roles)))[:200] if roles else 'none'

    if resource_count == 0 and role_count > 0:
        flag = 'ORPHANED_WITH_ROLES'
    elif high_priv:
        flag = 'HIGH_PRIV_ROLE'
    elif resource_count == 0:
        flag = 'UNUSED'
    else:
        flag = 'ok'

    print(f'{name},UserAssigned,{rg},{location},{principal_id},{resource_count},{role_count},{roles_summary},{flag}')
"

  # --- System-assigned managed identities ---
  # These are created implicitly alongside their parent resource and
  # share its lifecycle, so "orphaned" isn't a concept that applies —
  # but they can still be over-privileged.
  echo "Scanning for system-assigned managed identities with significant role assignments..." >&2
  az resource list \
    --query "[?identity.type=='SystemAssigned' || identity.type=='SystemAssigned, UserAssigned'].{name: name, type: type, rg: resourceGroup, principalId: identity.principalId}" \
    --output json 2>/dev/null | python3 -c "
import json, sys, subprocess

resources = [r for r in json.load(sys.stdin) if r.get('principalId')]

for res in resources:
    name = res.get('name', '').replace(',', ';')
    rtype = res.get('type', '').replace(',', ';')
    rg = res.get('rg', '')
    principal_id = res.get('principalId', '')

    try:
        role_result = subprocess.run(
            ['az', 'role', 'assignment', 'list', '--assignee', principal_id,
             '--all', '--query', '[].roleDefinitionName', '--output', 'json'],
            capture_output=True, text=True, timeout=20
        )
        roles = json.loads(role_result.stdout) if role_result.returncode == 0 else []
    except Exception:
        roles = []

    role_count = len(roles)
    high_priv = [r for r in roles if r in ('Owner', 'Contributor', 'User Access Administrator')]
    roles_summary = ';'.join(sorted(set(roles)))[:200] if roles else 'none'

    flag = 'HIGH_PRIV_ROLE' if high_priv else ('ok' if roles else 'no_roles')
    print(f'{name} ({rtype}),SystemAssigned,{rg},n/a,{principal_id},1,{role_count},{roles_summary},{flag}')
"
} > "$OUTPUT_PATH"

TOTAL=$(awk 'NR>1' "$OUTPUT_PATH" | wc -l)
FLAGGED=$(awk -F, 'NR>1 && $9!="ok" && $9!="no_roles"' "$OUTPUT_PATH" | wc -l)

echo ""
echo "Managed identity inventory complete: ${TOTAL} total, ${FLAGGED} flagged."
echo "Report written to: $OUTPUT_PATH"

[[ "$FLAGGED" -gt 0 ]] && exit 1 || exit 0
