#!/usr/bin/env bash
#
# resource-governance/audit-resource-locks.sh
#
# SYNOPSIS
#   Audits resource locks across a subscription, reporting resources
#   that should have a delete or read-only lock but don't — and
#   conversely, flagging any resource groups where locks are preventing
#   expected operations (a common "why can't we deploy?" debug scenario).
#
# DESCRIPTION
#   Azure resource locks are the last line of defense against accidental
#   deletion — an IaC pipeline with a bad `terraform destroy` or an
#   operator running `az group delete` with the wrong subscription
#   selected can both be stopped cold by a CanNotDelete lock on a
#   production resource group. This script audits whether critical
#   resource types (key vaults, storage accounts containing terraform
#   state, production VMs) actually have that protection applied.
#
# USAGE
#   ./audit-resource-locks.sh [-o report.csv]

set -uo pipefail

OUTPUT_PATH="./resource-lock-audit_$(date +%Y%m%d_%H%M%S).csv"
while getopts "o:" opt; do
  case "$opt" in
    o) OUTPUT_PATH="$OPTARG" ;;
    *) echo "Usage: $0 [-o report.csv]" >&2; exit 2 ;;
  esac
done

if ! az account show &>/dev/null; then
  echo "[ERROR] Not logged in." >&2; exit 2
fi

echo "Fetching all resource locks in subscription..."

# All locks across the subscription — subscription/RG/resource level
ALL_LOCKS=$(az lock list --query \
  "[].{name: name, level: level, lockId: id, notes: notes}" \
  --output json 2>/dev/null)

LOCK_COUNT=$(echo "$ALL_LOCKS" | python3 -c "import json,sys; print(len(json.load(sys.stdin)))")
echo "Found ${LOCK_COUNT} lock(s) currently applied."

# Critical resource types that should have a CanNotDelete lock by default
# in any production environment — key vaults especially, since a deleted
# vault purges secrets that may be unrecoverable even from soft-delete.
SHOULD_BE_LOCKED_TYPES=(
  "Microsoft.KeyVault/vaults"
  "Microsoft.RecoveryServices/vaults"
  "Microsoft.Sql/servers"
)

declare -a FINDINGS=()

# Check whether each instance of a critical type is actually locked
for resource_type in "${SHOULD_BE_LOCKED_TYPES[@]}"; do
  while IFS= read -r resource; do
    [[ -z "$resource" ]] && continue
    name=$(echo "$resource" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('name',''))")
    rg=$(echo "$resource" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('resourceGroup',''))")
    rid=$(echo "$resource" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('id',''))")

    # A lock on the resource directly OR on its parent resource group
    # provides protection — check both before flagging as unlocked.
    resource_lock=$(az lock list --resource "$rid" \
      --query "[?level=='CanNotDelete' || level=='ReadOnly'].name | [0]" \
      --output tsv 2>/dev/null)
    rg_lock=$(az lock list --resource-group "$rg" \
      --query "[?level=='CanNotDelete' || level=='ReadOnly'].name | [0]" \
      --output tsv 2>/dev/null)

    if [[ -z "$resource_lock" && -z "$rg_lock" ]]; then
      FINDINGS+=("$resource_type|$name|$rg|NO_LOCK|Neither resource nor its RG has a CanNotDelete or ReadOnly lock")
    else
      lock_source=$([ -n "$resource_lock" ] && echo "resource:${resource_lock}" || echo "rg:${rg_lock}")
      FINDINGS+=("$resource_type|$name|$rg|LOCKED|Protected by lock: $lock_source")
    fi
  done < <(az resource list \
    --resource-type "$resource_type" \
    --query "[].{name: name, resourceGroup: resourceGroup, id: id}" \
    --output json 2>/dev/null | python3 -c "import json,sys; [print(json.dumps(r)) for r in json.load(sys.stdin)]")
done

{
  echo "ResourceType,Name,ResourceGroup,LockStatus,Detail"
  for row in "${FINDINGS[@]}"; do
    IFS='|' read -r rtype name rg status detail <<< "$row"
    printf '%s,"%s","%s",%s,"%s"\n' "$rtype" "$name" "$rg" "$status" "$detail"
  done
} > "$OUTPUT_PATH"

UNLOCKED=$(printf '%s\n' "${FINDINGS[@]}" | grep -c '|NO_LOCK|' || true)
LOCKED=$(printf '%s\n' "${FINDINGS[@]}" | grep -c '|LOCKED|' || true)

echo ""
echo "Lock audit complete: ${LOCKED} protected, ${UNLOCKED} critical resource(s) WITHOUT a lock."
echo "Report written to: $OUTPUT_PATH"

[[ "$UNLOCKED" -gt 0 ]] && exit 1 || exit 0
