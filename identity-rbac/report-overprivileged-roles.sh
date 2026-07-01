#!/usr/bin/env bash
#
# identity-rbac/report-overprivileged-roles.sh
#
# SYNOPSIS
#   Reports role assignments where the scope is broader than necessary:
#   Owner/Contributor/User Access Administrator at subscription scope,
#   assignments to groups where individual user grants would be more
#   auditable, and any use of the wildcard-equivalent legacy
#   "classic" administrator roles that predate Azure RBAC.
#
# DESCRIPTION
#   Azure's "default-closed" RBAC model is only as strong as the
#   principle of least privilege is actually applied to it — an
#   environment where every developer has Contributor at subscription
#   scope "because it's easier" is functionally open regardless of what
#   the tenant-level policies say. This script surfaces the specific
#   patterns that security reviews flag most consistently: high-
#   privilege roles at a scope where they give far more access than the
#   assigned purpose requires.
#
#   This is a report, not a remediation — it flags every potentially
#   over-privileged assignment and leaves the "is this actually
#   intentional" judgment to a human reviewer, since there are legitimate
#   reasons for some of these that only context can determine.
#
# USAGE
#   ./report-overprivileged-roles.sh [-s subscription_id] [-o report.csv]

set -uo pipefail

SUBSCRIPTION_ID=""
OUTPUT_PATH="./overprivileged-roles_$(date +%Y%m%d_%H%M%S).csv"

while getopts "s:o:" opt; do
  case "$opt" in
    s) SUBSCRIPTION_ID="$OPTARG" ;;
    o) OUTPUT_PATH="$OPTARG" ;;
    *) echo "Usage: $0 [-s subscription_id] [-o report.csv]" >&2; exit 2 ;;
  esac
done

if ! az account show &>/dev/null; then
  echo "[ERROR] Not logged in to Azure CLI." >&2; exit 2
fi

if [[ -n "$SUBSCRIPTION_ID" ]]; then
  az account set --subscription "$SUBSCRIPTION_ID"
fi

CURRENT_SUB=$(az account show --query id -o tsv)
SUB_SCOPE="/subscriptions/${CURRENT_SUB}"
echo "Scanning subscription: $CURRENT_SUB"

# High-privilege roles that are routinely over-assigned at broad scope —
# Owner and User Access Administrator both let the assignee grant ANY
# further permissions to anyone else, making them categorically
# different from Contributor even though Contributor is already powerful.
HIGH_PRIV_ROLES=("Owner" "Contributor" "User Access Administrator")

declare -a FINDINGS=()  # "principal|type|role|scope|flag|reason"

for role in "${HIGH_PRIV_ROLES[@]}"; do
  while IFS= read -r assignment; do
    principal=$(echo "$assignment" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('principalName','unknown'))")
    principal_type=$(echo "$assignment" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('principalType','unknown'))")
    scope=$(echo "$assignment" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('scope',''))")

    flag="REVIEW"
    reason=""

    # Subscription-scope assignments are the highest-risk pattern —
    # they grant the role across everything in the subscription
    if [[ "$scope" == "$SUB_SCOPE" ]]; then
      if [[ "$role" == "Owner" ]]; then
        flag="HIGH"
        reason="Owner at subscription scope — full control including IAM, data plane, and billing"
      elif [[ "$role" == "User Access Administrator" ]]; then
        flag="HIGH"
        reason="User Access Administrator at subscription scope — can grant any role to any identity"
      else
        flag="MEDIUM"
        reason="Contributor at subscription scope — consider restricting to specific RG or resource"
      fi
    fi

    # Group assignments are harder to audit than individual user grants
    # because the group membership can change without the role assignment
    # being visible as having changed — flagged separately, not failed
    if [[ "$principal_type" == "Group" ]]; then
      [[ "$flag" != "HIGH" ]] && flag="REVIEW"
      reason="${reason:+$reason; }Group assignment: membership changes are invisible in role assignment audit log"
    fi

    FINDINGS+=("$principal|$principal_type|$role|$scope|$flag|$reason")
  done < <(az role assignment list --scope "$SUB_SCOPE" --role "$role" --all \
    --query "[].{principalName: principalName, principalType: principalType, scope: scope}" \
    --output json 2>/dev/null | python3 -c "
import json, sys
assignments = json.load(sys.stdin)
for a in assignments:
    print(json.dumps(a))
")
done

# ---- Classic (legacy) administrator roles ----
# These predate RBAC entirely — Co-Administrator/Service Administrator
# are effectively Contributor/Owner-equivalent on the old portal model
# and should almost never appear in a modern subscription.
CLASSIC_ADMINS=$(az role assignment list --all \
  --query "[?roleDefinitionName=='ServiceAdministrator' || roleDefinitionName=='CoAdministrator'].{
    principalName: principalName, role: roleDefinitionName}" \
  --output json 2>/dev/null)

if [[ -n "$CLASSIC_ADMINS" && "$CLASSIC_ADMINS" != "[]" ]]; then
  while IFS= read -r admin; do
    principal=$(echo "$admin" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('principalName',''))")
    role=$(echo "$admin" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('role',''))")
    FINDINGS+=("$principal|LegacyAdministrator|$role|subscription|HIGH|Legacy classic administrator role — should be migrated to RBAC and removed")
  done < <(echo "$CLASSIC_ADMINS" | python3 -c "import json,sys; [print(json.dumps(a)) for a in json.load(sys.stdin)]")
fi

{
  echo "Principal,PrincipalType,Role,Scope,Flag,Reason"
  for row in "${FINDINGS[@]}"; do
    IFS='|' read -r principal ptype role scope flag reason <<< "$row"
    printf '"%s",%s,%s,"%s",%s,"%s"\n' "$principal" "$ptype" "$role" "$scope" "$flag" "$reason"
  done
} > "$OUTPUT_PATH"

HIGH_COUNT=$(printf '%s\n' "${FINDINGS[@]}" | grep -c '|HIGH|' || true)
MEDIUM_COUNT=$(printf '%s\n' "${FINDINGS[@]}" | grep -c '|MEDIUM|' || true)
REVIEW_COUNT=$(printf '%s\n' "${FINDINGS[@]}" | grep -c '|REVIEW|' || true)

echo ""
echo "Role assignment report complete: ${HIGH_COUNT} high, ${MEDIUM_COUNT} medium, ${REVIEW_COUNT} for review."
echo "Report written to: $OUTPUT_PATH"

[[ "$HIGH_COUNT" -gt 0 ]] && exit 1 || exit 0
