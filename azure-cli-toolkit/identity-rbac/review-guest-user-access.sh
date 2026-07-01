#!/usr/bin/env bash
#
# identity-rbac/review-guest-user-access.sh
#
# SYNOPSIS
#   Inventories external (guest) users in the Entra ID tenant, their
#   Azure RBAC role assignments across all subscriptions, and flags
#   guests who have been inactive for longer than a configurable window
#   or who hold a privileged role — the cloud-identity equivalent of
#   "are contractors still active and are they still scoped correctly."
#
# DESCRIPTION
#   Guest accounts are the identity category most likely to be orphaned:
#   a vendor engagement ends, the vendor's user is never removed from
#   the tenant, and they retain whatever role assignments or group
#   memberships they had for the engagement. This script generates the
#   access review evidence most external auditors ask for ("show us
#   your periodic guest access review") as a structured CSV that can be
#   handed directly to a reviewer.
#
# USAGE
#   ./review-guest-user-access.sh [-d inactive_days] [-o report.csv]

set -uo pipefail

INACTIVE_DAYS=90
OUTPUT_PATH="./guest-access-review_$(date +%Y%m%d_%H%M%S).csv"

while getopts "d:o:" opt; do
  case "$opt" in
    d) INACTIVE_DAYS="$OPTARG" ;;
    o) OUTPUT_PATH="$OPTARG" ;;
    *) echo "Usage: $0 [-d inactive_days] [-o report.csv]" >&2; exit 2 ;;
  esac
done

if ! az account show &>/dev/null; then
  echo "[ERROR] Not logged in to Azure CLI." >&2; exit 2
fi

echo "Fetching guest users from Entra ID..."

GUESTS=$(az ad user list \
  --filter "userType eq 'Guest'" \
  --query "[].{id: id, displayName: displayName, userPrincipalName: userPrincipalName,
              signInActivity: signInActivity, createdDateTime: createdDateTime}" \
  --output json 2>/dev/null)

GUEST_COUNT=$(echo "$GUESTS" | python3 -c "import json,sys; print(len(json.load(sys.stdin)))")
echo "Found ${GUEST_COUNT} guest user(s)."

{
  echo "DisplayName,UPN,CreatedDate,LastSignIn,DaysInactive,AzureRoleCount,PrivilegedRoles,Flag"

  echo "$GUESTS" | python3 -c "
import json, sys, subprocess, datetime

guests = json.load(sys.stdin)
cutoff_days = ${INACTIVE_DAYS}
now = datetime.datetime.now(datetime.timezone.utc)
privileged_roles = {'Owner', 'Contributor', 'User Access Administrator'}

for guest in guests:
    obj_id = guest.get('id', '')
    display_name = guest.get('displayName', '').replace(',', ';')
    upn = guest.get('userPrincipalName', '')
    created = guest.get('createdDateTime', 'unknown')

    # Sign-in activity from the user object (available without P2
    # license, unlike the dedicated signInActivity endpoint)
    signin_info = guest.get('signInActivity') or {}
    last_signin = signin_info.get('lastSignInDateTime')
    if last_signin:
        last_signin_dt = datetime.datetime.fromisoformat(last_signin.replace('Z', '+00:00'))
        days_inactive = (now - last_signin_dt).days
    else:
        last_signin = 'never_or_unknown'
        days_inactive = -1

    # Azure RBAC assignments across all subscriptions
    try:
        role_result = subprocess.run(
            ['az', 'role', 'assignment', 'list', '--assignee', obj_id, '--all',
             '--query', '[].roleDefinitionName', '--output', 'json'],
            capture_output=True, text=True, timeout=20
        )
        if role_result.returncode == 0:
            roles = json.loads(role_result.stdout)
        else:
            roles = []
    except Exception:
        roles = []

    priv_assigned = [r for r in roles if r in privileged_roles]
    role_count = len(roles)

    # Flag logic: a guest with no recent sign-in AND a privileged role
    # is the highest-risk combination — dormant account with a powerful
    # role is the exact scenario threat actors look for in enumerating
    # a tenant for lateral movement paths.
    if days_inactive > cutoff_days or days_inactive == -1:
        if priv_assigned:
            flag = 'HIGH_RISK_STALE_PRIVILEGED'
        else:
            flag = 'STALE_GUEST'
    elif priv_assigned:
        flag = 'ACTIVE_PRIVILEGED_GUEST'
    else:
        flag = 'ok'

    priv_str = ';'.join(priv_assigned) if priv_assigned else 'none'
    print(f'{display_name},{upn},{created},{last_signin},{days_inactive},{role_count},{priv_str},{flag}')
"
} > "$OUTPUT_PATH"

FLAGGED=$(awk -F, 'NR>1 && $8!="ok"' "$OUTPUT_PATH" | wc -l)

echo ""
echo "Guest access review complete: ${FLAGGED} of ${GUEST_COUNT} guest(s) flagged."
echo "Report written to: $OUTPUT_PATH"

[[ "$FLAGGED" -gt 0 ]] && exit 1 || exit 0
