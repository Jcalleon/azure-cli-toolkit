#!/usr/bin/env bash
#
# identity-rbac/audit-stale-service-principals.sh
#
# SYNOPSIS
#   Audits Entra ID (Azure AD) service principals for staleness: SPs
#   with no credentials at all, credentials that expired without being
#   rotated, and SPs with no sign-in activity within a configurable
#   window — the Azure equivalent of audit-stale-accounts.sh in
#   bash-ops-toolkit, for non-human identities instead of local users.
#
# DESCRIPTION
#   Service principals accumulate the same way local accounts do:
#   a project ends, nobody deprovisions the SP, and it sits there
#   indefinitely with whatever role assignments it was given for that
#   project. Unlike a stale human account, a forgotten SP with
#   Contributor role on a subscription is a persistent pivot path for
#   anyone who finds a leaked credential for it, and "we don't know
#   which SPs are actually still in use" is a gap that shows up in
#   almost every cloud security review.
#
#   Reads sign-in data from the Entra ID audit log (requires
#   AuditLog.Read.All on the signed-in account or service principal),
#   flags SPs with no recorded sign-in in the window, and cross-
#   references their current role assignments so the output answers
#   "is this stale AND does it matter" rather than just a flat list.
#
# USAGE
#   ./audit-stale-service-principals.sh [-d inactive_days] [-o report.csv]
#
# REQUIREMENTS
#   az cli, signed in with AuditLog.Read.All + Directory.Read.All

set -uo pipefail

INACTIVE_DAYS=90
OUTPUT_PATH="./stale-sp-audit_$(date +%Y%m%d_%H%M%S).csv"

while getopts "d:o:" opt; do
  case "$opt" in
    d) INACTIVE_DAYS="$OPTARG" ;;
    o) OUTPUT_PATH="$OPTARG" ;;
    *) echo "Usage: $0 [-d inactive_days] [-o report.csv]" >&2; exit 2 ;;
  esac
done

if ! az account show &>/dev/null; then
  echo "[ERROR] Not logged in to Azure CLI. Run 'az login' first." >&2
  exit 2
fi

CUTOFF_DATE=$(date -d "-${INACTIVE_DAYS} days" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
  || date -v-"${INACTIVE_DAYS}"d +%Y-%m-%dT%H:%M:%SZ)

echo "Scanning service principals for inactivity since ${CUTOFF_DATE}..."

# Fetch all service principals, excluding Microsoft-published first-
# party apps (the ones with an appOwnerOrganizationId matching
# Microsoft's tenant ID) since those aren't customer-managed and
# "stale" is not a meaningful signal for them.
ALL_SPS=$(az ad sp list --all --query \
  "[?servicePrincipalType=='Application' && appOwnerOrganizationId!='f8cdef31-a31e-4b4a-93e4-5f571e91255a'].{
    id: id,
    appId: appId,
    displayName: displayName,
    createdDateTime: createdDateTime,
    keyCredentials: keyCredentials,
    passwordCredentials: passwordCredentials
  }" \
  --output json 2>/dev/null)

if [[ -z "$ALL_SPS" || "$ALL_SPS" == "[]" ]]; then
  echo "No non-Microsoft service principals found in this tenant."
  exit 0
fi

SP_COUNT=$(echo "$ALL_SPS" | python3 -c "import json,sys; print(len(json.load(sys.stdin)))")
echo "Found ${SP_COUNT} service principal(s) to evaluate."

{
  echo "DisplayName,AppId,ObjectId,LastSignIn,DaysInactive,HasCredentials,ExpiredCredentials,RoleAssignments,Flag"

  echo "$ALL_SPS" | python3 -c "
import json, sys, subprocess, datetime

sps = json.load(sys.stdin)
cutoff = datetime.datetime.fromisoformat('${CUTOFF_DATE}'.replace('Z', '+00:00'))
now = datetime.datetime.now(datetime.timezone.utc)

for sp in sps:
    app_id = sp.get('appId', '')
    obj_id = sp.get('id', '')
    display_name = sp.get('displayName', '').replace(',', ';')

    # Check sign-in activity via signInActivity endpoint.
    # Falls back to 'unknown' if the tenant's license tier doesn't
    # expose sign-in activity data (requires P1/P2 or equivalent).
    try:
        signin_result = subprocess.run(
            ['az', 'rest', '--method', 'GET',
             '--url', f'https://graph.microsoft.com/v1.0/servicePrincipals/{obj_id}/signInActivity'],
            capture_output=True, text=True, timeout=15
        )
        if signin_result.returncode == 0:
            signin_data = json.loads(signin_result.stdout)
            last_signin_str = signin_data.get('lastSignInDateTime')
        else:
            last_signin_str = None
    except Exception:
        last_signin_str = None

    if last_signin_str:
        last_signin = datetime.datetime.fromisoformat(last_signin_str.replace('Z', '+00:00'))
        days_inactive = (now - last_signin).days
        is_stale = last_signin < cutoff
    else:
        last_signin_str = 'never_or_unknown'
        days_inactive = -1
        is_stale = True  # treat unknown sign-in history as potentially stale

    # Credential check: does this SP have any credentials at all,
    # and are any of them already expired?
    key_creds = sp.get('keyCredentials', []) or []
    pass_creds = sp.get('passwordCredentials', []) or []
    all_creds = key_creds + pass_creds
    has_credentials = len(all_creds) > 0

    expired_count = 0
    for cred in all_creds:
        end_date_str = cred.get('endDateTime') or cred.get('endDate', '')
        if end_date_str:
            try:
                end_date = datetime.datetime.fromisoformat(end_date_str.replace('Z', '+00:00'))
                if end_date < now:
                    expired_count += 1
            except ValueError:
                pass

    # Role assignment scope — only fetches roles if the SP is actually
    # flagged as stale, to avoid burning API quota on active SPs just
    # to confirm they have roles, which is expected.
    role_summary = 'not_checked'
    if is_stale:
        try:
            role_result = subprocess.run(
                ['az', 'role', 'assignment', 'list', '--assignee', app_id,
                 '--all', '--query', '[].{role: roleDefinitionName, scope: scope}', '--output', 'json'],
                capture_output=True, text=True, timeout=20
            )
            if role_result.returncode == 0:
                roles = json.loads(role_result.stdout)
                role_summary = f'{len(roles)}_assignments' if roles else 'none'
            else:
                role_summary = 'lookup_failed'
        except Exception:
            role_summary = 'lookup_failed'

    flag = 'STALE' if is_stale else 'ok'
    if is_stale and not has_credentials:
        flag = 'STALE_NO_CREDS'
    if expired_count > 0 and is_stale:
        flag = f'STALE_EXPIRED_CREDS({expired_count})'

    print(f'{display_name},{app_id},{obj_id},{last_signin_str},{days_inactive},{has_credentials},{expired_count},{role_summary},{flag}')
"
} > "$OUTPUT_PATH"

STALE_COUNT=$(awk -F, 'NR>1 && $9!="ok"' "$OUTPUT_PATH" | wc -l)
echo ""
echo "Stale SP audit complete: ${STALE_COUNT} stale/flagged service principal(s) of ${SP_COUNT} scanned."
echo "Report written to: $OUTPUT_PATH"

[[ "$STALE_COUNT" -gt 0 ]] && exit 1 || exit 0
