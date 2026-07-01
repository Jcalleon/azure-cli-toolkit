#!/usr/bin/env bash
#
# backup-dr/check-backup-policy-compliance.sh
#
# SYNOPSIS
#   Audits Azure Backup policies across all Recovery Services vaults
#   for compliance with minimum retention requirements: daily retain
#   >= N days, weekly retain >= N weeks, and whether instant restore
#   snapshots are configured for rapid recovery.
#
# USAGE
#   ./check-backup-policy-compliance.sh [-d min_daily_days] [-w min_weekly_weeks] [-o report.csv]

set -uo pipefail

MIN_DAILY_DAYS=30
MIN_WEEKLY_WEEKS=12
OUTPUT_PATH="./backup-policy-compliance_$(date +%Y%m%d_%H%M%S).csv"

while getopts "d:w:o:" opt; do
  case "$opt" in
    d) MIN_DAILY_DAYS="$OPTARG" ;;
    w) MIN_WEEKLY_WEEKS="$OPTARG" ;;
    o) OUTPUT_PATH="$OPTARG" ;;
    *) echo "Usage: $0 [-d min_daily_days] [-w min_weekly_weeks] [-o report.csv]" >&2; exit 2 ;;
  esac
done

if ! az account show &>/dev/null; then
  echo "[ERROR] Not logged in." >&2; exit 2
fi

echo "Fetching Recovery Services vaults..."
ALL_VAULTS=$(az backup vault list \
  --query "[].{name: name, resourceGroup: resourceGroup}" \
  --output json 2>/dev/null)

VAULT_COUNT=$(echo "$ALL_VAULTS" | python3 -c "import json,sys; print(len(json.load(sys.stdin)))")
echo "Found ${VAULT_COUNT} vault(s)."

{
  echo "VaultName,PolicyName,ScheduleFrequency,DailyRetentionDays,WeeklyRetentionWeeks,InstantRestoreEnabled,Flag,Reason"

  echo "$ALL_VAULTS" | python3 -c "
import json, sys, subprocess

vaults = json.load(sys.stdin)
min_daily = ${MIN_DAILY_DAYS}
min_weekly = ${MIN_WEEKLY_WEEKS}

for vault in vaults:
    vault_name = vault.get('name', '')
    rg = vault.get('resourceGroup', '')

    policies_result = subprocess.run(
        ['az', 'backup', 'policy', 'list', '--vault-name', vault_name, '--resource-group', rg,
         '--query', '[].{name: name, properties: properties}', '--output', 'json'],
        capture_output=True, text=True, timeout=30
    )
    if policies_result.returncode != 0:
        continue

    policies = json.loads(policies_result.stdout)
    for policy in policies:
        policy_name = policy.get('name', '')
        props = policy.get('properties', {})
        schedule = props.get('schedulePolicy', {})
        retention = props.get('retentionPolicy', {})

        freq = schedule.get('schedulePolicyType', 'Unknown').replace('SimpleSchedulePolicy', '').replace('Policy', '')

        daily_retention = retention.get('dailySchedule', {}).get('retentionDuration', {}).get('count', 0)
        weekly_retention = retention.get('weeklySchedule', {}).get('retentionDuration', {}).get('count', 0)
        instant_restore = props.get('instantRpDetails', {}).get('azureBackupRGNamePrefix') is not None

        flag = 'ok'
        reasons = []

        if daily_retention > 0 and daily_retention < min_daily:
            flag = 'NON_COMPLIANT'
            reasons.append(f'Daily retention {daily_retention}d < required {min_daily}d')

        if weekly_retention > 0 and weekly_retention < min_weekly:
            flag = 'NON_COMPLIANT'
            reasons.append(f'Weekly retention {weekly_retention}w < required {min_weekly}w')

        if not instant_restore:
            reasons.append('Instant restore snapshots not configured')
            if flag == 'ok':
                flag = 'REVIEW'

        reason = '; '.join(reasons) if reasons else 'meets requirements'
        print(f'{vault_name},{policy_name},{freq},{daily_retention},{weekly_retention},{instant_restore},{flag},{reason}')
"
} > "$OUTPUT_PATH"

NON_COMPLIANT=$(awk -F, 'NR>1 && $7=="NON_COMPLIANT"' "$OUTPUT_PATH" | wc -l)
echo ""
echo "Backup policy compliance: ${NON_COMPLIANT} policy(ies) below minimum retention requirements."
echo "Report written to: $OUTPUT_PATH"
[[ "$NON_COMPLIANT" -gt 0 ]] && exit 1 || exit 0
