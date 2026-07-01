#!/usr/bin/env bash
#
# backup-dr/audit-backup-coverage.sh
#
# SYNOPSIS
#   Identifies VMs NOT enrolled in any Recovery Services vault backup
#   policy, and reports the last backup status for those that are
#   enrolled — answering "which VMs would we lose in a ransomware event
#   right now."
#
# USAGE
#   ./audit-backup-coverage.sh [-o report.csv]

set -uo pipefail

OUTPUT_PATH="./backup-coverage_$(date +%Y%m%d_%H%M%S).csv"
while getopts "o:" opt; do
  case "$opt" in
    o) OUTPUT_PATH="$OPTARG" ;;
    *) echo "Usage: $0 [-o report.csv]" >&2; exit 2 ;;
  esac
done

if ! az account show &>/dev/null; then
  echo "[ERROR] Not logged in." >&2; exit 2
fi

echo "Fetching all VMs..."
ALL_VMS=$(az vm list --query "[].{id: id, name: name, resourceGroup: resourceGroup}" --output json 2>/dev/null)
VM_COUNT=$(echo "$ALL_VMS" | python3 -c "import json,sys; print(len(json.load(sys.stdin)))")
echo "Found ${VM_COUNT} VM(s). Checking backup enrollment..."

{
  echo "VMName,ResourceGroup,BackupEnrolled,LastBackupStatus,LastBackupTime,VaultName,Flag"

  echo "$ALL_VMS" | python3 -c "
import json, sys, subprocess

vms = json.load(sys.stdin)

# Get all backup protected items across all RSVs — more efficient than
# querying per-VM, since a single API call covers all vaults.
try:
    items_result = subprocess.run(
        ['az', 'backup', 'protected-item', 'list', '--backup-management-type', 'AzureIaasVM',
         '--query', '[].{friendlyName: properties.friendlyName, lastBackupStatus: properties.lastBackupStatus, lastBackupTime: properties.lastBackupTime, vaultName: vaultName, resourceGroup: resourceGroup}',
         '--output', 'json'],
        capture_output=True, text=True, timeout=60
    )
    backup_items = json.loads(items_result.stdout) if items_result.returncode == 0 else []
except Exception:
    backup_items = []

# Index by VM name for O(1) lookup
backup_index = {item['friendlyName'].lower(): item for item in backup_items}

for vm in vms:
    name = vm.get('name', '')
    rg = vm.get('resourceGroup', '')

    backup_info = backup_index.get(name.lower())
    if backup_info:
        last_status = backup_info.get('lastBackupStatus', 'Unknown')
        last_time = backup_info.get('lastBackupTime', 'Unknown')
        vault = backup_info.get('vaultName', 'Unknown')
        enrolled = True
        flag = 'ok' if last_status == 'Completed' else 'BACKUP_FAILING'
    else:
        last_status = 'N/A'
        last_time = 'N/A'
        vault = 'N/A'
        enrolled = False
        flag = 'NOT_ENROLLED'

    print(f'{name},{rg},{enrolled},{last_status},{last_time},{vault},{flag}')
"
} > "$OUTPUT_PATH"

NOT_ENROLLED=$(awk -F, 'NR>1 && $7=="NOT_ENROLLED"' "$OUTPUT_PATH" | wc -l)
FAILING=$(awk -F, 'NR>1 && $7=="BACKUP_FAILING"' "$OUTPUT_PATH" | wc -l)

echo ""
echo "Backup coverage: ${NOT_ENROLLED} VM(s) NOT enrolled, ${FAILING} VM(s) with failing backup jobs."
echo "Report written to: $OUTPUT_PATH"
[[ "$((NOT_ENROLLED + FAILING))" -gt 0 ]] && exit 1 || exit 0
