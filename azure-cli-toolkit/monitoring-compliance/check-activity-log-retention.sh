#!/usr/bin/env bash
#
# monitoring-compliance/check-activity-log-retention.sh
#
# SYNOPSIS
#   Verifies the Azure Activity Log is retained for at least the
#   minimum required period (default: 90 days) and that a diagnostic
#   setting is forwarding it to a Log Analytics workspace — the
#   Activity Log is the audit trail for all control-plane operations
#   in a subscription, and losing it means losing evidence of any
#   configuration changes made during or before a security incident.
#
# DESCRIPTION
#   Azure retains the Activity Log for 90 days natively. Most compliance
#   frameworks (PCI-DSS, ISO 27001, HIPAA) require 12 months. The gap
#   is closed by forwarding the Activity Log to a Log Analytics workspace
#   (where retention is configurable up to 2 years) or a Storage Account
#   (essentially unlimited). This script checks both whether forwarding
#   is configured AND whether the destination workspace's retention meets
#   the minimum, not just whether a diagnostic setting exists.
#
# USAGE
#   ./check-activity-log-retention.sh [-m min_days] [-o report.csv]

set -uo pipefail

MIN_RETENTION_DAYS=90
OUTPUT_PATH="./activity-log-retention_$(date +%Y%m%d_%H%M%S).csv"

while getopts "m:o:" opt; do
  case "$opt" in
    m) MIN_RETENTION_DAYS="$OPTARG" ;;
    o) OUTPUT_PATH="$OPTARG" ;;
    *) echo "Usage: $0 [-m min_retention_days] [-o report.csv]" >&2; exit 2 ;;
  esac
done

if ! az account show &>/dev/null; then
  echo "[ERROR] Not logged in." >&2; exit 2
fi

SUBSCRIPTION_ID=$(az account show --query id -o tsv)
echo "Checking Activity Log configuration for subscription: $SUBSCRIPTION_ID"

{
  echo "Check,Status,Detail,Flag"

  # ---- Check 1: Are diagnostic settings forwarding the Activity Log? ----
  DIAG_SETTINGS=$(az monitor diagnostic-settings subscription list \
    --subscription "$SUBSCRIPTION_ID" \
    --output json 2>/dev/null)

  DIAG_COUNT=$(echo "$DIAG_SETTINGS" | python3 -c "import json,sys; print(len(json.load(sys.stdin)))" 2>/dev/null || echo 0)

  if [[ "$DIAG_COUNT" -gt 0 ]]; then
    WORKSPACE_ID=$(echo "$DIAG_SETTINGS" | python3 -c "
import json, sys
settings = json.load(sys.stdin)
workspaces = [s.get('workspaceId','') for s in settings if s.get('workspaceId')]
print(workspaces[0] if workspaces else '')
")
    echo "ActivityLogDiagnosticSetting,configured,${DIAG_COUNT} setting(s) — workspace: ${WORKSPACE_ID:-none},ok"

    # ---- Check 2: Does the target workspace retain for long enough? ----
    if [[ -n "$WORKSPACE_ID" ]]; then
      WS_RETENTION=$(az monitor log-analytics workspace show \
        --ids "$WORKSPACE_ID" \
        --query retentionInDays \
        --output tsv 2>/dev/null)

      if [[ -n "$WS_RETENTION" ]]; then
        if [[ "$WS_RETENTION" -ge "$MIN_RETENTION_DAYS" ]]; then
          echo "WorkspaceRetention,sufficient,${WS_RETENTION} days (>= required ${MIN_RETENTION_DAYS}),ok"
        else
          echo "WorkspaceRetention,insufficient,${WS_RETENTION} days (< required ${MIN_RETENTION_DAYS}),BELOW_MINIMUM"
        fi
      else
        echo "WorkspaceRetention,unknown,Could not retrieve retention config,REVIEW"
      fi
    fi
  else
    echo "ActivityLogDiagnosticSetting,NOT_CONFIGURED,No diagnostic settings forwarding Activity Log to any destination,MISSING"
    echo "WorkspaceRetention,N/A,No diagnostic setting to check,N/A"
  fi

  # ---- Check 3: Are any log profile (legacy) or alert rules in place? ----
  # Log profiles are the old (deprecated) mechanism for activity log
  # retention — worth flagging if still in use since they should be
  # migrated to diagnostic settings.
  LOG_PROFILES=$(az monitor log-profiles list \
    --query "[].{name: name, retentionDays: retentionPolicy.days}" \
    --output json 2>/dev/null)
  PROFILE_COUNT=$(echo "$LOG_PROFILES" | python3 -c "import json,sys; print(len(json.load(sys.stdin)))" 2>/dev/null || echo 0)

  if [[ "$PROFILE_COUNT" -gt 0 ]]; then
    echo "LegacyLogProfile,present,${PROFILE_COUNT} legacy log profile(s) found — consider migrating to diagnostic settings,REVIEW_MIGRATION"
  else
    echo "LegacyLogProfile,not_present,No legacy log profiles (correct for modern deployments),ok"
  fi

} > "$OUTPUT_PATH"

FAILED=$(awk -F, 'NR>1 && $4!="ok" && $4!="N/A"' "$OUTPUT_PATH" | wc -l)

echo ""
echo "Activity log retention check: ${FAILED} issue(s) found."
echo "Report written to: $OUTPUT_PATH"
[[ "$FAILED" -gt 0 ]] && exit 1 || exit 0
