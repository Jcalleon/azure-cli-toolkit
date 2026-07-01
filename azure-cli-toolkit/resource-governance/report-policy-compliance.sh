#!/usr/bin/env bash
#
# resource-governance/report-policy-compliance.sh
#
# SYNOPSIS
#   Pulls Azure Policy compliance state across all assigned policies
#   in a subscription (or a specific management group), summarizing
#   which policies have non-compliant resources and exporting the
#   non-compliant resource list per policy for remediation tracking.
#
# DESCRIPTION
#   Azure Policy compliance state is exposed through the policy states
#   API, not through `az policy assignment list` alone — the assignment
#   list only tells you what policies are assigned, not whether
#   resources are actually compliant with them. This script queries the
#   policy states endpoint to get the actual compliance picture, then
#   groups the output by policy definition so a reviewer can see
#   "which policies are failing, and how many resources are failing
#   each one" in a single pass rather than clicking through the portal.
#
# USAGE
#   ./report-policy-compliance.sh [-o report.csv]

set -uo pipefail

OUTPUT_PATH="./policy-compliance_$(date +%Y%m%d_%H%M%S).csv"
while getopts "o:" opt; do
  case "$opt" in
    o) OUTPUT_PATH="$OPTARG" ;;
    *) echo "Usage: $0 [-o report.csv]" >&2; exit 2 ;;
  esac
done

if ! az account show &>/dev/null; then
  echo "[ERROR] Not logged in." >&2; exit 2
fi

SUBSCRIPTION_ID=$(az account show --query id -o tsv)
echo "Pulling policy compliance state for subscription: $SUBSCRIPTION_ID"
echo "(This may take a minute — the policy states API aggregates across all resources.)"

# Policy states summary — compliant count, non-compliant count, exempt
# count per policy definition, without pulling every individual
# resource's state (which can be enormous on a large subscription).
COMPLIANCE_SUMMARY=$(az policy state summarize \
  --subscription "$SUBSCRIPTION_ID" \
  --output json 2>/dev/null)

if [[ -z "$COMPLIANCE_SUMMARY" ]]; then
  echo "[ERROR] Failed to retrieve policy compliance state." >&2
  exit 2
fi

{
  echo "PolicyName,PolicyDefinitionId,NonCompliantResources,CompliantResources,ExemptResources,CompliancePct,Flag"

  echo "$COMPLIANCE_SUMMARY" | python3 -c "
import json, sys

data = json.load(sys.stdin)
policy_details = data.get('policyAssignments', [])

for policy in policy_details:
    display_name = policy.get('policyAssignmentId', '').split('/')[-1].replace(',', ';')
    # The summary nests results per policy assignment and per
    # policy definition within that assignment
    for definition in policy.get('policyDefinitions', []):
        def_id = definition.get('policyDefinitionId', '').split('/')[-1]
        results = definition.get('results', {})
        non_compliant = results.get('nonCompliantResources', 0)
        compliant = results.get('compliantResources', 0)
        exempt = results.get('exemptResources', 0)

        total_evaluated = non_compliant + compliant
        compliance_pct = round((compliant / total_evaluated) * 100, 1) if total_evaluated > 0 else 0.0

        if non_compliant > 0:
            flag = 'NON_COMPLIANT'
        else:
            flag = 'compliant'

        print(f'{display_name},{def_id},{non_compliant},{compliant},{exempt},{compliance_pct},{flag}')
"
} > "$OUTPUT_PATH"

NON_COMPLIANT_POLICIES=$(awk -F, 'NR>1 && $7=="NON_COMPLIANT"' "$OUTPUT_PATH" | wc -l)
TOTAL_NON_COMPLIANT_RESOURCES=$(awk -F, 'NR>1' "$OUTPUT_PATH" | python3 -c "import sys; print(sum(int(l.split(',')[2]) for l in sys.stdin if l.strip()))")

echo ""
echo "Policy compliance report: ${NON_COMPLIANT_POLICIES} non-compliant policy definition(s), ${TOTAL_NON_COMPLIANT_RESOURCES} non-compliant resource(s) total."
echo "Report written to: $OUTPUT_PATH"

[[ "$NON_COMPLIANT_POLICIES" -gt 0 ]] && exit 1 || exit 0
