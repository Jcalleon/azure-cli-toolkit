#!/usr/bin/env bash
#
# resource-governance/cleanup-candidate-resource-groups.sh
#
# SYNOPSIS
#   Identifies resource groups that are candidates for cleanup: empty
#   RGs, RGs tagged as temporary with a past expiry date, and RGs whose
#   name matches common dev/test/sandbox patterns with no recent
#   resource activity — flagging candidates for human review, NOT
#   deleting anything.
#
# DESCRIPTION
#   Dev/test/sandbox resource groups are where resource sprawl
#   accumulates fastest — someone spins up a POC environment, the POC
#   ends, and the RG sits there with a handful of resources (or none)
#   being billed indefinitely. This script surfaces the specific signals
#   that identify likely cleanup candidates without anything too
#   aggressive: an RG marked expires=<past date> in its tags is almost
#   certainly safe to review; an RG named "test-jacob-2024" with no
#   resources is a strong candidate; an empty RG in production with no
#   obvious name pattern should still be flagged but at lower priority.
#
# USAGE
#   ./cleanup-candidate-resource-groups.sh [-o report.csv]

set -uo pipefail

OUTPUT_PATH="./rg-cleanup-candidates_$(date +%Y%m%d_%H%M%S).csv"
while getopts "o:" opt; do
  case "$opt" in
    o) OUTPUT_PATH="$OPTARG" ;;
    *) echo "Usage: $0 [-o report.csv]" >&2; exit 2 ;;
  esac
done

if ! az account show &>/dev/null; then
  echo "[ERROR] Not logged in." >&2; exit 2
fi

echo "Scanning resource groups for cleanup candidates..."

ALL_RGS=$(az group list \
  --query "[].{name: name, location: location, tags: tags}" \
  --output json 2>/dev/null)

RG_COUNT=$(echo "$ALL_RGS" | python3 -c "import json,sys; print(len(json.load(sys.stdin)))")
echo "Found ${RG_COUNT} resource group(s)."

{
  echo "ResourceGroupName,Location,ResourceCount,Tags,Flag,Reason"

  echo "$ALL_RGS" | python3 -c "
import json, sys, subprocess, datetime, re

rgs = json.load(sys.stdin)
now = datetime.datetime.now(datetime.timezone.utc)

# Patterns that suggest a non-permanent, likely-temporary environment.
# Deliberately conservative — production/prod/prd name patterns are
# explicitly excluded even when they match other criteria, since
# a false positive on a production RG is categorically worse than
# missing a dev RG that should have been cleaned up.
TEMP_PATTERNS = re.compile(r'(test|dev|sandbox|poc|demo|temp|tmp|staging|stg|trial|lab|experiment)', re.IGNORECASE)
PROD_OVERRIDE = re.compile(r'(prod|prd|production)', re.IGNORECASE)

for rg in rgs:
    name = rg.get('name', '')
    location = rg.get('location', '')
    tags = rg.get('tags') or {}

    # Count resources inside this RG — empty RGs are always candidates
    try:
        res_result = subprocess.run(
            ['az', 'resource', 'list', '--resource-group', name,
             '--query', 'length(@)', '--output', 'tsv'],
            capture_output=True, text=True, timeout=20
        )
        resource_count = int(res_result.stdout.strip()) if res_result.returncode == 0 else -1
    except Exception:
        resource_count = -1

    tags_str = ';'.join(f'{k}={v}' for k, v in tags.items())
    flag = 'ok'
    reasons = []

    # Check explicit expiry tag
    expiry_str = tags.get('expires') or tags.get('expiry') or tags.get('ExpiryDate')
    if expiry_str:
        try:
            expiry = datetime.datetime.fromisoformat(expiry_str.replace('Z', '+00:00'))
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=datetime.timezone.utc)
            if expiry < now:
                flag = 'HIGH'
                reasons.append(f'expiry tag is in the past ({expiry_str})')
        except ValueError:
            reasons.append(f'unparseable expiry tag: {expiry_str}')

    # Empty RGs
    if resource_count == 0:
        reasons.append('empty RG (0 resources)')
        if flag != 'HIGH':
            flag = 'CANDIDATE'

    # Name pattern matches temporary environment convention
    if TEMP_PATTERNS.search(name) and not PROD_OVERRIDE.search(name):
        reasons.append(f'name matches temp/test pattern')
        if flag == 'ok':
            flag = 'CANDIDATE'

    reason_str = '; '.join(reasons) if reasons else 'none'
    print(f'{name},{location},{resource_count},{tags_str},{flag},{reason_str}')
"
} > "$OUTPUT_PATH"

HIGH_COUNT=$(awk -F, 'NR>1 && $5=="HIGH"' "$OUTPUT_PATH" | wc -l)
CANDIDATE_COUNT=$(awk -F, 'NR>1 && $5=="CANDIDATE"' "$OUTPUT_PATH" | wc -l)

echo ""
echo "Scan complete: ${HIGH_COUNT} high-priority cleanup candidate(s), ${CANDIDATE_COUNT} general candidate(s)."
echo "All flagged entries require human review before any action — this script never deletes anything."
echo "Report written to: $OUTPUT_PATH"

[[ "$((HIGH_COUNT + CANDIDATE_COUNT))" -gt 0 ]] && exit 1 || exit 0
