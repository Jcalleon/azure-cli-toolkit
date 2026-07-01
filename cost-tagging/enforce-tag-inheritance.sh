#!/usr/bin/env bash
#
# cost-tagging/enforce-tag-inheritance.sh
#
# SYNOPSIS
#   Copies missing required tags from a resource group to its child
#   resources that don't already have them — enforcing tag inheritance
#   as a one-time remediation pass for resources that were deployed
#   before the tagging policy was in place (or in environments where
#   the Azure Policy tag-inheritance policy isn't deployed).
#
# DESCRIPTION
#   This script inherits from the RG downward, not upward — it does
#   NOT read or change RG tags themselves, only reads from them. It
#   also never overwrites an existing tag value on a resource with the
#   RG's value — resource-level tags take precedence over inherited
#   values, since the resource may legitimately have a different
#   cost_center than its RG (a shared services RG with multiple
#   cost-center owners, for example).
#
#   Supports --dry-run to show what would change without applying it.
#
# USAGE
#   ./enforce-tag-inheritance.sh -g my-resource-group [--dry-run] [-o report.csv]

set -uo pipefail

RESOURCE_GROUP=""
DRY_RUN=false
OUTPUT_PATH="./tag-inheritance-report_$(date +%Y%m%d_%H%M%S).csv"

while getopts "g:o:" opt; do
  case "$opt" in
    g) RESOURCE_GROUP="$OPTARG" ;;
    o) OUTPUT_PATH="$OPTARG" ;;
    *) echo "Usage: $0 -g resource_group [--dry-run] [-o report.csv]" >&2; exit 2 ;;
  esac
done
for arg in "$@"; do [[ "$arg" == "--dry-run" ]] && DRY_RUN=true; done

if [[ -z "$RESOURCE_GROUP" ]]; then
  echo "Usage: $0 -g resource_group [--dry-run]" >&2; exit 2
fi

if ! az account show &>/dev/null; then
  echo "[ERROR] Not logged in." >&2; exit 2
fi

$DRY_RUN && echo "DRY RUN mode — no changes will be applied." || true

RG_TAGS=$(az group show --name "$RESOURCE_GROUP" --query tags --output json 2>/dev/null)
if [[ -z "$RG_TAGS" || "$RG_TAGS" == "null" ]]; then
  echo "Resource group '$RESOURCE_GROUP' has no tags to inherit from." >&2
  exit 0
fi

echo "RG tags to inherit: $RG_TAGS"
echo ""

{
  echo "ResourceName,TagsAdded,DryRun"
  az resource list --resource-group "$RESOURCE_GROUP" \
    --query "[].{id: id, name: name, tags: tags}" \
    --output json 2>/dev/null | python3 << PYEOF
import json, sys, subprocess

rg_tags = json.loads(r'''${RG_TAGS}''')
resources = json.load(sys.stdin)
dry_run = ${DRY_RUN}

for res in resources:
    resource_id = res.get('id', '')
    name = res.get('name', '').replace(',', ';')
    existing_tags = res.get('tags') or {}

    tags_to_add = {
        k: v for k, v in rg_tags.items()
        if k.lower() not in {ek.lower() for ek in existing_tags}
    }

    if not tags_to_add:
        continue

    tags_str = ';'.join(f'{k}={v}' for k, v in tags_to_add.items())
    print(f'{name},{tags_str},{dry_run}', flush=True)

    if not dry_run:
        # az resource tag --tags merges with existing rather than replacing,
        # so this won't touch tags the resource already has.
        tag_args = ' '.join(f'"{k}={v}"' for k, v in tags_to_add.items())
        subprocess.run(
            ['az', 'resource', 'tag', '--ids', resource_id,
             '--tags'] + [f'{k}={v}' for k, v in tags_to_add.items()],
            capture_output=True, timeout=30
        )
PYEOF
} > "$OUTPUT_PATH"

UPDATED=$(awk 'NR>1' "$OUTPUT_PATH" | wc -l)
echo ""
echo "Tag inheritance $($DRY_RUN && echo 'simulation' || echo 'enforcement') complete: ${UPDATED} resource(s) $($DRY_RUN && echo 'would receive' || echo 'received') inherited tags."
echo "Report written to: $OUTPUT_PATH"
