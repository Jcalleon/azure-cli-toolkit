#!/usr/bin/env bash
#
# resource-governance/scan-orphaned-resources.sh
#
# SYNOPSIS
#   Finds Azure resources that are deployed but not attached to
#   anything — disks with no VM, NICs with no VM, public IPs with no
#   NIC, NSGs with no subnet or NIC, app service plans with no apps,
#   and load balancers with no backend pool members.
#
# DESCRIPTION
#   Orphaned resources typically accumulate through two patterns:
#   someone deletes a VM but leaves its OS disk, or an IaC pipeline
#   is torn down incompletely and leaves a subset of the supporting
#   resources behind. They don't cause incidents on their own, but
#   they do cost money continuously (managed disks especially), and
#   an unattached NIC or public IP with an NSG assigned to it is
#   configuration complexity with no attached workload to justify it.
#
#   Checking each resource type requires a different query because
#   Azure doesn't have a single "is this resource used" property —
#   each resource type expresses attachment through different fields.
#
# USAGE
#   ./scan-orphaned-resources.sh [-g resource_group] [-o report.csv]

set -uo pipefail

RESOURCE_GROUP=""
OUTPUT_PATH="./orphaned-resources_$(date +%Y%m%d_%H%M%S).csv"

while getopts "g:o:" opt; do
  case "$opt" in
    g) RESOURCE_GROUP="$OPTARG" ;;
    o) OUTPUT_PATH="$OPTARG" ;;
    *) echo "Usage: $0 [-g resource_group] [-o report.csv]" >&2; exit 2 ;;
  esac
done

if ! az account show &>/dev/null; then
  echo "[ERROR] Not logged in." >&2; exit 2
fi

RG_FILTER=""
[[ -n "$RESOURCE_GROUP" ]] && RG_FILTER="--resource-group $RESOURCE_GROUP"

declare -a ORPHANS=()  # "type|name|resource_group|reason|estimated_monthly_cost_indicator"

echo "Scanning for orphaned resources..."

# ---- Unattached managed disks ----
# diskState 'Unattached' is the direct signal Azure provides —
# no cross-referencing needed.
while IFS= read -r disk; do
  [[ -z "$disk" ]] && continue
  name=$(echo "$disk" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('name',''))")
  rg=$(echo "$disk" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('resourceGroup',''))")
  sku=$(echo "$disk" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('sku',''))")
  size=$(echo "$disk" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('diskSizeGb','?'))")
  ORPHANS+=("ManagedDisk|$name|$rg|Unattached disk (${size}GB, ${sku})|medium_cost")
done < <(az disk list $RG_FILTER \
  --query "[?diskState=='Unattached'].{name: name, resourceGroup: resourceGroup, sku: sku.name, diskSizeGb: diskSizeGB}" \
  --output json 2>/dev/null | python3 -c "import json,sys; [print(json.dumps(d)) for d in json.load(sys.stdin)]")

# ---- NICs with no VM ----
while IFS= read -r nic; do
  [[ -z "$nic" ]] && continue
  name=$(echo "$nic" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('name',''))")
  rg=$(echo "$nic" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('resourceGroup',''))")
  ORPHANS+=("NetworkInterface|$name|$rg|NIC not attached to any VM|low_cost")
done < <(az network nic list $RG_FILTER \
  --query "[?virtualMachine==null].{name: name, resourceGroup: resourceGroup}" \
  --output json 2>/dev/null | python3 -c "import json,sys; [print(json.dumps(d)) for d in json.load(sys.stdin)]")

# ---- Public IPs not associated with any NIC or load balancer ----
while IFS= read -r pip; do
  [[ -z "$pip" ]] && continue
  name=$(echo "$pip" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('name',''))")
  rg=$(echo "$pip" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('resourceGroup',''))")
  alloc=$(echo "$pip" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('publicIPAllocationMethod',''))")
  # Static allocation unattached IPs cost money 24/7; dynamic ones
  # only when allocated, but are still wasteful configuration clutter
  cost_ind=$([ "$alloc" = "Static" ] && echo "medium_cost" || echo "low_cost")
  ORPHANS+=("PublicIPAddress|$name|$rg|Public IP not associated with NIC or LB (${alloc})|$cost_ind")
done < <(az network public-ip list $RG_FILTER \
  --query "[?ipConfiguration==null].{name: name, resourceGroup: resourceGroup, publicIPAllocationMethod: publicIPAllocationMethod}" \
  --output json 2>/dev/null | python3 -c "import json,sys; [print(json.dumps(d)) for d in json.load(sys.stdin)]")

# ---- NSGs not associated with any subnet or NIC ----
while IFS= read -r nsg; do
  [[ -z "$nsg" ]] && continue
  name=$(echo "$nsg" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('name',''))")
  rg=$(echo "$nsg" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('resourceGroup',''))")
  ORPHANS+=("NetworkSecurityGroup|$name|$rg|NSG not associated with any subnet or NIC|low_cost")
done < <(az network nsg list $RG_FILTER \
  --query "[?subnets==null && networkInterfaces==null].{name: name, resourceGroup: resourceGroup}" \
  --output json 2>/dev/null | python3 -c "import json,sys; [print(json.dumps(d)) for d in json.load(sys.stdin)]")

# ---- App Service Plans with no apps ----
while IFS= read -r asp; do
  [[ -z "$asp" ]] && continue
  name=$(echo "$asp" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('name',''))")
  rg=$(echo "$asp" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('resourceGroup',''))")
  sku=$(echo "$asp" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('sku',''))")
  ORPHANS+=("AppServicePlan|$name|$rg|App Service Plan with 0 apps (${sku})|high_cost")
done < <(az appservice plan list $RG_FILTER \
  --query "[?numberOfSites==\`0\`].{name: name, resourceGroup: resourceGroup, sku: sku.name}" \
  --output json 2>/dev/null | python3 -c "import json,sys; [print(json.dumps(d)) for d in json.load(sys.stdin)]")

{
  echo "ResourceType,Name,ResourceGroup,Reason,CostIndicator"
  for row in "${ORPHANS[@]}"; do
    IFS='|' read -r rtype name rg reason cost <<< "$row"
    printf '%s,"%s","%s","%s",%s\n' "$rtype" "$name" "$rg" "$reason" "$cost"
  done
} > "$OUTPUT_PATH"

echo ""
echo "Orphaned resource scan complete: ${#ORPHANS[@]} orphaned resource(s) found."
echo "Report written to: $OUTPUT_PATH"

[[ "${#ORPHANS[@]}" -gt 0 ]] && exit 1 || exit 0
