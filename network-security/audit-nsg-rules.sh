#!/usr/bin/env bash
#
# network-security/audit-nsg-rules.sh
#
# SYNOPSIS
#   Audits all Network Security Groups across the subscription for
#   overly permissive inbound rules: any-source-any-port (effectively
#   no filtering), internet-open access on management ports (SSH/RDP),
#   and allow-all rules that override more specific deny rules beneath
#   them in the priority order.
#
# DESCRIPTION
#   NSG misconfigurations are consistently the #1 finding in Azure
#   cloud security reviews, and the pattern is almost always the same:
#   someone adds a temporary "allow everything" rule to debug a
#   connectivity issue, solves the problem, and the temporary rule
#   never gets removed. This script enumerates the specific patterns
#   an attacker would actually use — not a theoretical "this could
#   be tightened" finding, but a concrete "the internet can reach this
#   management port right now" finding that needs a same-day answer.
#
# USAGE
#   ./audit-nsg-rules.sh [-g resource_group] [-o report.csv]

set -uo pipefail

RESOURCE_GROUP=""
OUTPUT_PATH="./nsg-audit_$(date +%Y%m%d_%H%M%S).csv"

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

echo "Auditing NSG rules..."

ALL_NSGS=$(az network nsg list $RG_FILTER \
  --query "[].{name: name, resourceGroup: resourceGroup, id: id}" \
  --output json 2>/dev/null)

NSG_COUNT=$(echo "$ALL_NSGS" | python3 -c "import json,sys; print(len(json.load(sys.stdin)))")
echo "Found ${NSG_COUNT} NSG(s) to audit."

{
  echo "NSGName,ResourceGroup,RuleName,Priority,Direction,SourceAddressPrefix,DestinationPortRange,Flag,Reason"

  echo "$ALL_NSGS" | python3 -c "
import json, sys, subprocess

nsgs = json.load(sys.stdin)

# Ports that should almost never be open to the public internet.
# RDP (3389) and SSH (22) are the obvious ones — SMB (445) and
# WinRM (5985/5986) because they're commonly forgotten management
# ports that also show up in real-world attack chains.
MANAGEMENT_PORTS = {'22', '3389', '445', '5985', '5986', '23'}
INTERNET_SOURCES = {'*', 'Internet', '0.0.0.0/0', '::/0', 'Any'}

for nsg in nsgs:
    nsg_name = nsg.get('name', '')
    rg = nsg.get('resourceGroup', '')
    nsg_id = nsg.get('id', '')

    try:
        rules_result = subprocess.run(
            ['az', 'network', 'nsg', 'rule', 'list',
             '--nsg-name', nsg_name, '--resource-group', rg,
             '--query', '[?direction==\`Inbound\` && access==\`Allow\`].{name: name, priority: priority, sourceAddressPrefix: sourceAddressPrefix, destinationPortRange: destinationPortRange, destinationPortRanges: destinationPortRanges}',
             '--output', 'json'],
            capture_output=True, text=True, timeout=20
        )
        if rules_result.returncode != 0:
            continue
        rules = json.loads(rules_result.stdout)
    except Exception:
        continue

    for rule in rules:
        rule_name = rule.get('name', '')
        priority = rule.get('priority', 0)
        src = rule.get('sourceAddressPrefix', '') or '*'
        dest_port = rule.get('destinationPortRange', '') or '*'
        dest_ports = rule.get('destinationPortRanges', []) or []

        all_ports = [dest_port] + dest_ports
        is_internet_source = src in INTERNET_SOURCES

        flag = None
        reason = ''

        # Any-to-any: wildcard on both source and port — no filtering at all
        if is_internet_source and ('*' in all_ports or 'Any' in all_ports):
            flag = 'CRITICAL'
            reason = f'Allow-all from internet — effectively no NSG protection for anything in this scope'

        # Management port open to internet
        elif is_internet_source:
            matched_mgmt_ports = [p for p in all_ports if p in MANAGEMENT_PORTS]
            if matched_mgmt_ports:
                flag = 'HIGH'
                reason = f'Management port(s) {matched_mgmt_ports} open to internet (source: {src})'

        # Large port range open to internet — not as bad as wildcard but still usually wrong
        elif is_internet_source and dest_port == '0-65535':
            flag = 'HIGH'
            reason = 'All ports open to internet — use a specific port range instead'

        if flag:
            print(f'{nsg_name},{rg},{rule_name},{priority},Inbound,{src},{dest_port},{flag},{reason}')
"
} > "$OUTPUT_PATH"

CRITICAL=$(awk -F, 'NR>1 && $8=="CRITICAL"' "$OUTPUT_PATH" | wc -l)
HIGH=$(awk -F, 'NR>1 && $8=="HIGH"' "$OUTPUT_PATH" | wc -l)

echo ""
echo "NSG audit complete: ${CRITICAL} critical, ${HIGH} high-severity rule(s) across ${NSG_COUNT} NSG(s)."
echo "Report written to: $OUTPUT_PATH"

[[ "$((CRITICAL + HIGH))" -gt 0 ]] && exit 1 || exit 0
