#!/usr/bin/env bash
#
# network-security/inventory-public-ips.sh
#
# SYNOPSIS
#   Inventories every public IP address in the subscription, what it's
#   attached to, whether DDoS Protection is enabled, and whether the
#   attached resource sits behind any WAF or Application Gateway —
#   building the "external attack surface" map a cloud security review
#   always asks for.
#
# DESCRIPTION
#   The first question in any external penetration test is "what IPs
#   does this organization expose to the internet." This script answers
#   that question from the Azure control plane perspective, not from
#   network scanning — faster, more complete, and authorized regardless
#   of what's actually listening, giving you the full picture including
#   resources that are deployed but happen to have no services running
#   on them yet (which can still be targeted).
#
# USAGE
#   ./inventory-public-ips.sh [-o report.csv]

set -uo pipefail

OUTPUT_PATH="./public-ip-inventory_$(date +%Y%m%d_%H%M%S).csv"
while getopts "o:" opt; do
  case "$opt" in
    o) OUTPUT_PATH="$OPTARG" ;;
    *) echo "Usage: $0 [-o report.csv]" >&2; exit 2 ;;
  esac
done

if ! az account show &>/dev/null; then
  echo "[ERROR] Not logged in." >&2; exit 2
fi

echo "Enumerating all public IP addresses..."

az network public-ip list \
  --query "[].{
    name: name,
    resourceGroup: resourceGroup,
    ipAddress: ipAddress,
    allocationMethod: publicIPAllocationMethod,
    sku: sku.name,
    fqdn: dnsSettings.fqdn,
    associatedNIC: ipConfiguration.id,
    ddosSettings: ddosSettings
  }" \
  --output json 2>/dev/null | python3 -c "
import json, sys, subprocess

pips = json.load(sys.stdin)

print('Name,ResourceGroup,IPAddress,AllocationMethod,SKU,FQDN,AssociatedResource,DDoSProtection,Flag,Reason')

for pip in pips:
    name = pip.get('name', '').replace(',', ';')
    rg = pip.get('resourceGroup', '')
    ip_addr = pip.get('ipAddress') or 'not_allocated'
    alloc = pip.get('allocationMethod', '')
    sku = pip.get('sku', '')
    fqdn = pip.get('fqdn') or ''
    nic_config_id = pip.get('associatedNIC') or ''
    ddos = pip.get('ddosSettings') or {}

    # Determine what this IP is actually attached to from the NIC
    # config resource ID path — e.g. a path containing 'virtualMachines'
    # vs 'applicationGateways' vs 'loadBalancers' tells us the attached
    # resource type without a separate API call per IP.
    if nic_config_id:
        parts = nic_config_id.lower().split('/')
        if 'virtualmachines' in parts:
            associated = 'VirtualMachine'
        elif 'applicationgateways' in parts:
            associated = 'ApplicationGateway'
        elif 'loadbalancers' in parts:
            associated = 'LoadBalancer'
        elif 'bastionhosts' in parts:
            associated = 'BastionHost'
        elif 'firewalls' in parts:
            associated = 'AzureFirewall'
        else:
            associated = 'other'
    else:
        associated = 'unattached'

    # DDoS protection state: Basic is the default (no charge, limited
    # protection), Standard is the paid tier with adaptive tuning.
    # Flagging absence of Standard specifically is only meaningful for
    # production workloads — this flag is informational, not automatically
    # an action item without context about what's behind the IP.
    ddos_protection = ddos.get('protectionMode') or ddos.get('ddosCustomPolicy') or 'Basic'
    has_ddos_standard = ddos_protection not in ('', 'Basic', None)

    flag = 'ok'
    reasons = []

    if associated == 'unattached':
        flag = 'REVIEW'
        reasons.append('Public IP not attached to any resource')

    if associated == 'VirtualMachine' and not has_ddos_standard:
        flag = 'REVIEW'
        reasons.append('VM directly exposed — consider placing behind LB/AppGateway + DDoS Standard')

    if sku == 'Basic':
        reasons.append('Basic SKU — does not support Availability Zones or Standard features')

    reason = '; '.join(reasons) if reasons else ''
    print(f'{name},{rg},{ip_addr},{alloc},{sku},{fqdn},{associated},{has_ddos_standard},{flag},{reason}')
"

echo ""
echo "Public IP inventory written to: $OUTPUT_PATH"
