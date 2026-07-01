#!/usr/bin/env bash
#
# cost-tagging/detect-cost-anomalies.sh
#
# SYNOPSIS
#   Compares current month's Azure spend per resource group against a
#   trailing 3-month average, flagging resource groups whose cost has
#   jumped significantly — the CLI equivalent of Azure Cost Management's
#   anomaly detection, useful when you want the data in a script
#   rather than only in the portal, or want to run it on a schedule
#   and feed the output to a ticket system automatically.
#
# USAGE
#   ./detect-cost-anomalies.sh [-t threshold_pct] [-o report.csv]
#   -t  Percent increase over 3-month average to flag (default: 50)

set -uo pipefail

THRESHOLD_PCT=50
OUTPUT_PATH="./cost-anomalies_$(date +%Y%m%d_%H%M%S).csv"

while getopts "t:o:" opt; do
  case "$opt" in
    t) THRESHOLD_PCT="$OPTARG" ;;
    o) OUTPUT_PATH="$OPTARG" ;;
    *) echo "Usage: $0 [-t threshold_pct] [-o report.csv]" >&2; exit 2 ;;
  esac
done

if ! az account show &>/dev/null; then
  echo "[ERROR] Not logged in." >&2; exit 2
fi

SUBSCRIPTION_ID=$(az account show --query id -o tsv)
echo "Fetching cost data for subscription: $SUBSCRIPTION_ID"
echo "(Requires Cost Management Reader on the subscription)"

# Get current month and prior 3 months date boundaries for the cost API
python3 -c "
import datetime, subprocess, json, sys

now = datetime.date.today()

def month_range(months_back):
    d = now.replace(day=1)
    for _ in range(months_back):
        d = (d - datetime.timedelta(days=1)).replace(day=1)
    last_day = (d.replace(month=d.month % 12 + 1, day=1) - datetime.timedelta(days=1)).day if d.month < 12 else 31
    return d.strftime('%Y-%m-01'), d.strftime(f'%Y-%m-{min(last_day, 28):02d}')

current_start = now.strftime('%Y-%m-01')
current_end = now.strftime('%Y-%m-%d')

# Query the cost management API for spend per resource group
def query_costs(start, end):
    payload = {
        'type': 'ActualCost',
        'timeframe': 'Custom',
        'timePeriod': {'from': start + 'T00:00:00Z', 'to': end + 'T23:59:59Z'},
        'dataset': {
            'granularity': 'None',
            'aggregation': {'totalCost': {'name': 'Cost', 'function': 'Sum'}},
            'grouping': [{'type': 'Dimension', 'name': 'ResourceGroupName'}]
        }
    }
    result = subprocess.run(
        ['az', 'rest', '--method', 'POST',
         '--url', f'https://management.azure.com/subscriptions/${SUBSCRIPTION_ID}/providers/Microsoft.CostManagement/query?api-version=2023-03-01',
         '--body', json.dumps(payload)],
        capture_output=True, text=True, timeout=60
    )
    if result.returncode != 0:
        return {}
    data = json.loads(result.stdout)
    rows = data.get('properties', {}).get('rows', [])
    # rows format: [cost, currency, resource_group_name]
    return {row[2]: float(row[0]) for row in rows if len(row) >= 3}

current_costs = query_costs(current_start, current_end)

historical: dict[str, list[float]] = {}
for months_back in range(1, 4):
    start, end = month_range(months_back)
    month_costs = query_costs(start, end)
    for rg, cost in month_costs.items():
        historical.setdefault(rg, []).append(cost)

print('ResourceGroup,CurrentMonthCost,3MonthAvg,PercentChange,Flag')
for rg, current in sorted(current_costs.items(), key=lambda x: -x[1]):
    history = historical.get(rg, [])
    if not history:
        avg = 0.0
        pct_change = 999.0
        flag = 'NEW_RG_OR_NO_HISTORY'
    else:
        avg = sum(history) / len(history)
        if avg < 1:
            pct_change = 999.0 if current > 0 else 0.0
            flag = 'LOW_BASELINE'
        else:
            pct_change = round(((current - avg) / avg) * 100, 1)
            flag = 'ANOMALY' if pct_change >= ${THRESHOLD_PCT} else 'ok'

    rg_safe = rg.replace(',', ';')
    print(f'{rg_safe},{current:.2f},{avg:.2f},{pct_change},{flag}')
" > "$OUTPUT_PATH"

ANOMALY_COUNT=$(awk -F, 'NR>1 && $5=="ANOMALY"' "$OUTPUT_PATH" | wc -l)
echo ""
echo "Cost anomaly scan complete: ${ANOMALY_COUNT} resource group(s) with spend >=${THRESHOLD_PCT}% above 3-month average."
echo "Report written to: $OUTPUT_PATH"
[[ "$ANOMALY_COUNT" -gt 0 ]] && exit 1 || exit 0
