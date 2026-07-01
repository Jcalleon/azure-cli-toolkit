# Azure CLI Toolkit

> Azure operations and security scripts using the Azure CLI — identity/RBAC auditing, resource governance, network security checks, cost and tagging enforcement, backup/DR validation, and monitoring compliance. 20 scripts across 6 operational domains, all bash syntax-validated.

[![Azure CLI](https://img.shields.io/badge/Azure%20CLI-2.50%2B-blue)](https://docs.microsoft.com/en-us/cli/azure/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Scripts](https://img.shields.io/badge/Scripts-20-orange)](.)
[![Validated](https://img.shields.io/badge/bash%20-n-clean-brightgreen)](.)

---

## Author

**Jacob Calleon** | CISSP, CompTIA Network+ | M.S. Cybersecurity (Purdue, 3.82 GPA)
Fifth in a set of companion toolkits, each its own repo: [PowerShell Security Toolkit](https://github.com/jcalleon/powershell-security-toolkit), [Bash Ops Toolkit](https://github.com/jcalleon/bash-ops-toolkit), [Python Security Automation](https://github.com/jcalleon/python-security-automation), [Ansible Infrastructure Toolkit](https://github.com/jcalleon/ansible-infra-toolkit), [Terraform Multi-Cloud Toolkit](https://github.com/jcalleon/terraform-multicloud-toolkit), and this one — Azure-specific control-plane operations that sit between "what Terraform provisions" and "what the portal shows you."

---

## Repository Structure

```
azure-cli-toolkit/
├── identity-rbac/               # 4 scripts — Stale SPs, over-privileged roles, guest access review, managed identity inventory
├── resource-governance/        # 4 scripts — Orphaned resources, resource locks, policy compliance, RG cleanup candidates
├── network-security/            # 3 scripts — NSG rule audit, public IP inventory, private endpoint compliance
├── cost-tagging/                  # 3 scripts — Untagged resource reporter, tag inheritance enforcer, cost anomaly detector
├── backup-dr/                      # 3 scripts — Backup coverage audit, policy compliance, geo-redundancy validation
└── monitoring-compliance/    # 3 scripts — Diagnostic settings audit, Defender coverage report, Activity Log retention check
```

---

## Design Principles

**Every script is read-only by default.** The one exception is `enforce-tag-inheritance.sh`, which requires an explicit `--dry-run` flag to flip to report-only mode; the write path requires intentional opt-in. All others are pure audit/reporting — they produce a CSV and exit with a non-zero code when findings exist, making them usable as pipeline checks ("fail the CI step if there are open-to-internet management ports") without ever modifying anything unexpectedly.

**Coverage over clever queries.** Several scripts shell out to inline Python for post-processing rather than writing a single complex JMESPath query that would need significant documentation to explain. A JMESPath query that takes 20 minutes to debug is worse engineering than a 10-line Python block that's immediately readable, especially for scripts that will be run during incidents or handed to someone unfamiliar with the author's az query style.

**The audit/report pairing pattern mirrors the rest of this toolkit family.** `audit-backup-coverage.sh` reports gaps; it doesn't enroll VMs into backup. `report-overprivileged-roles.sh` lists over-privileged assignments; it doesn't remove them. The actions that follow from these reports are environment-specific decisions — a script that does both is doing two things that shouldn't be coupled.

---

## Prerequisites

- Azure CLI 2.50+ (`az --version`)
- `az login` or a service principal already authenticated (`az login --service-principal`)
- For identity-rbac scripts: `AuditLog.Read.All` + `Directory.Read.All` on the Entra ID tenant
- For cost-tagging scripts: `Cost Management Reader` on the subscription
- For monitoring-compliance scripts: `Security Reader` for Defender; subscription-scope `Reader` for everything else

---

## Quick Start

```bash
# Audit all NSG rules for internet-open management ports
./network-security/audit-nsg-rules.sh -o nsg-findings.csv

# Find VMs not enrolled in any backup policy
./backup-dr/audit-backup-coverage.sh -o backup-gaps.csv

# Stale service principal report (SPs inactive > 90 days)
./identity-rbac/audit-stale-service-principals.sh -d 90 -o stale-sps.csv

# Everything that's public-internet-accessible and shouldn't be
./network-security/check-private-endpoint-compliance.sh -o pe-gaps.csv

# Resources missing required tags (dry-run pattern — just shows count)
./cost-tagging/report-untagged-resources.sh -t "environment,owner,cost_center"

# Defender for Cloud coverage gaps
./monitoring-compliance/report-defender-coverage.sh -o defender-coverage.csv
```

---

## Requirements

Azure CLI 2.50+, bash 4.0+, Python 3.8+ (used inline for JSON post-processing in several scripts — avoids complex JMESPath while keeping the scripts dependency-free beyond what's already in the az CLI environment). Every script calls `az` directly and requires an active `az login` session.
