# AEGISAI AWS Terraform Blueprint

This directory is a **zero-cost, non-deploying production blueprint**. It
documents and validates the foundation for a future AWS deployment without
requiring an AWS account, credentials, or billable resources.

## What it proves

- A production environment uses private application and data network tiers.
- PostgreSQL and Redis accept traffic only from the AEGISAI workload boundary.
- Campaign workers must have a separately reviewed egress design.
- Infrastructure changes are formatted and validated in CI.

## Safe local commands

Install Terraform only if you want to validate the blueprint locally:

```bash
terraform -chdir=infra/terraform init -backend=false
terraform -chdir=infra/terraform validate
terraform fmt -check -recursive infra/terraform
```

These commands do not create cloud infrastructure. Never run `terraform apply`
for this directory unless you own the cloud account, have reviewed the cost, and
have completed `docs/enterprise-blueprint.md`.

## Before a real deployment

Complete the missing reviewed components: multi-AZ RDS, managed Redis, private
ECS services, an HTTPS load balancer/WAF, Secrets Manager/KMS, monitoring,
backup restore testing, SSO/MFA, and an egress-controlled campaign runner.
