# Terraform: host misp-mcp on AWS (Fargate + internal ALB)

This module runs misp-mcp as a container on ECS Fargate behind an internal
Application Load Balancer that terminates TLS. There is no VM to manage and no
SSH. It points at a MISP instance you already run; the two are independent.

```
 caller (MCP client, own X-MISP-Key)
        │  HTTPS  (443, allowed CIDRs only)
        ▼
 internal ALB          TLS termination (ACM cert)
        │  HTTP :8080  (SG-to-SG)
        ▼
 misp-mcp task         Fargate, private subnet
        │  HTTPS
        ▼
 your MISP instance
```

Why there is no key or secret in here: misp-mcp holds **no MISP credential of
its own**. Every caller sends their own key in the `X-MISP-Key` header, which
MISP validates and attributes to that user. So this module stores nothing
secret.

## Prerequisites

- Terraform >= 1.3, AWS provider >= 5.0, credentials for the target account.
- A VPC with subnets (private subnets recommended for both the tasks and an
  internal ALB) and egress to ECR + CloudWatch + your MISP (NAT gateway or VPC
  endpoints).
- An ACM certificate covering the hostname callers will use.
- The misp-mcp image pushed to a registry the account can pull (e.g. ECR):

  ```bash
  # from the repo root
  docker build -t misp-mcp:1.2.0 .
  aws ecr create-repository --repository-name misp-mcp   # once
  docker tag misp-mcp:1.2.0 <acct>.dkr.ecr.<region>.amazonaws.com/misp-mcp:1.2.0
  aws ecr get-login-password --region <region> | docker login --username AWS \
    --password-stdin <acct>.dkr.ecr.<region>.amazonaws.com
  docker push <acct>.dkr.ecr.<region>.amazonaws.com/misp-mcp:1.2.0
  ```

## Use

```bash
cd deploy/terraform
cp terraform.tfvars.example terraform.tfvars   # then edit
terraform init
terraform apply
```

`terraform output mcp_endpoint` prints the URL to give callers
(`https://.../mcp`). Point a DNS name at the ALB (set `domain_name` +
`route53_zone_id` to have Terraform create the record), and make sure the ACM
cert matches that name.

## Verify

```bash
curl -s -o /dev/null -w '%{http_code}\n' -X POST https://<your-host>/mcp
# 401 = reachable and auth required (correct). Timeout = your network is not in allowed_cidrs.
```

## Notes and hardening

- **`allowed_cidrs`**: the `X-MISP-Key` header is a bearer credential. Scope
  ingress to your VPN / office / caller networks. Never `0.0.0.0/0`.
- **Internal by default**: `internal_alb = true` keeps the endpoint off the
  public internet. Only set false if you front it with something else.
- **Read-only vs write**: leave `misp_submission_event_id` empty for a
  read-only deployment. Set it to enable `misp_submit_ioc` / `misp_submit_iocs`
  (writes still require each caller to hold a write-capable MISP key).
- **Egress**: private-subnet tasks need a NAT gateway, or VPC endpoints for
  ECR (api + dkr), S3, and CloudWatch Logs, plus a route to MISP.
- **Scaling**: raise `desired_count` for HA; the ALB spreads traffic across
  tasks. Tune `cpu` / `memory` for your query volume.

This is one reference topology. For EC2/systemd, GCP, or Azure instead, see
[../../CLOUD.md](../../CLOUD.md) and [../../DEPLOY.md](../../DEPLOY.md).
