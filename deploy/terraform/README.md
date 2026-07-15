# Terraform: host misp-mcp on AWS

Two ways to run misp-mcp on AWS, both behind an internal, TLS-terminating
Application Load Balancer, both pointing at a MISP instance you already run.
They share one networking module (`modules/net_lb`) so the ALB, security groups,
target group, and DNS are identical; only the compute differs.

```
 caller (MCP client, own X-MISP-Key)
        │  HTTPS 443, allowed CIDRs only
        ▼
 internal ALB              TLS termination (ACM)   ← modules/net_lb
        │  HTTP :8080, SG-to-SG
        ▼
 misp-mcp   (Fargate task  ─or─  EC2 instance)
        │  HTTPS
        ▼
 your MISP instance
```

misp-mcp stores **no secret**: every caller sends their own key in the
`X-MISP-Key` header, which MISP validates and attributes to that user.

## Which one?

| | [`fargate/`](fargate/) | [`ec2/`](ec2/) |
|---|---|---|
| Compute | Serverless container | Managed VM running the container |
| You patch the OS | No (AWS-managed) | Yes |
| Shell access | None needed | SSM Session Manager (no SSH) |
| Best for | Standalone deploy, least ops | Full host control, co-locating near MISP, org standard on EC2 |
| Attack surface | Smaller (no host OS) | Larger (you own the OS) |

Both keep the endpoint private (internal ALB), lock ingress to `allowed_cidrs`,
allow the compute inbound only from the ALB, and assign no public IP. Pick the
operational model you want; the security posture is equivalent.

## Prerequisites (both)

- Terraform >= 1.3, AWS provider >= 5.0, credentials for the target account.
- A VPC with private subnets and egress to ECR + your MISP (NAT gateway or VPC
  endpoints). Fargate also needs CloudWatch Logs egress.
- An ACM certificate covering the hostname callers will use.
- The misp-mcp image pushed to a registry the account can pull (e.g. ECR):

  ```bash
  # from the repo root
  docker build -t misp-mcp:1.2.0 .
  aws ecr create-repository --repository-name misp-mcp   # once
  aws ecr get-login-password --region <region> | docker login --username AWS \
    --password-stdin <acct>.dkr.ecr.<region>.amazonaws.com
  docker tag misp-mcp:1.2.0 <acct>.dkr.ecr.<region>.amazonaws.com/misp-mcp:1.2.0
  docker push <acct>.dkr.ecr.<region>.amazonaws.com/misp-mcp:1.2.0
  ```

## Use

```bash
cd deploy/terraform/fargate     # or: cd deploy/terraform/ec2
cp terraform.tfvars.example terraform.tfvars   # then edit
terraform init
terraform apply
terraform output mcp_endpoint   # the URL to give callers
```

## Verify

```bash
curl -s -o /dev/null -w '%{http_code}\n' -X POST https://<your-host>/mcp
# 401 = reachable and auth required (correct). Timeout = your network is not in allowed_cidrs.
```

## Notes

- **`allowed_cidrs`**: the `X-MISP-Key` header is a bearer credential. Scope
  ingress to your VPN / office / caller networks. Never `0.0.0.0/0`.
- **Read-only vs write**: leave `misp_submission_event_id` empty for a
  read-only deployment; set it to enable `misp_submit_ioc` / `misp_submit_iocs`
  (writes still require each caller to hold a write-capable MISP key).
- **EC2 access**: `aws ssm start-session --target <instance_id>` (from the
  `instance_id` output). No SSH, no public IP; IMDSv2 required, root volume
  encrypted.
- **Egress**: private compute needs a NAT gateway, or VPC endpoints for ECR
  (api + dkr), S3, and (Fargate) CloudWatch Logs, plus a route to MISP.

For EC2/systemd by hand, GCP, or Azure instead, see
[../../CLOUD.md](../../CLOUD.md) and [../../DEPLOY.md](../../DEPLOY.md).
