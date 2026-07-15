# misp-mcp on ECS Fargate

Runs the misp-mcp container serverless behind an internal ALB. No VM to manage,
no OS to patch, no SSH. Best default for a standalone deploy.

See [../README.md](../README.md) for prerequisites (image push, ACM cert, VPC
egress), the security notes, and how to choose between this and `ec2/`.

```bash
cp terraform.tfvars.example terraform.tfvars   # edit
terraform init
terraform apply
terraform output mcp_endpoint
```

What it creates: an ECS cluster + Fargate service (`desired_count` tasks), a
task execution role, a CloudWatch log group, a task security group (inbound
`:8080` from the ALB only), and the shared `net_lb` module (ALB, SGs, target
group by IP, HTTPS listener, optional Route 53 record).

Scale with `desired_count` (the ALB spreads traffic); tune `cpu` / `memory` for
query volume. Logs: CloudWatch group `/ecs/<name>`.
