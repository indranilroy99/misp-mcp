# misp-mcp on EC2

Runs the misp-mcp container on a single managed EC2 instance behind an internal
ALB. You own the OS (patching, access) in exchange for full host control and
SSM shell access. Good when you standardize on EC2 or want the box near MISP.

See [../README.md](../README.md) for prerequisites (image push, ACM cert, VPC
egress), the security notes, and how to choose between this and `fargate/`.

```bash
cp terraform.tfvars.example terraform.tfvars   # edit
terraform init
terraform apply
terraform output mcp_endpoint
```

What it creates: one EC2 instance (Amazon Linux 2023 by default) in a private
subnet with no public IP, an instance role (SSM + read-only ECR), an instance
security group (inbound `:8080` from the ALB only), and the shared `net_lb`
module (ALB, SGs, target group by instance id, HTTPS listener, optional Route 53
record). User-data installs Docker, logs in to ECR if needed, and runs the
container with `--restart unless-stopped`.

Hardening baked in: IMDSv2 required, encrypted root volume, no SSH (use
`aws ssm start-session --target <instance_id>`), egress-only to MISP/ECR/DNS.

Operate it:

```bash
aws ssm start-session --target <instance_id>   # from `terraform output instance_id`
sudo docker logs -f misp-mcp                    # container logs
sudo docker restart misp-mcp                    # bounce it
```

To roll a new image: push the tag, update `container_image`, `terraform apply`
(`user_data_replace_on_change` replaces the instance so it pulls the new image).
