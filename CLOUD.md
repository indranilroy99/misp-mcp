# Cloud hosting (AWS, GCP, Azure)

This guide covers the cloud-specific parts of hosting misp-mcp: the compute, the
private networking, the TLS load balancer, and the firewall. The application
itself (env vars, TLS, systemd, verification) is the same everywhere and lives
in [DEPLOY.md](DEPLOY.md) — follow that once your VM is up.

> **AWS shortcut:** a ready-to-apply Terraform module lives in
> [deploy/terraform/](deploy/terraform/) - ECS Fargate behind an internal ALB
> with TLS, no VM to manage. Fill in a `.tfvars` and `terraform apply`. The rest
> of this guide covers the manual VM path and the other clouds.

The shape is identical on all three clouds:

```
 caller (their MCP client, own X-MISP-Key)
        │  HTTPS
        ▼
 internal load balancer   (terminates TLS)
        │  private network
        ▼
 small VM running misp-mcp (MCP_TRANSPORT=http, port 8080)
        │  HTTPS
        ▼
 your MISP instance
```

Rules that apply on every cloud:

- Keep the VM **private**. Never give it a public IP or a public inbound rule.
- Put an **internal** (not internet-facing) load balancer in front and let it
  terminate TLS, or give the process its own certs (see DEPLOY.md). The
  `X-MISP-Key` header is a bearer credential and must never travel in cleartext.
- Allow inbound to the VM **only** from the load balancer (or the specific
  caller networks), on the MCP port only.
- Allow outbound from the VM to your MISP instance (HTTPS) and DNS.
- Store nothing secret on the box. misp-mcp holds no MISP key; each caller sends
  their own per request.

---

## AWS (EC2 + internal ALB)

1. **Network.** Use a private subnet in your VPC. No public IP on the instance.
2. **Instance.** Launch a small EC2 instance (e.g. `t3.small`, Amazon Linux 2023
   or Ubuntu). Attach an IAM role with SSM so you can shell in without SSH
   (`AmazonSSMManagedInstanceCore`).
3. **Security groups.**
   - Instance SG: inbound TCP `8080` **only** from the ALB's security group.
   - ALB SG: inbound `443` from the caller networks; outbound `8080` to the
     instance SG.
   - Instance outbound: `443` to MISP, plus DNS.
4. **TLS + ALB.** Create an **internal** Application Load Balancer, HTTPS `443`
   listener with an ACM certificate, target group → instance `8080`, health
   check path `/healthz`.
5. **App.** SSM into the instance and follow [DEPLOY.md](DEPLOY.md) (venv,
   install, systemd unit with `MCP_TRANSPORT=http`, `MISP_MCP_ALLOW_INSECURE_BIND=true`
   because the ALB does TLS).
6. Callers point their MCP client at `https://<alb-dns-name>/mcp`.

---

## GCP (Compute Engine + internal HTTPS LB)

1. **Network.** A VPC subnet; give the VM no external IP. Use Cloud NAT for
   outbound to MISP if needed.
2. **Instance.** A small Compute Engine VM (e.g. `e2-small`, Debian/Ubuntu). Use
   IAP or OS Login to reach it without a public IP.
3. **Firewall.**
   - Allow ingress TCP `8080` to the VM **only** from the load balancer's
     health-check and proxy ranges (tag the VM and scope the rule to that tag).
   - Allow egress `443` to MISP and DNS.
4. **TLS + LB.** Create an **internal** HTTPS load balancer with a
   Google-managed certificate, backend service → the VM instance group on
   `8080`, health check `/healthz`.
5. **App.** SSH via IAP and follow [DEPLOY.md](DEPLOY.md) (systemd,
   `MCP_TRANSPORT=http`, `MISP_MCP_ALLOW_INSECURE_BIND=true` since the LB does TLS).
6. Callers point at `https://<lb-address>/mcp`.

---

## Azure (VM + internal Application Gateway)

1. **Network.** A VNet subnet; the VM gets no public IP. Reach it with Azure
   Bastion.
2. **Instance.** A small VM (e.g. `Standard_B1ms`, Ubuntu).
3. **Network security group.**
   - Inbound TCP `8080` to the VM **only** from the Application Gateway's subnet.
   - Outbound `443` to MISP and DNS.
4. **TLS + gateway.** Deploy an **internal** Application Gateway with an HTTPS
   `443` listener and a certificate, backend pool → the VM on `8080`, health
   probe `/healthz`.
5. **App.** Connect via Bastion and follow [DEPLOY.md](DEPLOY.md) (systemd,
   `MCP_TRANSPORT=http`, `MISP_MCP_ALLOW_INSECURE_BIND=true` since the gateway
   does TLS).
6. Callers point at `https://<app-gateway-hostname>/mcp`.

---

## Prefer certs on the box instead of an LB?

If you do not want a load balancer, give the process its own TLS certificate and
key with `MISP_MCP_TLS_CERT` / `MISP_MCP_TLS_KEY` (see [DEPLOY.md](DEPLOY.md)) and
point callers straight at the VM over HTTPS. You still keep the VM private and
firewalled to the caller networks only.
