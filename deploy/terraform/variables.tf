variable "name" {
  description = "Name prefix for all resources."
  type        = string
  default     = "misp-mcp"
}

variable "region" {
  description = "AWS region to deploy into."
  type        = string
}

variable "vpc_id" {
  description = "VPC to deploy into."
  type        = string
}

variable "service_subnet_ids" {
  description = "Subnets for the Fargate task. Use private subnets (with a NAT or VPC endpoints for egress to ECR/CloudWatch and to MISP)."
  type        = list(string)
}

variable "alb_subnet_ids" {
  description = "Subnets for the load balancer. For an internal ALB these are private subnets; for internet-facing, public subnets."
  type        = list(string)
}

variable "container_image" {
  description = "Full image reference for misp-mcp, e.g. <account>.dkr.ecr.<region>.amazonaws.com/misp-mcp:1.2.0. Build from the repo Dockerfile and push to your own registry first."
  type        = string
}

variable "misp_url" {
  description = "Base URL of your MISP instance that misp-mcp calls, e.g. https://misp.internal or an internal DNS name."
  type        = string
}

variable "misp_verify_tls" {
  description = "Verify MISP's TLS certificate. Keep true in production; set false only for a self-signed lab MISP."
  type        = bool
  default     = true
}

variable "misp_submission_event_id" {
  description = "MISP event id that write tools submit into. Leave empty to run read-only (write tools return an error until set)."
  type        = string
  default     = ""
}

variable "certificate_arn" {
  description = "ACM certificate ARN for the HTTPS listener (must cover the hostname callers use)."
  type        = string
}

variable "allowed_cidrs" {
  description = "CIDRs allowed to reach the ALB on 443. Scope this to your VPN / office / caller networks. The X-MISP-Key header is a bearer credential, so do not open this to 0.0.0.0/0."
  type        = list(string)
}

variable "internal_alb" {
  description = "true = internal ALB (not reachable from the public internet, recommended). false = internet-facing."
  type        = bool
  default     = true
}

variable "assign_public_ip" {
  description = "Assign a public IP to the Fargate task. false when running in private subnets with a NAT / VPC endpoints (recommended)."
  type        = bool
  default     = false
}

variable "domain_name" {
  description = "Optional. FQDN to point at the ALB via Route 53 (e.g. misp-mcp.example.com). Requires route53_zone_id."
  type        = string
  default     = ""
}

variable "route53_zone_id" {
  description = "Optional. Route 53 hosted zone id for domain_name."
  type        = string
  default     = ""
}

variable "desired_count" {
  description = "Number of Fargate tasks."
  type        = number
  default     = 1
}

variable "cpu" {
  description = "Fargate task CPU units (256 = 0.25 vCPU)."
  type        = number
  default     = 256
}

variable "memory" {
  description = "Fargate task memory (MiB)."
  type        = number
  default     = 512
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention for the container."
  type        = number
  default     = 30
}

variable "tags" {
  description = "Tags applied to all resources."
  type        = map(string)
  default     = {}
}
