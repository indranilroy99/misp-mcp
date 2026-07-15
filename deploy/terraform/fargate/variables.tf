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
  description = "Subnets for the Fargate task. Use private subnets with egress to ECR/CloudWatch and to MISP (NAT or VPC endpoints)."
  type        = list(string)
}

variable "alb_subnet_ids" {
  description = "Subnets for the load balancer. Private for an internal ALB, public for internet-facing."
  type        = list(string)
}

variable "container_image" {
  description = "Full image reference, e.g. <account>.dkr.ecr.<region>.amazonaws.com/misp-mcp:1.2.0. Build from the repo Dockerfile and push to your own registry first."
  type        = string
}

variable "misp_url" {
  description = "Base URL of the MISP instance misp-mcp calls."
  type        = string
}

variable "misp_verify_tls" {
  description = "Verify MISP's TLS cert. Keep true in production."
  type        = bool
  default     = true
}

variable "misp_submission_event_id" {
  description = "MISP event id the write tools submit into. Empty = read-only."
  type        = string
  default     = ""
}

variable "certificate_arn" {
  description = "ACM certificate ARN for the HTTPS listener."
  type        = string
}

variable "allowed_cidrs" {
  description = "CIDRs allowed to reach the ALB on 443. Never 0.0.0.0/0."
  type        = list(string)

  validation {
    condition     = length([for c in var.allowed_cidrs : c if c == "0.0.0.0/0" || c == "::/0"]) == 0
    error_message = "allowed_cidrs must not include 0.0.0.0/0 or ::/0. The X-MISP-Key header is a bearer credential; scope ingress to your VPN / office / caller networks."
  }
}

variable "internal_alb" {
  description = "true = internal ALB (recommended). false = internet-facing."
  type        = bool
  default     = true
}

variable "assign_public_ip" {
  description = "Assign a public IP to the task. false in private subnets with NAT/endpoints."
  type        = bool
  default     = false
}

variable "domain_name" {
  description = "Optional FQDN to point at the ALB via Route 53."
  type        = string
  default     = ""
}

variable "route53_zone_id" {
  description = "Optional Route 53 hosted zone id for domain_name."
  type        = string
  default     = ""
}

variable "desired_count" {
  description = "Number of Fargate tasks."
  type        = number
  default     = 1
}

variable "cpu" {
  description = "Task CPU units (256 = 0.25 vCPU)."
  type        = number
  default     = 256
}

variable "memory" {
  description = "Task memory (MiB)."
  type        = number
  default     = 512
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention."
  type        = number
  default     = 30
}

variable "tags" {
  description = "Tags applied to all resources."
  type        = map(string)
  default     = {}
}
