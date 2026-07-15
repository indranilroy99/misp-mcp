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

variable "instance_subnet_id" {
  description = "Private subnet for the EC2 instance. No public IP is assigned; needs egress (NAT/endpoints) to pull the image and reach MISP."
  type        = string
}

variable "alb_subnet_ids" {
  description = "Subnets for the load balancer. Private for an internal ALB, public for internet-facing."
  type        = list(string)
}

variable "container_image" {
  description = "Full image reference the instance pulls and runs, e.g. <account>.dkr.ecr.<region>.amazonaws.com/misp-mcp:1.2.0."
  type        = string
}

variable "instance_type" {
  description = "EC2 instance type."
  type        = string
  default     = "t3.small"
}

variable "ami_id" {
  description = "Optional AMI id. Empty = latest Amazon Linux 2023 (x86_64) from SSM."
  type        = string
  default     = ""
}

variable "ebs_volume_size" {
  description = "Root EBS volume size (GiB)."
  type        = number
  default     = 20
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
}

variable "internal_alb" {
  description = "true = internal ALB (recommended). false = internet-facing."
  type        = bool
  default     = true
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

variable "tags" {
  description = "Tags applied to all resources."
  type        = map(string)
  default     = {}
}
