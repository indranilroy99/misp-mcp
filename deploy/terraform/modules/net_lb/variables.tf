variable "name" {
  type = string
}

variable "vpc_id" {
  type = string
}

variable "alb_subnet_ids" {
  type = list(string)
}

variable "allowed_cidrs" {
  description = "CIDRs allowed to reach the ALB on 443. Scope to your caller networks; never 0.0.0.0/0 (X-MISP-Key is a bearer credential)."
  type        = list(string)
}

variable "internal_alb" {
  type    = bool
  default = true
}

variable "certificate_arn" {
  type = string
}

variable "port" {
  type    = number
  default = 8080
}

variable "health_path" {
  type    = string
  default = "/healthz"
}

variable "target_type" {
  description = "ip for Fargate (awsvpc), instance for EC2."
  type        = string
}

variable "domain_name" {
  type    = string
  default = ""
}

variable "route53_zone_id" {
  type    = string
  default = ""
}

variable "tags" {
  type    = map(string)
  default = {}
}
