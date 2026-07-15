output "alb_security_group_id" {
  value = aws_security_group.alb.id
}

output "target_group_arn" {
  value = aws_lb_target_group.this.arn
}

output "alb_dns_name" {
  value = aws_lb.this.dns_name
}

output "alb_zone_id" {
  value = aws_lb.this.zone_id
}

output "mcp_endpoint" {
  value = var.domain_name != "" ? "https://${var.domain_name}/mcp" : "https://${aws_lb.this.dns_name}/mcp"
}
