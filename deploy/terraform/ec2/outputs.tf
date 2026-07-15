output "mcp_endpoint" {
  description = "Point MCP clients here."
  value       = module.net_lb.mcp_endpoint
}

output "alb_dns_name" {
  value = module.net_lb.alb_dns_name
}

output "alb_security_group_id" {
  value = module.net_lb.alb_security_group_id
}

output "instance_id" {
  description = "Reach it with: aws ssm start-session --target <id>"
  value       = aws_instance.this.id
}

output "instance_security_group_id" {
  value = aws_security_group.instance.id
}
