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

output "service_security_group_id" {
  value = aws_security_group.service.id
}

output "ecs_cluster_name" {
  value = aws_ecs_cluster.this.name
}

output "log_group" {
  value = aws_cloudwatch_log_group.this.name
}
