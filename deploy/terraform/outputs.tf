output "mcp_endpoint" {
  description = "Point MCP clients here (append the hostname's cert). Uses the custom domain if set, otherwise the ALB DNS name."
  value       = var.domain_name != "" ? "https://${var.domain_name}/mcp" : "https://${aws_lb.this.dns_name}/mcp"
}

output "alb_dns_name" {
  description = "ALB DNS name."
  value       = aws_lb.this.dns_name
}

output "alb_security_group_id" {
  description = "ALB security group id."
  value       = aws_security_group.alb.id
}

output "service_security_group_id" {
  description = "Fargate task security group id."
  value       = aws_security_group.service.id
}

output "ecs_cluster_name" {
  description = "ECS cluster name."
  value       = aws_ecs_cluster.this.name
}

output "log_group" {
  description = "CloudWatch Logs group for the container."
  value       = aws_cloudwatch_log_group.this.name
}
