# Shared networking + load balancer for misp-mcp, used by both the fargate and
# ec2 roots. Owns the ALB, its security group, the target group, the HTTPS
# listener, and an optional Route 53 record. The compute side (the task or the
# instance) lives in the calling root and registers into target_group_arn.

resource "aws_security_group" "alb" {
  name        = "${var.name}-alb"
  description = "Ingress to misp-mcp ALB on 443 from allowed CIDRs"
  vpc_id      = var.vpc_id
  tags        = var.tags

  ingress {
    description = "HTTPS from allowed caller networks"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidrs
  }

  egress {
    description = "To the misp-mcp compute"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_lb" "this" {
  name               = var.name
  internal           = var.internal_alb
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = var.alb_subnet_ids
  idle_timeout       = 300 # MCP streaming responses can be long-lived
  tags               = var.tags
}

resource "aws_lb_target_group" "this" {
  name        = var.name
  port        = var.port
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  target_type = var.target_type
  tags        = var.tags

  health_check {
    path                = var.health_path
    matcher             = "200"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.this.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.certificate_arn
  tags              = var.tags

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.this.arn
  }
}

resource "aws_route53_record" "this" {
  count   = var.domain_name != "" && var.route53_zone_id != "" ? 1 : 0
  zone_id = var.route53_zone_id
  name    = var.domain_name
  type    = "A"

  alias {
    name                   = aws_lb.this.dns_name
    zone_id                = aws_lb.this.zone_id
    evaluate_target_health = true
  }
}
