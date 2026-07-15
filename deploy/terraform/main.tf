locals {
  port = 8080

  # Base environment. misp-mcp holds NO MISP key of its own; each caller sends
  # their own key in the X-MISP-Key header, so there is no secret to store here.
  base_env = [
    { name = "MCP_TRANSPORT", value = "http" },
    { name = "MCP_HOST", value = "0.0.0.0" },
    { name = "MCP_PORT", value = tostring(local.port) },
    { name = "MISP_URL", value = var.misp_url },
    { name = "MISP_VERIFY_TLS", value = tostring(var.misp_verify_tls) },
    # TLS terminates at the ALB, so the container serves plain HTTP behind it.
    { name = "MISP_MCP_ALLOW_INSECURE_BIND", value = "true" },
  ]

  submission_env = var.misp_submission_event_id == "" ? [] : [
    { name = "MISP_SUBMISSION_EVENT_ID", value = var.misp_submission_event_id },
  ]

  container_env = concat(local.base_env, local.submission_env)
}

# --- Networking: security groups -------------------------------------------

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
    description = "To the misp-mcp tasks"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "service" {
  name        = "${var.name}-service"
  description = "misp-mcp task: inbound only from the ALB"
  vpc_id      = var.vpc_id
  tags        = var.tags

  ingress {
    description     = "MCP port from the ALB only"
    from_port       = local.port
    to_port         = local.port
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  egress {
    description = "Egress to MISP, ECR, CloudWatch, DNS"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# --- Load balancer ----------------------------------------------------------

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
  port        = local.port
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  target_type = "ip" # Fargate awsvpc tasks register by IP
  tags        = var.tags

  health_check {
    path                = "/healthz"
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

# --- Logging ----------------------------------------------------------------

resource "aws_cloudwatch_log_group" "this" {
  name              = "/ecs/${var.name}"
  retention_in_days = var.log_retention_days
  tags              = var.tags
}

# --- IAM: task execution role (pull image, write logs) ----------------------

data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "execution" {
  name               = "${var.name}-execution"
  assume_role_policy = data.aws_iam_policy_document.assume.json
  tags               = var.tags
}

resource "aws_iam_role_policy_attachment" "execution" {
  role       = aws_iam_role.execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# --- ECS: cluster, task, service --------------------------------------------

resource "aws_ecs_cluster" "this" {
  name = var.name
  tags = var.tags
}

resource "aws_ecs_task_definition" "this" {
  family                   = var.name
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.cpu
  memory                   = var.memory
  execution_role_arn       = aws_iam_role.execution.arn
  tags                     = var.tags

  container_definitions = jsonencode([
    {
      name         = var.name
      image        = var.container_image
      essential    = true
      environment  = local.container_env
      portMappings = [{ containerPort = local.port, protocol = "tcp" }]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.this.name
          "awslogs-region"        = var.region
          "awslogs-stream-prefix" = "misp-mcp"
        }
      }
    }
  ])
}

resource "aws_ecs_service" "this" {
  name            = var.name
  cluster         = aws_ecs_cluster.this.id
  task_definition = aws_ecs_task_definition.this.arn
  desired_count   = var.desired_count
  launch_type     = "FARGATE"
  tags            = var.tags

  network_configuration {
    subnets          = var.service_subnet_ids
    security_groups  = [aws_security_group.service.id]
    assign_public_ip = var.assign_public_ip
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.this.arn
    container_name   = var.name
    container_port   = local.port
  }

  depends_on = [aws_lb_listener.https]
}

# --- Optional Route 53 record -----------------------------------------------

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
