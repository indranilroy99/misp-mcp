locals {
  port = 8080

  # Docker `-e` flags for the container. misp-mcp stores no secret; each caller
  # sends their own X-MISP-Key. MISP_URL is single-quoted to survive odd chars.
  env_flags = join(" ", concat(
    [
      "-e MCP_TRANSPORT=http",
      "-e MCP_HOST=0.0.0.0",
      "-e MCP_PORT=${local.port}",
      "-e MISP_URL='${var.misp_url}'",
      "-e MISP_VERIFY_TLS=${var.misp_verify_tls}",
      "-e MISP_MCP_ALLOW_INSECURE_BIND=true",
    ],
    var.misp_submission_event_id == "" ? [] : [
      "-e MISP_SUBMISSION_EVENT_ID=${var.misp_submission_event_id}",
    ],
  ))
}

module "net_lb" {
  source = "../modules/net_lb"

  name            = var.name
  vpc_id          = var.vpc_id
  alb_subnet_ids  = var.alb_subnet_ids
  allowed_cidrs   = var.allowed_cidrs
  internal_alb    = var.internal_alb
  certificate_arn = var.certificate_arn
  port            = local.port
  target_type     = "instance" # EC2 registers by instance id
  domain_name     = var.domain_name
  route53_zone_id = var.route53_zone_id
  tags            = var.tags
}

resource "aws_security_group" "instance" {
  name        = "${var.name}-instance"
  description = "misp-mcp instance: inbound only from the ALB"
  vpc_id      = var.vpc_id
  tags        = var.tags

  ingress {
    description     = "MCP port from the ALB only"
    from_port       = local.port
    to_port         = local.port
    protocol        = "tcp"
    security_groups = [module.net_lb.alb_security_group_id]
  }

  egress {
    description = "Egress to MISP, ECR, DNS"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# --- IAM: SSM access (no SSH) + read-only ECR pull --------------------------

data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "instance" {
  name               = "${var.name}-instance"
  assume_role_policy = data.aws_iam_policy_document.assume.json
  tags               = var.tags
}

resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.instance.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy_attachment" "ecr" {
  role       = aws_iam_role.instance.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
}

resource "aws_iam_instance_profile" "this" {
  name = "${var.name}-instance"
  role = aws_iam_role.instance.name
  tags = var.tags
}

# --- Instance ---------------------------------------------------------------

data "aws_ssm_parameter" "al2023" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
}

resource "aws_instance" "this" {
  ami                         = var.ami_id != "" ? var.ami_id : data.aws_ssm_parameter.al2023.value
  instance_type               = var.instance_type
  subnet_id                   = var.instance_subnet_id
  vpc_security_group_ids      = [aws_security_group.instance.id]
  iam_instance_profile        = aws_iam_instance_profile.this.name
  associate_public_ip_address = false
  user_data_replace_on_change = true

  user_data = templatefile("${path.module}/user_data.sh.tftpl", {
    container_image = var.container_image
    env_flags       = local.env_flags
  })

  metadata_options {
    http_tokens   = "required" # IMDSv2 only
    http_endpoint = "enabled"
  }

  root_block_device {
    volume_size = var.ebs_volume_size
    encrypted   = true
  }

  tags = merge(var.tags, { Name = var.name })
}

resource "aws_lb_target_group_attachment" "this" {
  target_group_arn = module.net_lb.target_group_arn
  target_id        = aws_instance.this.id
  port             = local.port
}
