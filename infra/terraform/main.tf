locals {
  deployment_count = var.enable_deployment ? 1 : 0

  common_tags = {
    Application = "AEGISAI"
    Environment = var.environment
    ManagedBy   = "Terraform"
    Owner       = "SecurityEngineering"
  }
}

# This VPC is deliberately protected by enable_deployment=false. The repository
# validates the infrastructure design in CI but cannot create billable cloud
# resources accidentally.
resource "aws_vpc" "aegisai" {
  count                = local.deployment_count
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = merge(local.common_tags, {
    Name = "${var.project_name}-${var.environment}"
  })
}

# Future ECS tasks live here. They must not receive public IP addresses. A NAT
# gateway or private VPC endpoints are deliberately left as an explicit review
# decision because they incur cloud costs.
resource "aws_subnet" "private_app_a" {
  count             = local.deployment_count
  vpc_id            = aws_vpc.aegisai[0].id
  cidr_block        = cidrsubnet(var.vpc_cidr, 4, 1)
  availability_zone = "${var.aws_region}a"

  tags = merge(local.common_tags, {
    Name = "${var.project_name}-${var.environment}-private-app-a"
    Tier = "application"
  })
}

resource "aws_subnet" "private_app_b" {
  count             = local.deployment_count
  vpc_id            = aws_vpc.aegisai[0].id
  cidr_block        = cidrsubnet(var.vpc_cidr, 4, 3)
  availability_zone = "${var.aws_region}b"

  tags = merge(local.common_tags, {
    Name = "${var.project_name}-${var.environment}-private-app-b"
    Tier = "application"
  })
}

resource "aws_subnet" "private_data_a" {
  count             = local.deployment_count
  vpc_id            = aws_vpc.aegisai[0].id
  cidr_block        = cidrsubnet(var.vpc_cidr, 4, 2)
  availability_zone = "${var.aws_region}a"

  tags = merge(local.common_tags, {
    Name = "${var.project_name}-${var.environment}-private-data-a"
    Tier = "data"
  })
}

resource "aws_subnet" "private_data_b" {
  count             = local.deployment_count
  vpc_id            = aws_vpc.aegisai[0].id
  cidr_block        = cidrsubnet(var.vpc_cidr, 4, 4)
  availability_zone = "${var.aws_region}b"

  tags = merge(local.common_tags, {
    Name = "${var.project_name}-${var.environment}-private-data-b"
    Tier = "data"
  })
}

# The security-group design documents an important boundary: API workloads can
# reach PostgreSQL and Redis; neither data service accepts Internet traffic.
resource "aws_security_group" "api" {
  count       = local.deployment_count
  name_prefix = "${var.project_name}-${var.environment}-api-"
  description = "AEGISAI API and worker workload boundary"
  vpc_id      = aws_vpc.aegisai[0].id

  egress {
    description = "Temporary bootstrap egress; replace with approved endpoint rules before go-live."
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = local.common_tags
}

resource "aws_security_group" "data" {
  count       = local.deployment_count
  name_prefix = "${var.project_name}-${var.environment}-data-"
  description = "AEGISAI PostgreSQL and Redis workload boundary"
  vpc_id      = aws_vpc.aegisai[0].id

  ingress {
    description     = "PostgreSQL from the AEGISAI API and worker only"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.api[0].id]
  }

  ingress {
    description     = "Redis from the AEGISAI API and worker only"
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = [aws_security_group.api[0].id]
  }

  tags = local.common_tags
}
