terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.30"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

resource "aws_vpc" "nimbus" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = {
    Name = "nimbus-vpc"
  }
}

resource "aws_subnet" "public" {
  count                   = length(var.public_subnet_cidrs)
  vpc_id                  = aws_vpc.nimbus.id
  cidr_block              = var.public_subnet_cidrs[count.index]
  map_public_ip_on_launch = true
  availability_zone       = element(var.availability_zones, count.index)
  tags = {
    Name = "nimbus-public-${count.index}"
  }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.nimbus.id
  tags = {
    Name = "nimbus-igw"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.nimbus.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }
  tags = {
    Name = "nimbus-public-rt"
  }
}

resource "aws_route_table_association" "public" {
  count          = length(aws_subnet.public)
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_security_group" "control_plane" {
  name        = "nimbus-control-plane"
  description = "Allow HTTPS/SSH"
  vpc_id      = aws_vpc.nimbus.id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.admin_cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "nimbus-control-plane"
  }
}

resource "aws_instance" "control_plane" {
  ami                    = var.control_plane_ami
  instance_type          = var.control_plane_instance_type
  subnet_id              = aws_subnet.public[0].id
  vpc_security_group_ids = [aws_security_group.control_plane.id]
  key_name               = var.ssh_key_name

  user_data = file("${path.module}/bootstrap/bootstrap-nimbus.sh")

  tags = {
    Name = "nimbus-control-plane"
  }
}

resource "aws_lb" "control_plane" {
  name               = "nimbus-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.control_plane.id]
  subnets            = [for subnet in aws_subnet.public : subnet.id]
}

resource "aws_lb_target_group" "control_plane" {
  name     = "nimbus-targets"
  port     = 8443
  protocol = "HTTPS"
  vpc_id   = aws_vpc.nimbus.id
  health_check {
    protocol = "HTTP"
    port     = "8000"
    path     = "/healthz"
  }
}

resource "aws_lb_target_group_attachment" "control_plane" {
  target_group_arn = aws_lb_target_group.control_plane.arn
  target_id        = aws_instance.control_plane.id
  port             = 8443
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.control_plane.arn
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.acm_certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.control_plane.arn
  }
}

output "control_plane_public_ip" {
  value = aws_instance.control_plane.public_ip
}

output "load_balancer_dns" {
  value = aws_lb.control_plane.dns_name
}
