variable "aws_region" {
  type        = string
  description = "AWS region" 
  default     = "us-east-1"
}

variable "vpc_cidr" {
  type        = string
  description = "CIDR block for Nimbus VPC"
  default     = "10.42.0.0/16"
}

variable "public_subnet_cidrs" {
  type        = list(string)
  description = "Public subnet CIDRs"
  default     = ["10.42.1.0/24", "10.42.2.0/24"]
}

variable "availability_zones" {
  type        = list(string)
  description = "Availability zones for subnets"
  default     = ["us-east-1a", "us-east-1b"]
}

variable "control_plane_ami" {
  type        = string
  description = "AMI ID for the control-plane EC2 instance"
}

variable "control_plane_instance_type" {
  type        = string
  description = "Instance type for control plane"
  default     = "t3.large"
}

variable "ssh_key_name" {
  type        = string
  description = "Existing EC2 key pair for SSH"
}

variable "acm_certificate_arn" {
  type        = string
  description = "ARN of ACM certificate for ALB"
}

variable "admin_cidr" {
  type        = string
  description = "CIDR range allowed to SSH"
  default     = "0.0.0.0/0"
}

variable "agent_ami" {
  type        = string
  description = "AMI for host agent autoscaling group"
}

variable "agent_instance_type" {
  type        = string
  description = "EC2 instance type for host agents"
  default     = "t3.large"
}

variable "agent_desired_capacity" {
  type        = number
  description = "Desired host agent count"
  default     = 2
}
