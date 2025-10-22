# Terraform Quickstart Blueprint

This sample configuration provisions the minimum AWS infrastructure required to run Nimbus in a sandbox environment. It spins up:

- A VPC with public subnets
- An EC2 instance that runs the control plane + cache services via the docker-compose bundle
- An application load balancer terminating TLS
- Security groups for the host agents and dashboard traffic

> **Note:** This is an illustrative starting point. Hardened production deployments should add private subnets, managed databases, secret managers, and monitoring per your organisation’s standards.

## Prerequisites

- Terraform ≥ 1.6
- AWS credentials with permissions to create VPC, EC2, ALB, and IAM roles
- Nimbus repo cloned locally

## Usage

1. Copy `terraform.tfvars.example` to `terraform.tfvars` and populate the required variables.
2. Initialise providers and modules:
   ```bash
   terraform init
   ```
3. Review the plan:
   ```bash
   terraform plan
   ```
4. Apply:
   ```bash
   terraform apply
   ```
5. SSH into the instance and run the bootstrap script:
   ```bash
   ssh ec2-user@$(terraform output -raw control_plane_public_ip)
   sudo /usr/local/bin/bootstrap-nimbus.sh
   ```

The bootstrap script installs Docker, pulls the Nimbus images, and writes the `.env` using the outputs produced by this Terraform stack.

## File layout

```
deploy/terraform/
├── main.tf
├── variables.tf
├── outputs.tf
├── bootstrap/
│   └── bootstrap-nimbus.sh
└── terraform.tfvars.example
```

Feel free to fork this layout into your IaC repository and extend it with managed Postgres/Redis, autoscaling host agent groups, and monitoring sinks.
