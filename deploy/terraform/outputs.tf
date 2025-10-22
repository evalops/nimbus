output "control_plane_public_ip" {
  description = "Public IP of the Nimbus control plane instance"
  value       = aws_instance.control_plane.public_ip
}

output "load_balancer_dns" {
  description = "DNS of the application load balancer"
  value       = aws_lb.control_plane.dns_name
}
