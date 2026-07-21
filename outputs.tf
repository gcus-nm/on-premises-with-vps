output "instance_id" {
  description = "OCID of the relay compute instance."
  value       = oci_core_instance.relay.id
}

output "availability_domain" {
  description = "Availability domain selected for the instance."
  value       = oci_core_instance.relay.availability_domain
}

output "instance_shape" {
  description = "Compute shape selected for the relay."
  value       = oci_core_instance.relay.shape
}

output "public_ipv4" {
  description = "Reserved public IPv4 endpoint for clients and DNS."
  value       = oci_core_public_ip.relay.ip_address
}

output "public_ipv6_addresses" {
  description = "Publicly routable IPv6 addresses assigned to the relay VNIC."
  value       = data.oci_core_vnic.relay.ipv6addresses
}

output "private_ipv4" {
  description = "Private IPv4 address of the relay VNIC."
  value       = data.oci_core_vnic.relay.private_ip_address
}

output "wireguard_endpoint_ipv4" {
  description = "IPv4 WireGuard endpoint in host:port form."
  value       = "${oci_core_public_ip.relay.ip_address}:${var.wireguard_port}"
}

output "ssh_command" {
  description = "SSH command (works only when ssh_ingress_cidrs permits the caller)."
  value       = "ssh ubuntu@${oci_core_public_ip.relay.ip_address}"
}

output "budget_id" {
  description = "OCID of the monthly budget, or null when budget alerts are disabled."
  value       = try(oci_budget_budget.relay[0].id, null)
}

output "budget_alert_rule_id" {
  description = "OCID of the actual-spend alert rule, or null when budget alerts are disabled."
  value       = try(oci_budget_alert_rule.relay_actual_spend[0].id, null)
}
