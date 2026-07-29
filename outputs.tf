output "instance_id" {
  description = "OCID of the relay compute instance."
  value       = local.relay_instance_id
}

output "availability_domain" {
  description = "Availability domain selected for the instance."
  value       = local.relay_instance_availability_domain
}

output "instance_shape" {
  description = "Compute shape selected for the relay."
  value       = local.relay_instance_shape
}

output "boot_volume_id" {
  description = "OCID of the boot volume currently attached to the relay instance."
  value       = local.relay_boot_volume_id
}

output "boot_volume_backup_policy_id" {
  description = "OCID of the weekly boot-volume backup policy, or null when backups are disabled."
  value       = try(oci_core_volume_backup_policy.relay[0].id, null)
}

output "restore_mode_active" {
  description = "Whether the relay is currently managed from a restored boot volume."
  value       = local.restore_mode
}

output "restored_boot_volume_id" {
  description = "OCID of the Terraform-restored boot volume, or null in normal image mode."
  value       = try(oci_core_boot_volume.relay_restore[0].id, null)
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
