resource "oci_core_volume_backup_policy" "relay" {
  count = var.enable_boot_volume_backups ? 1 : 0

  compartment_id = var.compartment_ocid
  display_name   = "${var.name_prefix}-weekly-boot-backup"
  freeform_tags  = var.freeform_tags

  schedules {
    backup_type       = "INCREMENTAL"
    period            = "ONE_WEEK"
    retention_seconds = var.boot_volume_backup_retention_days * 86400
    day_of_week       = var.boot_volume_backup_day_of_week
    hour_of_day       = var.boot_volume_backup_hour
    offset_type       = "STRUCTURED"
    time_zone         = "REGIONAL_DATA_CENTER_TIME"
  }
}

resource "oci_core_volume_backup_policy_assignment" "relay" {
  count = var.enable_boot_volume_backups ? 1 : 0

  asset_id  = local.relay_boot_volume_id
  policy_id = oci_core_volume_backup_policy.relay[0].id
}
