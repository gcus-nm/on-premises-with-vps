data "oci_identity_availability_domains" "available" {
  compartment_id = var.compartment_ocid
}

locals {
  is_ampere_a1                  = var.instance_shape == "VM.Standard.A1.Flex"
  restore_mode                  = var.restore_boot_volume_backup != null
  restore_boot_volume_backup_id = try(var.restore_boot_volume_backup.id, null)
  selected_availability_domain  = data.oci_identity_availability_domains.available.availability_domains[var.availability_domain_index].name
  ubuntu_version = var.ubuntu_version != null ? var.ubuntu_version : (
    local.is_ampere_a1 ? "24.04 Minimal aarch64" : "24.04 Minimal"
  )
  base_image_id = var.image_ocid != null ? var.image_ocid : try(data.oci_core_images.ubuntu[0].images[0].id, null)
  # Keep instance metadata stable when the repository is checked out with
  # LF on macOS/Linux or CRLF on Windows.
  cloud_init_content = replace(
    replace(file("${path.module}/cloud-init.yaml"), "\r\n", "\n"),
    "\r",
    "\n"
  )
}

data "oci_core_images" "ubuntu" {
  count = var.image_ocid == null && !local.restore_mode ? 1 : 0

  compartment_id           = var.compartment_ocid
  operating_system         = "Canonical Ubuntu"
  operating_system_version = local.ubuntu_version
  shape                    = var.instance_shape
  state                    = "AVAILABLE"
  sort_by                  = "TIMECREATED"
  sort_order               = "DESC"
}

# Disaster-recovery mode creates a new boot volume from an existing backup.
# This resource exists only while restore_boot_volume_backup is configured.
resource "oci_core_boot_volume" "relay_restore" {
  count = local.restore_mode ? 1 : 0

  availability_domain = local.selected_availability_domain
  compartment_id      = var.compartment_ocid
  display_name        = "${var.name_prefix}-restored-boot"
  freeform_tags       = var.freeform_tags

  source_details {
    id   = local.restore_boot_volume_backup_id
    type = "bootVolumeBackup"
  }
}

resource "oci_core_instance" "relay_image" {
  count = local.restore_mode ? 0 : 1

  availability_domain = local.selected_availability_domain
  compartment_id      = var.compartment_ocid
  display_name        = "${var.name_prefix}-vm"
  shape               = var.instance_shape
  freeform_tags       = var.freeform_tags

  dynamic "shape_config" {
    for_each = local.is_ampere_a1 ? [1] : []

    content {
      ocpus         = var.instance_ocpus
      memory_in_gbs = var.instance_memory_gbs
    }
  }

  create_vnic_details {
    assign_ipv6ip    = true
    assign_public_ip = false
    display_name     = "${var.name_prefix}-primary-vnic"
    hostname_label   = "relay"
    nsg_ids          = [oci_core_network_security_group.relay.id]
    subnet_id        = oci_core_subnet.public.id
  }

  source_details {
    source_type             = "image"
    source_id               = local.base_image_id
    boot_volume_size_in_gbs = 50
    boot_volume_vpus_per_gb = 10
  }

  metadata = {
    ssh_authorized_keys = trimspace(var.ssh_public_key)
    user_data           = base64encode(local.cloud_init_content)
  }

  instance_options {
    are_legacy_imds_endpoints_disabled = true
  }

  availability_config {
    recovery_action = "RESTORE_INSTANCE"
  }

  lifecycle {
    # The image data source intentionally selects the newest matching Ubuntu
    # image for new instances. Ignore later image releases for an existing VM
    # so routine changes do not produce an unrelated source_id update.
    ignore_changes = [source_details[0].source_id]

    precondition {
      condition     = var.availability_domain_index < length(data.oci_identity_availability_domains.available.availability_domains)
      error_message = "availability_domain_index is outside the availability domains returned for this region."
    }

    precondition {
      condition     = local.base_image_id != null
      error_message = "No compatible Ubuntu image was found. Set image_ocid explicitly or adjust ubuntu_version."
    }
  }
}

resource "oci_core_instance" "relay_restore" {
  count = local.restore_mode ? 1 : 0

  availability_domain = local.selected_availability_domain
  compartment_id      = var.compartment_ocid
  display_name        = "${var.name_prefix}-vm"
  shape               = var.instance_shape
  freeform_tags       = var.freeform_tags

  dynamic "shape_config" {
    for_each = local.is_ampere_a1 ? [1] : []

    content {
      ocpus         = var.instance_ocpus
      memory_in_gbs = var.instance_memory_gbs
    }
  }

  create_vnic_details {
    assign_ipv6ip    = true
    assign_public_ip = false
    display_name     = "${var.name_prefix}-primary-vnic"
    hostname_label   = "relay"
    nsg_ids          = [oci_core_network_security_group.relay.id]
    subnet_id        = oci_core_subnet.public.id
  }

  source_details {
    source_type                     = "bootVolume"
    source_id                       = oci_core_boot_volume.relay_restore[0].id
    is_preserve_boot_volume_enabled = true
  }

  metadata = {
    ssh_authorized_keys = trimspace(var.ssh_public_key)
    user_data           = base64encode(local.cloud_init_content)
  }

  instance_options {
    are_legacy_imds_endpoints_disabled = true
  }

  availability_config {
    recovery_action = "RESTORE_INSTANCE"
  }

  lifecycle {
    precondition {
      condition     = var.availability_domain_index < length(data.oci_identity_availability_domains.available.availability_domains)
      error_message = "availability_domain_index is outside the availability domains returned for this region."
    }
  }
}

# Preserve the existing instance without replacement after splitting normal
# image mode and disaster-recovery mode into separate Terraform resources.
moved {
  from = oci_core_instance.relay
  to   = oci_core_instance.relay_image[0]
}

locals {
  relay_instance_id                  = local.restore_mode ? oci_core_instance.relay_restore[0].id : oci_core_instance.relay_image[0].id
  relay_instance_availability_domain = local.restore_mode ? oci_core_instance.relay_restore[0].availability_domain : oci_core_instance.relay_image[0].availability_domain
  relay_instance_shape               = local.restore_mode ? oci_core_instance.relay_restore[0].shape : oci_core_instance.relay_image[0].shape
  relay_boot_volume_id               = local.restore_mode ? oci_core_instance.relay_restore[0].boot_volume_id : oci_core_instance.relay_image[0].boot_volume_id
}

data "oci_core_vnic_attachments" "relay" {
  compartment_id = var.compartment_ocid
  instance_id    = local.relay_instance_id
}

data "oci_core_vnic" "relay" {
  vnic_id = data.oci_core_vnic_attachments.relay.vnic_attachments[0].vnic_id
}

data "oci_core_private_ips" "relay" {
  vnic_id = data.oci_core_vnic.relay.id
}

# A reserved IPv4 endpoint survives instance replacement and can be reassigned.
resource "oci_core_public_ip" "relay" {
  compartment_id = var.compartment_ocid
  display_name   = "${var.name_prefix}-public-ipv4"
  lifetime       = "RESERVED"
  private_ip_id  = one([for ip in data.oci_core_private_ips.relay.private_ips : ip.id if ip.is_primary])
  freeform_tags  = var.freeform_tags
}
