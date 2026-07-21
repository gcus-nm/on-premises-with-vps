data "oci_identity_availability_domains" "available" {
  compartment_id = var.compartment_ocid
}

locals {
  is_ampere_a1 = var.instance_shape == "VM.Standard.A1.Flex"
  ubuntu_version = var.ubuntu_version != null ? var.ubuntu_version : (
    local.is_ampere_a1 ? "24.04 Minimal aarch64" : "24.04 Minimal"
  )
}

data "oci_core_images" "ubuntu" {
  count = var.image_ocid == null ? 1 : 0

  compartment_id           = var.compartment_ocid
  operating_system         = "Canonical Ubuntu"
  operating_system_version = local.ubuntu_version
  shape                    = var.instance_shape
  state                    = "AVAILABLE"
  sort_by                  = "TIMECREATED"
  sort_order               = "DESC"
}

resource "oci_core_instance" "relay" {
  availability_domain = data.oci_identity_availability_domains.available.availability_domains[var.availability_domain_index].name
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
    source_id               = var.image_ocid != null ? var.image_ocid : data.oci_core_images.ubuntu[0].images[0].id
    boot_volume_size_in_gbs = 50
    boot_volume_vpus_per_gb = 10
  }

  metadata = {
    ssh_authorized_keys = trimspace(var.ssh_public_key)
    user_data           = base64encode(file("${path.module}/cloud-init.yaml"))
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

    precondition {
      condition     = var.image_ocid != null ? true : length(data.oci_core_images.ubuntu[0].images) > 0
      error_message = "No compatible Ubuntu image was found. Set image_ocid explicitly or adjust ubuntu_version."
    }
  }
}

data "oci_core_vnic_attachments" "relay" {
  compartment_id = var.compartment_ocid
  instance_id    = oci_core_instance.relay.id
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
