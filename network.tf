locals {
  public_udp_ports = setunion(var.public_udp_ports, toset([var.wireguard_port]))

  tcp_ingress_rules = {
    for pair in setproduct(var.public_tcp_ports, var.public_ingress_cidrs) :
    "${pair[0]}:${pair[1]}" => {
      port   = pair[0]
      source = pair[1]
    }
  }

  udp_ingress_rules = {
    for pair in setproduct(local.public_udp_ports, var.public_ingress_cidrs) :
    "${pair[0]}:${pair[1]}" => {
      port   = pair[0]
      source = pair[1]
    }
  }
}

resource "oci_core_vcn" "relay" {
  compartment_id = var.compartment_ocid
  cidr_blocks    = [var.vcn_ipv4_cidr]
  display_name   = "${var.name_prefix}-vcn"
  dns_label      = "relayvcn"
  is_ipv6enabled = true
  freeform_tags  = var.freeform_tags
}

resource "oci_core_internet_gateway" "relay" {
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.relay.id
  display_name   = "${var.name_prefix}-internet-gateway"
  enabled        = true
  freeform_tags  = var.freeform_tags
}

resource "oci_core_route_table" "public" {
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.relay.id
  display_name   = "${var.name_prefix}-public-routes"
  freeform_tags  = var.freeform_tags

  route_rules {
    destination       = "0.0.0.0/0"
    destination_type  = "CIDR_BLOCK"
    network_entity_id = oci_core_internet_gateway.relay.id
  }

  route_rules {
    destination       = "::/0"
    destination_type  = "CIDR_BLOCK"
    network_entity_id = oci_core_internet_gateway.relay.id
  }
}

# OCI requires at least one security list on a subnet. All actual allow rules
# are attached to the relay VNIC through the more narrowly scoped NSG below.
resource "oci_core_security_list" "subnet" {
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.relay.id
  display_name   = "${var.name_prefix}-subnet-baseline"
  freeform_tags  = var.freeform_tags
}

resource "oci_core_subnet" "public" {
  compartment_id             = var.compartment_ocid
  vcn_id                     = oci_core_vcn.relay.id
  display_name               = "${var.name_prefix}-public-subnet"
  dns_label                  = "relay"
  cidr_block                 = var.subnet_ipv4_cidr
  ipv6cidr_block             = cidrsubnet(oci_core_vcn.relay.ipv6cidr_blocks[0], 8, 0)
  route_table_id             = oci_core_route_table.public.id
  security_list_ids          = [oci_core_security_list.subnet.id]
  prohibit_internet_ingress  = false
  prohibit_public_ip_on_vnic = false
  freeform_tags              = var.freeform_tags
}

resource "oci_core_network_security_group" "relay" {
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.relay.id
  display_name   = "${var.name_prefix}-nsg"
  freeform_tags  = var.freeform_tags
}

resource "oci_core_network_security_group_security_rule" "egress_ipv4" {
  network_security_group_id = oci_core_network_security_group.relay.id
  direction                 = "EGRESS"
  protocol                  = "all"
  destination               = "0.0.0.0/0"
  destination_type          = "CIDR_BLOCK"
  description               = "Allow relay outbound IPv4 traffic"
}

resource "oci_core_network_security_group_security_rule" "egress_ipv6" {
  network_security_group_id = oci_core_network_security_group.relay.id
  direction                 = "EGRESS"
  protocol                  = "all"
  destination               = "::/0"
  destination_type          = "CIDR_BLOCK"
  description               = "Allow relay outbound IPv6 traffic"
}

resource "oci_core_network_security_group_security_rule" "public_tcp" {
  for_each = local.tcp_ingress_rules

  network_security_group_id = oci_core_network_security_group.relay.id
  direction                 = "INGRESS"
  protocol                  = "6"
  source                    = each.value.source
  source_type               = "CIDR_BLOCK"
  description               = "Public TCP/${each.value.port} from ${each.value.source}"

  tcp_options {
    destination_port_range {
      min = each.value.port
      max = each.value.port
    }
  }
}

resource "oci_core_network_security_group_security_rule" "public_udp" {
  for_each = local.udp_ingress_rules

  network_security_group_id = oci_core_network_security_group.relay.id
  direction                 = "INGRESS"
  protocol                  = "17"
  source                    = each.value.source
  source_type               = "CIDR_BLOCK"
  description               = "Public UDP/${each.value.port} from ${each.value.source}"

  udp_options {
    destination_port_range {
      min = each.value.port
      max = each.value.port
    }
  }
}

resource "oci_core_network_security_group_security_rule" "ssh" {
  for_each = var.ssh_ingress_cidrs

  network_security_group_id = oci_core_network_security_group.relay.id
  direction                 = "INGRESS"
  protocol                  = "6"
  source                    = each.value
  source_type               = "CIDR_BLOCK"
  description               = "Administrative SSH from ${each.value}"

  tcp_options {
    destination_port_range {
      min = 22
      max = 22
    }
  }
}
