variable "region" {
  description = "OCI home region in which Always Free compute resources can be created (for example, ap-tokyo-1)."
  type        = string

  validation {
    condition     = length(trimspace(var.region)) > 0
    error_message = "region must not be empty."
  }
}

variable "compartment_ocid" {
  description = "OCID of the compartment in which the relay resources will be created."
  type        = string

  validation {
    condition     = startswith(var.compartment_ocid, "ocid1.compartment.") || startswith(var.compartment_ocid, "ocid1.tenancy.")
    error_message = "compartment_ocid must be a compartment or tenancy OCID."
  }
}

variable "tenancy_ocid" {
  description = "Root tenancy OCID used to create a budget. Required only when budget alerts are enabled and compartment_ocid is a child compartment."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition     = var.tenancy_ocid == null || startswith(var.tenancy_ocid, "ocid1.tenancy.")
    error_message = "tenancy_ocid must be null or a tenancy OCID."
  }
}

variable "oci_config_profile" {
  description = "Profile name in ~/.oci/config used by the OCI provider."
  type        = string
  default     = "DEFAULT"
}

variable "ssh_public_key" {
  description = "OpenSSH public key installed for the ubuntu user. Never provide a private key here."
  type        = string

  validation {
    condition = anytrue([
      for prefix in ["ssh-ed25519 ", "ssh-rsa ", "ecdsa-sha2-nistp256 ", "sk-ssh-ed25519@openssh.com "] :
      startswith(trimspace(var.ssh_public_key), prefix)
    ])
    error_message = "ssh_public_key must be a supported OpenSSH public key."
  }
}

variable "name_prefix" {
  description = "Short lowercase prefix used in resource names and DNS labels."
  type        = string
  default     = "onprem-relay"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,13}[a-z0-9]$", var.name_prefix))
    error_message = "name_prefix must be 3-15 lowercase letters, numbers, or hyphens; it must start with a letter and end with a letter or number."
  }
}

variable "availability_domain_index" {
  description = "Zero-based availability-domain index. Change this if OCI reports out of host capacity."
  type        = number
  default     = 0

  validation {
    condition     = var.availability_domain_index >= 0 && floor(var.availability_domain_index) == var.availability_domain_index
    error_message = "availability_domain_index must be a non-negative integer."
  }
}

variable "instance_shape" {
  description = "Always Free compute shape. E2 Micro is the low-resource relay default; A1 Flex can be selected when capacity is available."
  type        = string
  default     = "VM.Standard.E2.1.Micro"

  validation {
    condition     = contains(["VM.Standard.E2.1.Micro", "VM.Standard.A1.Flex"], var.instance_shape)
    error_message = "instance_shape must be VM.Standard.E2.1.Micro or VM.Standard.A1.Flex."
  }
}

variable "instance_ocpus" {
  description = "OCPUs allocated when instance_shape is VM.Standard.A1.Flex. Ignored for the fixed E2 Micro shape."
  type        = number
  default     = 1

  validation {
    condition     = var.instance_ocpus >= 1 && var.instance_ocpus <= 2
    error_message = "instance_ocpus must be between 1 and 2 to stay within the current Always Free A1 limit for this stack."
  }
}

variable "instance_memory_gbs" {
  description = "Memory allocated when instance_shape is VM.Standard.A1.Flex. Ignored for the fixed E2 Micro shape."
  type        = number
  default     = 6

  validation {
    condition     = var.instance_memory_gbs >= 1 && var.instance_memory_gbs <= 12
    error_message = "instance_memory_gbs must be between 1 and 12 to stay within the current Always Free A1 limit for this stack."
  }
}

variable "image_ocid" {
  description = "Optional OCI image OCID. When null, the newest matching Ubuntu image is selected."
  type        = string
  default     = null
  nullable    = true
}

variable "ubuntu_version" {
  description = "Optional OCI operating_system_version override. When null, an architecture-compatible Ubuntu image is selected for the chosen shape."
  type        = string
  default     = null
  nullable    = true
}

variable "vcn_ipv4_cidr" {
  description = "Private IPv4 CIDR for the relay VCN."
  type        = string
  default     = "10.42.0.0/16"

  validation {
    condition     = can(cidrhost(var.vcn_ipv4_cidr, 0))
    error_message = "vcn_ipv4_cidr must be a valid CIDR."
  }
}

variable "subnet_ipv4_cidr" {
  description = "Private IPv4 CIDR for the public relay subnet; it must be contained by vcn_ipv4_cidr."
  type        = string
  default     = "10.42.1.0/24"

  validation {
    condition     = can(cidrhost(var.subnet_ipv4_cidr, 0))
    error_message = "subnet_ipv4_cidr must be a valid CIDR."
  }
}

variable "wireguard_port" {
  description = "Public UDP port reserved for the later WireGuard configuration."
  type        = number
  default     = 51820

  validation {
    condition     = var.wireguard_port >= 1 && var.wireguard_port <= 65535 && floor(var.wireguard_port) == var.wireguard_port
    error_message = "wireguard_port must be an integer from 1 through 65535."
  }
}

variable "public_tcp_ports" {
  description = "Additional TCP ports exposed by the OCI network firewall. Host forwarding is configured separately."
  type        = set(number)
  default     = []

  validation {
    condition     = alltrue([for port in var.public_tcp_ports : port >= 1 && port <= 65535 && floor(port) == port])
    error_message = "Every public TCP port must be an integer from 1 through 65535."
  }
}

variable "public_udp_ports" {
  description = "Additional UDP ports exposed by the OCI network firewall. The WireGuard port is added automatically."
  type        = set(number)
  default     = []

  validation {
    condition     = alltrue([for port in var.public_udp_ports : port >= 1 && port <= 65535 && floor(port) == port])
    error_message = "Every public UDP port must be an integer from 1 through 65535."
  }
}

variable "public_ingress_cidrs" {
  description = "IPv4 and IPv6 source CIDRs allowed to reach the WireGuard and additional public ports."
  type        = set(string)
  default     = ["0.0.0.0/0", "::/0"]

  validation {
    condition     = length(var.public_ingress_cidrs) > 0 && alltrue([for cidr in var.public_ingress_cidrs : can(cidrhost(cidr, 0))])
    error_message = "public_ingress_cidrs must contain valid IPv4 or IPv6 CIDRs."
  }
}

variable "ssh_ingress_cidrs" {
  description = "Source CIDRs allowed to use SSH. Empty by default; add only trusted administrator addresses."
  type        = set(string)
  default     = []

  validation {
    condition     = alltrue([for cidr in var.ssh_ingress_cidrs : can(cidrhost(cidr, 0))])
    error_message = "ssh_ingress_cidrs must contain only valid IPv4 or IPv6 CIDRs."
  }
}

variable "freeform_tags" {
  description = "Optional free-form tags added to OCI resources that support them."
  type        = map(string)
  default = {
    managed-by = "terraform"
    project    = "on-premises-with-vps"
  }
}

variable "budget_amount" {
  description = "Monthly budget amount in the tenancy rate-card currency. The budget is a notification guardrail and does not stop resources."
  type        = number
  default     = 100

  validation {
    condition     = var.budget_amount > 0 && floor(var.budget_amount) == var.budget_amount
    error_message = "budget_amount must be a positive whole number in the tenancy rate-card currency."
  }
}

variable "budget_alert_threshold" {
  description = "Actual monthly spend that triggers an alert, in the tenancy rate-card currency."
  type        = number
  default     = 1

  validation {
    condition     = var.budget_alert_threshold > 0 && var.budget_alert_threshold <= var.budget_amount
    error_message = "budget_alert_threshold must be greater than zero and no greater than budget_amount."
  }
}

variable "budget_alert_recipients" {
  description = "Email addresses that receive actual-spend alerts. Leave empty to disable creation of the budget and alert rule."
  type        = set(string)
  default     = []

  validation {
    condition = alltrue([
      for recipient in var.budget_alert_recipients :
      can(regex("^[^@[:space:]]+@[^@[:space:]]+\\.[^@[:space:]]+$", recipient))
    ])
    error_message = "budget_alert_recipients must contain valid email addresses."
  }
}
