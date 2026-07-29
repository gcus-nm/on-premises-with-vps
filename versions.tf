terraform {
  required_version = ">= 1.6.0"

  backend "oci" {
    bucket              = "onprem-relay-tfstate"
    namespace           = "nrsfc145paft"
    key                 = "on-premises-with-vps/terraform.tfstate"
    region              = "ap-tokyo-1"
    config_file_profile = "DEFAULT"
  }

  required_providers {
    oci = {
      source  = "oracle/oci"
      version = "~> 8.0"
    }
  }
}