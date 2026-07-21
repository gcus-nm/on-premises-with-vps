locals {
  budget_alerts_enabled = length(var.budget_alert_recipients) > 0
  budget_tenancy_ocid = var.tenancy_ocid != null ? var.tenancy_ocid : (
    startswith(var.compartment_ocid, "ocid1.tenancy.") ? var.compartment_ocid : null
  )
}

resource "oci_budget_budget" "relay" {
  count = local.budget_alerts_enabled ? 1 : 0

  compartment_id = local.budget_tenancy_ocid
  amount         = var.budget_amount
  reset_period   = "MONTHLY"

  display_name = "${var.name_prefix}-budget"
  description  = "Monthly cost guardrail for the on-premises relay stack."

  target_type = "COMPARTMENT"
  targets     = [var.compartment_ocid]

  freeform_tags = var.freeform_tags

  lifecycle {
    precondition {
      condition     = local.budget_tenancy_ocid != null
      error_message = "tenancy_ocid is required for budget alerts when compartment_ocid is not the root tenancy OCID."
    }
  }
}

resource "oci_budget_alert_rule" "relay_actual_spend" {
  count = local.budget_alerts_enabled ? 1 : 0

  budget_id = oci_budget_budget.relay[0].id

  display_name   = "${var.name_prefix}-actual-spend"
  description    = "Notify administrators when actual OCI charges reach the configured amount."
  type           = "ACTUAL"
  threshold_type = "ABSOLUTE"
  threshold      = var.budget_alert_threshold

  recipients = join(",", sort(tolist(var.budget_alert_recipients)))
  message    = "OCIで課金が発生しました。Billing & Cost ManagementのCost Analysisを確認してください。"

  freeform_tags = var.freeform_tags
}
