# Cost guardrail. The budget is account-wide: cost-allocation tags take up to 24 h to
# activate, and a tag filter would silently miss costs until then.

resource "aws_budgets_budget" "monthly" {
  name         = "${local.project}-monthly"
  budget_type  = "COST"
  limit_amount = format("%.2f", var.monthly_budget_usd)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  dynamic "notification" {
    for_each = [50, 100]

    content {
      comparison_operator        = "GREATER_THAN"
      threshold                  = notification.value
      threshold_type             = "PERCENTAGE"
      notification_type          = "ACTUAL"
      subscriber_email_addresses = [var.alert_email]
    }
  }
}

# Every taggable resource appears here in the console (Resource Groups & Tag Editor).
resource "aws_resourcegroups_group" "project" {
  name        = local.project
  description = "All tagged resources of the IoT certificate security demo"

  resource_query {
    query = jsonencode({
      ResourceTypeFilters = ["AWS::AllSupported"]
      TagFilters = [
        {
          Key    = "Project"
          Values = [local.project]
        },
      ]
    })
  }
}
