# Read-only role for the local Grafana dashboard (grafana/). Grafana runs with your normal
# AWS profile and assumes this role, so the dashboard itself can only read metrics and the
# project's log groups.

variable "grafana_trusted_principal_arns" {
  description = "IAM principals allowed to assume the Grafana read-only role. Empty = the identity running Terraform."
  type        = list(string)
  default     = []
}

locals {
  grafana_log_groups = [
    module.telemetry_processor.log_group_name,
    module.detector.log_group_name,
    module.quarantine.log_group_name,
    module.cert_expiry.log_group_name,
    aws_cloudwatch_log_group.iot_logs.name,
    aws_cloudwatch_log_group.rule_errors.name,
  ]
  grafana_log_group_arns = flatten([
    for name in local.grafana_log_groups : [
      "arn:${local.partition}:logs:${var.region}:${local.account_id}:log-group:${name}",
      "arn:${local.partition}:logs:${var.region}:${local.account_id}:log-group:${name}:*",
    ]
  ])
}

data "aws_iam_policy_document" "grafana_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = length(var.grafana_trusted_principal_arns) > 0 ? var.grafana_trusted_principal_arns : [data.aws_caller_identity.current.arn]
    }
  }
}

resource "aws_iam_role" "grafana" {
  name                 = "${local.project}-grafana-readonly"
  description          = "Read-only access for the local Grafana dashboard"
  assume_role_policy   = data.aws_iam_policy_document.grafana_assume.json
  max_session_duration = 3600
}

data "aws_iam_policy_document" "grafana" {
  # checkov:skip=CKV_AWS_356:GetMetricData/ListMetrics only scope to CloudWatch metric "dataset" resources, not ordinary metrics; the remaining "*" actions have no resource types.
  statement {
    # Reading ordinary CloudWatch metrics cannot be scoped to a resource.
    sid       = "ReadMetrics"
    actions   = ["cloudwatch:GetMetricData", "cloudwatch:ListMetrics"]
    resources = ["*"]
  }
  statement {
    sid       = "QueryProjectLogs"
    actions   = ["logs:StartQuery", "logs:GetQueryResults", "logs:GetLogGroupFields", "logs:GetLogEvents", "logs:FilterLogEvents"]
    resources = local.grafana_log_group_arns
  }
  statement {
    # StopQuery does not support resource-level permissions.
    sid       = "StopQueries"
    actions   = ["logs:StopQuery"]
    resources = ["*"]
  }
  statement {
    sid       = "ListLogGroups"
    actions   = ["logs:DescribeLogGroups"]
    resources = ["arn:${local.partition}:logs:${var.region}:${local.account_id}:log-group:*"]
  }
  statement {
    # Used by Grafana's region and dimension pickers.
    sid       = "GrafanaDiscovery"
    actions   = ["ec2:DescribeRegions", "tag:GetResources"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "grafana" {
  name   = "read-dashboard-data"
  role   = aws_iam_role.grafana.id
  policy = data.aws_iam_policy_document.grafana.json
}

output "grafana_role_arn" {
  description = "Role the local Grafana assumes (see grafana/README section in the main README)."
  value       = aws_iam_role.grafana.arn
}
