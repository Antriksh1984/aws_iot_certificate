# Response: automatic quarantine on violation, and a weekly certificate-expiry report.

resource "aws_dynamodb_table" "security_events" {
  name         = "${local.project}-security-events"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "eventId"

  attribute {
    name = "eventId"
    type = "S"
  }

  attribute {
    name = "deviceId"
    type = "S"
  }

  attribute {
    name = "timestamp"
    type = "S"
  }

  global_secondary_index {
    name            = "deviceId-timestamp-index"
    projection_type = "ALL"

    key_schema {
      attribute_name = "deviceId"
      key_type       = "HASH"
    }

    key_schema {
      attribute_name = "timestamp"
      key_type       = "RANGE"
    }
  }

  ttl {
    attribute_name = "expiresAt"
    enabled        = true
  }

  point_in_time_recovery {
    enabled = true
  }
}

# ---------------------------------------------------------------- quarantine

data "aws_iam_policy_document" "quarantine" {
  statement {
    sid       = "FindDeviceCertificates"
    actions   = ["iot:ListThingPrincipals"]
    resources = ["${local.arn_prefix}:thing/${local.project}-*"]
  }
  statement {
    # ListAttachedPolicies does not support resource-level permissions.
    sid       = "ListCertificatePolicies"
    actions   = ["iot:ListAttachedPolicies"]
    resources = ["*"]
  }
  statement {
    sid = "IsolateCertificate"
    actions = [
      "iot:DescribeCertificate",
      "iot:UpdateCertificate",
      "iot:AttachPolicy",
      "iot:DetachPolicy",
    ]
    resources = ["${local.arn_prefix}:cert/*"]
  }
  statement {
    sid       = "RecordSecurityEvent"
    actions   = ["dynamodb:PutItem"]
    resources = [aws_dynamodb_table.security_events.arn]
  }
}

module "quarantine" {
  source = "./modules/python_lambda"

  name               = "${local.project}-quarantine"
  description        = "Quarantines a device on a Defender violation: deny-all policy and certificate set INACTIVE."
  source_file        = "${local.lambdas_dir}/quarantine.py"
  build_dir          = local.build_dir
  policy_json        = data.aws_iam_policy_document.quarantine.json
  log_retention_days = var.log_retention_days
  timeout            = 60

  environment = {
    QUARANTINE_POLICY_NAME = aws_iot_policy.quarantine.name
    EVENTS_TABLE           = aws_dynamodb_table.security_events.name
    THING_PREFIX           = "${local.project}-"
    TTL_DAYS               = tostring(var.data_ttl_days)
  }
}

# Only Defender-format "in-alarm" violations invoke the Lambda; CloudWatch alarms,
# audit results and expiry reports on the same topic are filtered out by SNS.
resource "aws_sns_topic_subscription" "quarantine" {
  topic_arn           = aws_sns_topic.security_alerts.arn
  protocol            = "lambda"
  endpoint            = module.quarantine.function_arn
  filter_policy_scope = "MessageBody"
  filter_policy       = jsonencode({ violationEventType = ["in-alarm"] })
}

resource "aws_lambda_permission" "sns_invoke_quarantine" {
  statement_id  = "AllowSecurityAlertsTopic"
  action        = "lambda:InvokeFunction"
  function_name = module.quarantine.function_name
  principal     = "sns.amazonaws.com"
  source_arn    = aws_sns_topic.security_alerts.arn
}

# ---------------------------------------------------------------- certificate expiry

data "aws_iam_policy_document" "cert_expiry" {
  statement {
    # ListCertificates does not support resource-level permissions.
    sid       = "ListCertificates"
    actions   = ["iot:ListCertificates"]
    resources = ["*"]
  }
  statement {
    sid       = "InspectCertificates"
    actions   = ["iot:DescribeCertificate", "iot:ListPrincipalThings"]
    resources = ["${local.arn_prefix}:cert/*"]
  }
  statement {
    sid       = "ReportExpiringCertificates"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.security_alerts.arn]
  }
}

module "cert_expiry" {
  source = "./modules/python_lambda"

  name               = "${local.project}-cert-expiry"
  description        = "Weekly report of IoT certificates expiring within the threshold."
  source_file        = "${local.lambdas_dir}/cert_expiry.py"
  build_dir          = local.build_dir
  policy_json        = data.aws_iam_policy_document.cert_expiry.json
  log_retention_days = var.log_retention_days
  timeout            = 60

  environment = {
    THRESHOLD_DAYS  = "30"
    ALERT_TOPIC_ARN = aws_sns_topic.security_alerts.arn
  }
}

resource "aws_cloudwatch_event_rule" "cert_expiry_weekly" {
  name                = "${local.project}-cert-expiry-weekly"
  description         = "Run the certificate expiry check every 7 days"
  schedule_expression = "rate(7 days)"
}

resource "aws_cloudwatch_event_target" "cert_expiry" {
  rule      = aws_cloudwatch_event_rule.cert_expiry_weekly.name
  target_id = "cert-expiry-lambda"
  arn       = module.cert_expiry.function_arn
}

resource "aws_lambda_permission" "events_invoke_cert_expiry" {
  statement_id  = "AllowWeeklySchedule"
  action        = "lambda:InvokeFunction"
  function_name = module.cert_expiry.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.cert_expiry_weekly.arn
}
