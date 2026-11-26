# AWS IoT logging, CloudWatch dashboard and alarms.

# ---------------------------------------------------------------- IoT logging (WARN)

# AWS IoT always writes to this fixed log group name, so it cannot carry the project prefix.
resource "aws_cloudwatch_log_group" "iot_logs" {
  name              = "AWSIotLogsV2"
  retention_in_days = var.log_retention_days
}

resource "aws_iam_role" "iot_logging" {
  name               = "${local.project}-iot-logging"
  assume_role_policy = data.aws_iam_policy_document.iot_assume.json
}

data "aws_iam_policy_document" "iot_logging" {
  statement {
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "logs:DescribeLogStreams",
    ]
    resources = ["${aws_cloudwatch_log_group.iot_logs.arn}:*"]
  }
}

resource "aws_iam_role_policy" "iot_logging" {
  name   = "write-iot-logs"
  role   = aws_iam_role.iot_logging.id
  policy = data.aws_iam_policy_document.iot_logging.json
}

resource "aws_iot_logging_options" "this" {
  default_log_level = "WARN"
  role_arn          = aws_iam_role.iot_logging.arn

  depends_on = [aws_iam_role_policy.iot_logging]
}

# ---------------------------------------------------------------- custom metrics from logs

resource "aws_cloudwatch_log_metric_filter" "violations" {
  name           = "${local.project}-violations"
  log_group_name = module.detector.log_group_name
  pattern        = "{ $.message = \"violation detected\" }"

  metric_transformation {
    name          = "DeviceViolations"
    namespace     = local.project
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_log_metric_filter" "quarantines" {
  name           = "${local.project}-quarantines"
  log_group_name = module.quarantine.log_group_name
  pattern        = "{ $.message = \"device quarantined\" }"

  metric_transformation {
    name          = "DevicesQuarantined"
    namespace     = local.project
    value         = "1"
    default_value = "0"
  }
}

# ---------------------------------------------------------------- dashboard

locals {
  lambda_functions = {
    telemetry  = module.telemetry_processor.function_name
    detector   = module.detector.function_name
    quarantine = module.quarantine.function_name
    expiry     = module.cert_expiry.function_name
  }

  # AWS IoT does not publish Subscribe.AuthError for denied MQTT 5 subscribes; Connection.AuthNError
  # counts TLS-level rejections (unknown or mismatched certificates).
  iot_metric = { for m in ["Connect.Success", "Connect.AuthError", "PublishIn.AuthError", "Connection.AuthNError"] :
    m => ["AWS/IoT", m, "Protocol", "MQTT", { stat = "Sum" }]
  }
}

resource "aws_cloudwatch_dashboard" "this" {
  dashboard_name = "${local.project}-dashboard"

  dashboard_body = jsonencode({
    widgets = [
      {
        type = "metric", x = 0, y = 0, width = 12, height = 6
        properties = {
          title   = "Connections"
          region  = var.region
          view    = "timeSeries"
          period  = 60
          metrics = [local.iot_metric["Connect.Success"], local.iot_metric["Connect.AuthError"]]
        }
      },
      {
        type = "metric", x = 12, y = 0, width = 12, height = 6
        properties = {
          title   = "Blocked by AWS IoT (denied publishes, rejected certificates)"
          region  = var.region
          view    = "timeSeries"
          period  = 60
          metrics = [local.iot_metric["PublishIn.AuthError"], local.iot_metric["Connection.AuthNError"]]
        }
      },
      {
        type = "metric", x = 0, y = 6, width = 12, height = 6
        properties = {
          title  = "Device violations and quarantines"
          region = var.region
          view   = "timeSeries"
          period = 60
          metrics = [
            [local.project, "DeviceViolations", { stat = "Sum" }],
            [local.project, "DevicesQuarantined", { stat = "Sum" }],
          ]
        }
      },
      {
        type = "metric", x = 12, y = 6, width = 12, height = 6
        properties = {
          title   = "Lambda errors"
          region  = var.region
          view    = "timeSeries"
          period  = 300
          metrics = [for fn in values(local.lambda_functions) : ["AWS/Lambda", "Errors", "FunctionName", fn, { stat = "Sum" }]]
        }
      },
      {
        type = "metric", x = 0, y = 12, width = 24, height = 6
        properties = {
          title   = "Lambda invocations"
          region  = var.region
          view    = "timeSeries"
          period  = 300
          metrics = [for fn in values(local.lambda_functions) : ["AWS/Lambda", "Invocations", "FunctionName", fn, { stat = "Sum" }]]
        }
      },
    ]
  })
}

# ---------------------------------------------------------------- alarms

resource "aws_cloudwatch_metric_alarm" "connect_auth_errors" {
  alarm_name          = "${local.project}-connect-auth-errors"
  alarm_description   = "More than 5 rejected MQTT connections in 5 minutes"
  namespace           = "AWS/IoT"
  metric_name         = "Connect.AuthError"
  dimensions          = { Protocol = "MQTT" }
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 5
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
}

resource "aws_cloudwatch_metric_alarm" "lambda_errors" {
  for_each = local.lambda_functions

  alarm_name          = "${each.value}-errors"
  alarm_description   = "Lambda ${each.value} reported errors"
  namespace           = "AWS/Lambda"
  metric_name         = "Errors"
  dimensions          = { FunctionName = each.value }
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
}
