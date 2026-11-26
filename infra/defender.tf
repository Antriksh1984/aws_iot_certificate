# Detection: SNS alert topic, Device Defender Audit, and rogue-device detection.
#
# Device Defender *Detect* (security profiles) is closed to accounts that were not using it
# before 31 Aug 2026. The detector Lambda below implements the same four cloud-side rules
# and publishes Defender-format violation messages, so the response path is identical. The
# real security profile is still defined, behind var.enable_device_defender_detect.

locals {
  security_profile_name = "${local.project}-security-profile"
}

# ---------------------------------------------------------------- alert topic

resource "aws_sns_topic" "security_alerts" {
  name = "${local.project}-security-alerts"
}

resource "aws_sns_topic_subscription" "alert_email" {
  topic_arn = aws_sns_topic.security_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Role IoT (Defender alerts and audit notifications) assumes to publish to the topic.
resource "aws_iam_role" "defender_alerts" {
  name               = "${local.project}-defender-alerts"
  assume_role_policy = data.aws_iam_policy_document.iot_assume.json
}

data "aws_iam_policy_document" "defender_alerts" {
  statement {
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.security_alerts.arn]
  }
}

resource "aws_iam_role_policy" "defender_alerts" {
  name   = "publish-security-alerts"
  role   = aws_iam_role.defender_alerts.id
  policy = data.aws_iam_policy_document.defender_alerts.json
}

# ---------------------------------------------------------------- Device Defender Audit

resource "aws_iam_role" "defender_audit" {
  name               = "${local.project}-defender-audit"
  assume_role_policy = data.aws_iam_policy_document.iot_assume.json
}

# AWS-managed read-only audit policy (describe/list on IoT config); not a *FullAccess policy.
resource "aws_iam_role_policy_attachment" "defender_audit" {
  role       = aws_iam_role.defender_audit.name
  policy_arn = "arn:${local.partition}:iam::aws:policy/service-role/AWSIoTDeviceDefenderAudit"
}

resource "awscc_iot_account_audit_configuration" "this" {
  account_id = local.account_id
  role_arn   = aws_iam_role.defender_audit.arn

  audit_check_configurations = {
    device_certificate_expiring_check = {
      enabled = true
      configuration = {
        cert_expiration_threshold_in_days = "30"
      }
    }
    device_certificate_shared_check               = { enabled = true }
    iot_policy_overly_permissive_check            = { enabled = true }
    logging_disabled_check                        = { enabled = true }
    conflicting_client_ids_check                  = { enabled = true }
    revoked_device_certificate_still_active_check = { enabled = true }
    device_certificate_key_quality_check          = { enabled = true }
  }

  audit_notification_target_configurations = {
    sns = {
      enabled    = true
      role_arn   = aws_iam_role.defender_alerts.arn
      target_arn = aws_sns_topic.security_alerts.arn
    }
  }

  depends_on = [
    aws_iam_role_policy_attachment.defender_audit,
    aws_iam_role_policy.defender_alerts,
  ]
}

resource "awscc_iot_scheduled_audit" "daily" {
  scheduled_audit_name = "${local.project}-daily-audit"
  frequency            = "DAILY"

  target_check_names = [
    "DEVICE_CERTIFICATE_EXPIRING_CHECK",
    "DEVICE_CERTIFICATE_SHARED_CHECK",
    "IOT_POLICY_OVERLY_PERMISSIVE_CHECK",
    "LOGGING_DISABLED_CHECK",
    "CONFLICTING_CLIENT_IDS_CHECK",
    "REVOKED_DEVICE_CERTIFICATE_STILL_ACTIVE_CHECK",
    "DEVICE_CERTIFICATE_KEY_QUALITY_CHECK",
  ]

  tags = [for k, v in local.common_tags : { key = k, value = v }]

  depends_on = [awscc_iot_account_audit_configuration.this]
}

# ---------------------------------------------------------------- Defender Detect (optional)

resource "awscc_iot_security_profile" "this" {
  count = var.enable_device_defender_detect ? 1 : 0

  security_profile_name        = local.security_profile_name
  security_profile_description = "Rules Detect for iot-project devices"
  target_arns                  = [aws_iot_thing_group.sensors.arn]

  behaviors = [
    {
      name   = "excessive-authorization-failures"
      metric = "aws:num-authorization-failures"
      criteria = {
        comparison_operator = "greater-than"
        value               = { count = tostring(var.max_auth_failures) }
        duration_seconds    = var.detection_window_seconds
      }
    },
    {
      name   = "excessive-connection-attempts"
      metric = "aws:num-connection-attempts"
      criteria = {
        comparison_operator = "greater-than"
        value               = { count = tostring(var.max_connection_attempts) }
        duration_seconds    = var.detection_window_seconds
      }
    },
    {
      name   = "oversized-messages"
      metric = "aws:message-byte-size"
      criteria = {
        comparison_operator = "greater-than"
        value               = { count = tostring(var.max_message_bytes) }
      }
    },
    {
      name   = "excessive-disconnects"
      metric = "aws:num-disconnects"
      criteria = {
        comparison_operator = "greater-than"
        value               = { count = tostring(var.max_disconnects) }
        duration_seconds    = var.detection_window_seconds
      }
    },
  ]

  alert_targets = {
    SNS = {
      alert_target_arn = aws_sns_topic.security_alerts.arn
      role_arn         = aws_iam_role.defender_alerts.arn
    }
  }

  tags = [for k, v in local.common_tags : { key = k, value = v }]
}

# ---------------------------------------------------------------- self-managed detector

# Per-device counters, one item per (device, metric, 5-minute window). Expire after a day.
resource "aws_dynamodb_table" "device_metrics" {
  name         = "${local.project}-device-metrics"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "deviceId"
  range_key    = "metricWindow"

  attribute {
    name = "deviceId"
    type = "S"
  }

  attribute {
    name = "metricWindow"
    type = "S"
  }

  ttl {
    attribute_name = "expiresAt"
    enabled        = true
  }

  point_in_time_recovery {
    enabled = true
  }
}

data "aws_iam_policy_document" "detector" {
  statement {
    sid       = "CountBehaviour"
    actions   = ["dynamodb:UpdateItem"]
    resources = [aws_dynamodb_table.device_metrics.arn]
  }
  statement {
    sid       = "RecordViolation"
    actions   = ["dynamodb:PutItem"]
    resources = [aws_dynamodb_table.security_events.arn]
  }
  statement {
    sid       = "PublishViolation"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.security_alerts.arn]
  }
  statement {
    sid       = "ResolveCertificateToThing"
    actions   = ["iot:ListPrincipalThings"]
    resources = ["${local.arn_prefix}:cert/*"]
  }
}

module "detector" {
  source = "./modules/python_lambda"

  name               = "${local.project}-detector"
  description        = "Counts per-device auth failures, connects, disconnects and message size; publishes Defender-format violations."
  source_file        = "${local.lambdas_dir}/detector.py"
  build_dir          = local.build_dir
  policy_json        = data.aws_iam_policy_document.detector.json
  log_retention_days = var.log_retention_days

  environment = {
    METRICS_TABLE           = aws_dynamodb_table.device_metrics.name
    EVENTS_TABLE            = aws_dynamodb_table.security_events.name
    ALERT_TOPIC_ARN         = aws_sns_topic.security_alerts.arn
    SECURITY_PROFILE_NAME   = local.security_profile_name
    THING_PREFIX            = "${local.project}-"
    WINDOW_SECONDS          = tostring(var.detection_window_seconds)
    MAX_AUTH_FAILURES       = tostring(var.max_auth_failures)
    MAX_CONNECTION_ATTEMPTS = tostring(var.max_connection_attempts)
    MAX_DISCONNECTS         = tostring(var.max_disconnects)
    MAX_MESSAGE_BYTES       = tostring(var.max_message_bytes)
    TTL_DAYS                = tostring(var.data_ttl_days)
  }
}

# Source 1: connect / disconnect lifecycle events for project devices.
resource "aws_iot_topic_rule" "lifecycle" {
  name        = "iot_project_lifecycle_events"
  description = "Feed device connect/disconnect events to the detector"
  enabled     = true
  sql         = "SELECT clientId, eventType, principalIdentifier, disconnectReason, timestamp FROM '$aws/events/presence/+/+' WHERE startswith(clientId, '${local.project}-')"
  sql_version = "2016-03-23"

  lambda {
    function_arn = module.detector.function_arn
  }

  error_action {
    cloudwatch_logs {
      log_group_name = aws_cloudwatch_log_group.rule_errors.name
      role_arn       = aws_iam_role.rule_errors.arn
    }
  }
}

# Source 2: only messages larger than the limit reach the detector. base64 length > 4*floor(n/3)
# means the payload is at least ~n bytes; the Lambda then checks the exact size.
resource "aws_iot_topic_rule" "message_size" {
  name        = "iot_project_oversized_messages"
  description = "Feed oversized device messages to the detector"
  enabled     = true
  sql         = "SELECT clientid() AS clientId, principal() AS principal, topic() AS topic, encode(*, 'base64') AS payloadB64 FROM 'sensors/#' WHERE length(encode(*, 'base64')) > ${4 * floor(var.max_message_bytes / 3)}"
  sql_version = "2016-03-23"

  lambda {
    function_arn = module.detector.function_arn
  }

  error_action {
    cloudwatch_logs {
      log_group_name = aws_cloudwatch_log_group.rule_errors.name
      role_arn       = aws_iam_role.rule_errors.arn
    }
  }
}

resource "aws_lambda_permission" "iot_invoke_detector" {
  for_each = {
    lifecycle    = aws_iot_topic_rule.lifecycle.arn
    message_size = aws_iot_topic_rule.message_size.arn
  }

  statement_id   = "AllowIoTRuleInvoke-${each.key}"
  action         = "lambda:InvokeFunction"
  function_name  = module.detector.function_name
  principal      = "iot.amazonaws.com"
  source_arn     = each.value
  source_account = local.account_id
}

# Source 3: authorization and connect failures from the AWS IoT log (ERROR/WARN entries).
resource "aws_lambda_permission" "logs_invoke_detector" {
  statement_id   = "AllowIoTLogsSubscription"
  action         = "lambda:InvokeFunction"
  function_name  = module.detector.function_name
  principal      = "logs.amazonaws.com"
  source_arn     = "${aws_cloudwatch_log_group.iot_logs.arn}:*"
  source_account = local.account_id
}

resource "aws_cloudwatch_log_subscription_filter" "iot_failures" {
  name            = "${local.project}-iot-failures"
  log_group_name  = aws_cloudwatch_log_group.iot_logs.name
  filter_pattern  = "{ $.status = \"Failure\" }"
  destination_arn = module.detector.function_arn

  depends_on = [aws_lambda_permission.logs_invoke_detector]
}
