# Telemetry path: sensors/+/telemetry -> IoT rule -> Lambda -> DynamoDB.

locals {
  lambdas_dir = abspath("${path.module}/../lambdas")
  build_dir   = abspath("${path.module}/../build")
}

resource "aws_dynamodb_table" "telemetry" {
  name         = "${local.project}-telemetry"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "deviceId"
  range_key    = "ts"

  attribute {
    name = "deviceId"
    type = "S"
  }

  attribute {
    name = "ts"
    type = "N"
  }

  ttl {
    attribute_name = "expiresAt"
    enabled        = true
  }

  point_in_time_recovery {
    enabled = true
  }
}

data "aws_iam_policy_document" "telemetry_processor" {
  statement {
    sid       = "WriteTelemetry"
    actions   = ["dynamodb:PutItem"]
    resources = [aws_dynamodb_table.telemetry.arn]
  }
}

module "telemetry_processor" {
  source = "./modules/python_lambda"

  name               = "${local.project}-telemetry-processor"
  description        = "Validates sensor telemetry from the IoT rule and stores it in DynamoDB."
  source_file        = "${local.lambdas_dir}/telemetry_processor.py"
  build_dir          = local.build_dir
  policy_json        = data.aws_iam_policy_document.telemetry_processor.json
  log_retention_days = var.log_retention_days

  environment = {
    TABLE_NAME = aws_dynamodb_table.telemetry.name
    TTL_DAYS   = tostring(var.data_ttl_days)
  }
}

# IoT rule names allow only letters, digits and underscores, so they use iot_project_ instead of iot-project-.
resource "aws_iot_topic_rule" "telemetry" {
  name        = "iot_project_telemetry"
  description = "Route sensor telemetry to the telemetry-processor Lambda"
  enabled     = true
  sql         = "SELECT *, topic(2) AS deviceId, timestamp() AS ts FROM 'sensors/+/telemetry'"
  sql_version = "2016-03-23"

  lambda {
    function_arn = module.telemetry_processor.function_arn
  }

  error_action {
    cloudwatch_logs {
      log_group_name = aws_cloudwatch_log_group.rule_errors.name
      role_arn       = aws_iam_role.rule_errors.arn
    }
  }
}

resource "aws_lambda_permission" "iot_invoke_telemetry" {
  statement_id   = "AllowIoTRuleInvoke"
  action         = "lambda:InvokeFunction"
  function_name  = module.telemetry_processor.function_name
  principal      = "iot.amazonaws.com"
  source_arn     = aws_iot_topic_rule.telemetry.arn
  source_account = local.account_id
}

# Shared error action for every topic rule: failed rule actions are logged here.
resource "aws_cloudwatch_log_group" "rule_errors" {
  name              = "/aws/iot/${local.project}-rule-errors"
  retention_in_days = var.log_retention_days
}

data "aws_iam_policy_document" "iot_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["iot.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

resource "aws_iam_role" "rule_errors" {
  name               = "${local.project}-rule-errors"
  assume_role_policy = data.aws_iam_policy_document.iot_assume.json
}

data "aws_iam_policy_document" "rule_errors" {
  statement {
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"]
    resources = ["${aws_cloudwatch_log_group.rule_errors.arn}:*"]
  }
}

resource "aws_iam_role_policy" "rule_errors" {
  name   = "write-rule-errors"
  role   = aws_iam_role.rule_errors.id
  policy = data.aws_iam_policy_document.rule_errors.json
}
