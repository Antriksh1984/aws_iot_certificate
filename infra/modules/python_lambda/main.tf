# One Python Lambda with its own log group and its own IAM role.
# The caller passes the exact permissions the function needs as a policy document.

terraform {
  required_version = ">= 1.6"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = ">= 2.4"
    }
  }
}

variable "name" {
  description = "Function name; also used for the role and log group."
  type        = string
}

variable "description" {
  description = "Function description."
  type        = string
}

variable "source_file" {
  description = "Path to the single-file Python handler module."
  type        = string
}

variable "policy_json" {
  description = "IAM policy document with the function's permissions (logging is added by the module)."
  type        = string
}

variable "environment" {
  description = "Environment variables."
  type        = map(string)
  default     = {}
}

variable "timeout" {
  description = "Timeout in seconds."
  type        = number
  default     = 30
}

variable "memory_size" {
  description = "Memory in MB."
  type        = number
  default     = 128
}

variable "log_retention_days" {
  description = "Log group retention in days."
  type        = number
}

variable "build_dir" {
  description = "Directory for the generated deployment zip."
  type        = string
}

locals {
  module_name = trimsuffix(basename(var.source_file), ".py")
}

data "archive_file" "this" {
  type        = "zip"
  source_file = var.source_file
  output_path = "${var.build_dir}/${var.name}.zip"
}

resource "aws_cloudwatch_log_group" "this" {
  name              = "/aws/lambda/${var.name}"
  retention_in_days = var.log_retention_days
}

data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "this" {
  name               = var.name
  assume_role_policy = data.aws_iam_policy_document.assume.json
}

data "aws_iam_policy_document" "logs" {
  statement {
    sid       = "WriteOwnLogs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.this.arn}:*"]
  }
}

resource "aws_iam_role_policy" "logs" {
  name   = "logs"
  role   = aws_iam_role.this.id
  policy = data.aws_iam_policy_document.logs.json
}

resource "aws_iam_role_policy" "permissions" {
  name   = "permissions"
  role   = aws_iam_role.this.id
  policy = var.policy_json
}

resource "aws_lambda_function" "this" {
  function_name    = var.name
  description      = var.description
  role             = aws_iam_role.this.arn
  runtime          = "python3.12"
  architectures    = ["arm64"]
  handler          = "${local.module_name}.handler"
  filename         = data.archive_file.this.output_path
  source_code_hash = data.archive_file.this.output_base64sha256
  timeout          = var.timeout
  memory_size      = var.memory_size

  environment {
    variables = merge(var.environment, { LOG_LEVEL = "INFO" })
  }

  depends_on = [
    aws_cloudwatch_log_group.this,
    aws_iam_role_policy.logs,
    aws_iam_role_policy.permissions,
  ]
}

output "function_name" {
  description = "Lambda function name."
  value       = aws_lambda_function.this.function_name
}

output "function_arn" {
  description = "Lambda function ARN."
  value       = aws_lambda_function.this.arn
}

output "log_group_name" {
  description = "Lambda log group name."
  value       = aws_cloudwatch_log_group.this.name
}
