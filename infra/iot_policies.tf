# Least-privilege device policy: every resource is pinned to the connecting thing's own name.
# "$${...}" is Terraform's escape for the literal IoT policy variable "${...}".

locals {
  thing_var = "$${iot:Connection.Thing.ThingName}"
}

resource "aws_iot_policy" "sensor" {
  name = "${local.project}-sensor-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ConnectAsOwnThingOnly"
        Effect   = "Allow"
        Action   = "iot:Connect"
        Resource = "${local.arn_prefix}:client/${local.thing_var}"
        Condition = {
          Bool = { "iot:Connection.Thing.IsAttached" = "true" }
        }
      },
      {
        Sid    = "PublishOwnTelemetryAndStatus"
        Effect = "Allow"
        Action = "iot:Publish"
        Resource = [
          "${local.arn_prefix}:topic/sensors/${local.thing_var}/telemetry",
          "${local.arn_prefix}:topic/sensors/${local.thing_var}/status",
          "${local.arn_prefix}:topic/$aws/things/${local.thing_var}/shadow/get",
          "${local.arn_prefix}:topic/$aws/things/${local.thing_var}/shadow/update",
        ]
      },
      {
        Sid    = "SubscribeOwnCommandsAndConfig"
        Effect = "Allow"
        Action = "iot:Subscribe"
        Resource = [
          "${local.arn_prefix}:topicfilter/sensors/${local.thing_var}/commands",
          "${local.arn_prefix}:topicfilter/sensors/${local.thing_var}/config",
          "${local.arn_prefix}:topicfilter/$aws/things/${local.thing_var}/shadow/get/*",
          "${local.arn_prefix}:topicfilter/$aws/things/${local.thing_var}/shadow/update/*",
        ]
      },
      {
        Sid    = "ReceiveOwnCommandsAndConfig"
        Effect = "Allow"
        Action = "iot:Receive"
        Resource = [
          "${local.arn_prefix}:topic/sensors/${local.thing_var}/commands",
          "${local.arn_prefix}:topic/sensors/${local.thing_var}/config",
          "${local.arn_prefix}:topic/$aws/things/${local.thing_var}/shadow/get/*",
          "${local.arn_prefix}:topic/$aws/things/${local.thing_var}/shadow/update/*",
        ]
      },
      {
        Sid      = "OwnShadowOnly"
        Effect   = "Allow"
        Action   = ["iot:GetThingShadow", "iot:UpdateThingShadow"]
        Resource = "${local.arn_prefix}:thing/${local.thing_var}"
      },
    ]
  })
}

# Attached by the quarantine Lambda. An explicit Deny overrides every Allow.
resource "aws_iot_policy" "quarantine" {
  name = "${local.project}-quarantine-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "DenyEverything"
        Effect   = "Deny"
        Action   = "iot:*"
        Resource = "*"
      },
    ]
  })
}
