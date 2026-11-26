# Per-device X.509 identity: one thing + one AWS-issued certificate per emulated device.

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

data "aws_iot_endpoint" "ats" {
  endpoint_type = "iot:Data-ATS"
}

locals {
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition
  arn_prefix = "arn:${local.partition}:iot:${var.region}:${local.account_id}"

  sensor_locations = ["plant-a/line-1", "plant-a/line-2", "plant-b/boiler", "plant-b/compressor", "warehouse/cold-room"]

  sensors = {
    for i in range(1, var.sensor_count + 1) : format("sensor-%03d", i) => {
      location        = local.sensor_locations[(i - 1) % length(local.sensor_locations)]
      deviceType      = "industrial-sensor"
      firmwareVersion = "2.4.1"
    }
  }

  # The rogue device is a legitimately provisioned sensor that gets compromised during the demo.
  devices = merge(local.sensors, {
    "rogue-001" = {
      location        = "plant-c/unknown"
      deviceType      = "industrial-sensor"
      firmwareVersion = "2.4.1"
    }
  })

  certs_dir = abspath("${path.module}/../certs")
}

resource "aws_iot_thing_type" "sensor" {
  name = "${local.project}-industrial-sensor"

  properties {
    description           = "Emulated industrial telemetry sensor"
    searchable_attributes = ["location", "deviceType", "firmwareVersion"]
  }
}

resource "aws_iot_thing" "device" {
  for_each = local.devices

  name            = "${local.project}-${each.key}"
  thing_type_name = aws_iot_thing_type.sensor.name
  attributes      = each.value
}

resource "aws_iot_thing_group" "sensors" {
  name = "${local.project}-sensors"

  properties {
    description = "All iot-project devices. Things and certificates cannot be tagged, so this group is how they are grouped."
  }
}

resource "aws_iot_thing_group_membership" "device" {
  for_each = aws_iot_thing.device

  thing_name       = each.value.name
  thing_group_name = aws_iot_thing_group.sensors.name
}

# AWS IoT generates the key pair and signs the certificate. The private key is
# returned once and kept in Terraform state - fine for a lab, never for production.
resource "aws_iot_certificate" "device" {
  for_each = local.devices

  active = true

  # After creation the certificate status belongs to the quarantine Lambda and
  # `emulator.py reset`; a later apply must not silently re-activate a quarantined device.
  lifecycle {
    ignore_changes = [active]
  }

  # Destroy certificates before the quarantine policy. The quarantine Lambda attaches
  # that policy outside Terraform, and AWS IoT deletes neither the certificate nor the
  # policy while they are attached, so `make destroy` first runs `emulator.py pre-destroy`
  # to detach it.
  depends_on = [aws_iot_policy.quarantine]
}

resource "aws_iot_thing_principal_attachment" "device" {
  for_each = local.devices

  thing     = aws_iot_thing.device[each.key].name
  principal = aws_iot_certificate.device[each.key].arn
}

resource "aws_iot_policy_attachment" "device" {
  for_each = local.devices

  policy = aws_iot_policy.sensor.name
  target = aws_iot_certificate.device[each.key].arn
}

resource "local_sensitive_file" "certificate_pem" {
  for_each = local.devices

  filename        = "${local.certs_dir}/${aws_iot_thing.device[each.key].name}.cert.pem"
  content         = aws_iot_certificate.device[each.key].certificate_pem
  file_permission = "0600"
}

resource "local_sensitive_file" "private_key" {
  for_each = local.devices

  filename        = "${local.certs_dir}/${aws_iot_thing.device[each.key].name}.private.key"
  content         = aws_iot_certificate.device[each.key].private_key
  file_permission = "0600"
}
