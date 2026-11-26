output "region" {
  description = "AWS region."
  value       = var.region
}

output "iot_endpoint" {
  description = "AWS IoT Core data endpoint (ATS)."
  value       = data.aws_iot_endpoint.ats.endpoint_address
}

output "thing_names" {
  description = "Thing name per device key."
  value       = { for k, t in aws_iot_thing.device : k => t.name }
}

output "certificate_ids" {
  description = "Certificate ID per device key."
  value       = { for k, c in aws_iot_certificate.device : k => c.id }
}

output "cert_files" {
  description = "Local certificate and private-key paths per device key."
  value = { for k in keys(local.devices) : k => {
    certificate = local_sensitive_file.certificate_pem[k].filename
    private_key = local_sensitive_file.private_key[k].filename
  } }
}

output "certs_dir" {
  description = "Directory holding device certificates and the Amazon Root CA."
  value       = local.certs_dir
}

output "sensor_policy_name" {
  description = "Least-privilege device policy."
  value       = aws_iot_policy.sensor.name
}

output "quarantine_policy_name" {
  description = "Deny-all quarantine policy."
  value       = aws_iot_policy.quarantine.name
}

output "telemetry_table" {
  description = "DynamoDB table with sensor telemetry."
  value       = aws_dynamodb_table.telemetry.name
}

output "security_events_table" {
  description = "DynamoDB table with violations and quarantine actions."
  value       = aws_dynamodb_table.security_events.name
}

output "device_metrics_table" {
  description = "DynamoDB table with the detector's per-device window counters."
  value       = aws_dynamodb_table.device_metrics.name
}

output "security_alerts_topic_arn" {
  description = "SNS topic for security alerts."
  value       = aws_sns_topic.security_alerts.arn
}

output "lambda_functions" {
  description = "Lambda function names."
  value       = local.lambda_functions
}

output "dashboard_url" {
  description = "CloudWatch dashboard."
  value       = "https://${var.region}.console.aws.amazon.com/cloudwatch/home?region=${var.region}#dashboards/dashboard/${aws_cloudwatch_dashboard.this.dashboard_name}"
}

output "resource_group_url" {
  description = "Resource Group listing every tagged project resource."
  value       = "https://${var.region}.console.aws.amazon.com/resource-groups/group/${aws_resourcegroups_group.project.name}?region=${var.region}"
}
