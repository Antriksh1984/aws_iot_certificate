variable "region" {
  description = "AWS region for every resource in the project."
  type        = string
  default     = "ap-south-1"
}

variable "alert_email" {
  description = "Email address for SNS security alerts and budget alerts."
  type        = string

  validation {
    condition     = can(regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", var.alert_email))
    error_message = "alert_email must be a valid email address."
  }
}

variable "sensor_count" {
  description = "Number of well-behaved emulated sensors."
  type        = number
  default     = 5
}

variable "monthly_budget_usd" {
  description = "Monthly cost budget in USD."
  type        = number
  default     = 5
}

variable "log_retention_days" {
  description = "Retention for every CloudWatch log group in the project."
  type        = number
  default     = 14
}

variable "data_ttl_days" {
  description = "Days before telemetry and security-event items expire from DynamoDB."
  type        = number
  default     = 30
}

variable "enable_device_defender_detect" {
  description = <<-EOT
    Create the AWS IoT Device Defender Rules Detect security profile. Detect is closed to
    accounts that were not already using it before 31 Aug 2026, so this defaults to false and
    the project relies on its own detector Lambda instead. Set true only on an account that
    still has Detect access.
  EOT
  type        = bool
  default     = false
}

# Thresholds shared by the self-managed detector and the optional Defender profile.
variable "detection_window_seconds" {
  description = "Evaluation window for count-based behaviours."
  type        = number
  default     = 300
}

variable "max_auth_failures" {
  description = "Authorization failures per window above which a device is in violation."
  type        = number
  default     = 5
}

variable "max_connection_attempts" {
  description = "Connection attempts per window above which a device is in violation."
  type        = number
  default     = 10
}

variable "max_disconnects" {
  description = "Disconnects per window above which a device is in violation."
  type        = number
  default     = 5
}

variable "max_message_bytes" {
  description = "Message size in bytes above which a device is in violation."
  type        = number
  default     = 1024
}
