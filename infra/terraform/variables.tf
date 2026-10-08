variable "aws_region" {
  description = "AWS Region for a future reviewed deployment."
  type        = string
  default     = "ap-south-1"
}

variable "environment" {
  description = "Deployment environment name. Production resources require an explicit opt-in."
  type        = string
  default     = "production"

  validation {
    condition     = contains(["staging", "production"], var.environment)
    error_message = "environment must be staging or production."
  }
}

variable "project_name" {
  description = "Short, lowercase name used in cloud resource names."
  type        = string
  default     = "aegisai"
}

variable "vpc_cidr" {
  description = "Private address space reserved for the future AEGISAI VPC."
  type        = string
  default     = "10.42.0.0/16"
}

variable "enable_deployment" {
  description = "Safety switch. It must be set to true explicitly before Terraform creates cloud resources."
  type        = bool
  default     = false
}
