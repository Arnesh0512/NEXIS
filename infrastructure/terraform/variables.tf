variable "aws_region" {
  description = "AWS region for cryptographic asset provisioning"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Deployment tier"
  type        = string
  default     = "production"
}

variable "enable_pqc_transition" {
  description = "Flag enabling Post-Quantum hybrid algorithms in infrastructure"
  type        = bool
  default     = true
}
