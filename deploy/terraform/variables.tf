variable "aws_region" {
  description = "AWS region to deploy into."
  type        = string
  default     = "us-east-1"
}

variable "alert_email" {
  description = "Email address to receive HIGH/CRITICAL alerts."
  type        = string
}

variable "models_to_scan" {
  description = "Comma-separated list of model ids the scheduled scanner checks."
  type        = string
  default     = "distilbert-base-uncased,gpt2,bert-base-uncased"
}

variable "project_name" {
  description = "Name prefix for all resources."
  type        = string
  default     = "ai-sentinel"
}