output "report_bucket" {
  value = aws_s3_bucket.reports.id
}

output "sns_topic_arn" {
  value = aws_sns_topic.alerts.arn
}

output "lambda_function_name" {
  value = aws_lambda_function.scanner.function_name
}