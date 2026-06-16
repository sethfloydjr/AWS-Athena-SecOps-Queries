output "web_acl_arn" {
  description = "ARN of the Web ACL — attach to CloudFront/ALB/API Gateway"
  value       = aws_wafv2_web_acl.this.arn
}

output "web_acl_id" {
  description = "ID of the Web ACL"
  value       = aws_wafv2_web_acl.this.id
}

output "web_acl_name" {
  description = "Name of the Web ACL"
  value       = aws_wafv2_web_acl.this.name
}
