output "athena_workgroup_name" {
  description = "Name of the Athena workgroup for security IR queries"
  value       = aws_athena_workgroup.security_ir.name
}

output "glue_database_name" {
  description = "Name of the Glue catalog database"
  value       = aws_glue_catalog_database.security_ir.name
}

output "results_bucket_name" {
  description = "S3 bucket storing Athena query results"
  value       = module.athena_results.id
}
