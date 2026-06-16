###############################################
# Athena Query Results Bucket
###############################################
module "athena_results" {
  source = "./modules/s3"
  providers = {
    aws.west = aws.west
  }

  bucket_name = var.results_bucket_name

  lifecycle_rules = [
    {
      id = "expire-query-results"
      filter = {
        prefix = ""
      }
      expiration = {
        days = var.results_expiration_days
      }
    },
    {
      id = "abort-incomplete-multipart-uploads"
      filter = {
        prefix = ""
      }
      abort_incomplete_multipart_upload = {
        days_after_initiation = 2
      }
    },
  ]
}
