# Native tests for the s3 module. Mock providers → no AWS calls, creates nothing.

mock_provider "aws" {}
mock_provider "aws" {
  alias = "west"
}

run "name_and_public_access_block_defaults" {
  command = plan

  variables {
    bucket_name = "my-test-bucket"
  }

  assert {
    condition     = aws_s3_bucket.this.bucket == "my-test-bucket"
    error_message = "Bucket name should pass through unchanged."
  }

  assert {
    condition = (
      aws_s3_bucket_public_access_block.this.block_public_acls &&
      aws_s3_bucket_public_access_block.this.block_public_policy &&
      aws_s3_bucket_public_access_block.this.ignore_public_acls &&
      aws_s3_bucket_public_access_block.this.restrict_public_buckets
    )
    error_message = "All four public-access-block settings should default to true."
  }

  assert {
    condition     = length(aws_s3_bucket_website_configuration.this) == 0
    error_message = "Website configuration should be off by default."
  }

  assert {
    condition     = length(aws_s3_bucket_lifecycle_configuration.this) == 0
    error_message = "No lifecycle configuration should be created without rules."
  }
}

run "website_and_lifecycle_toggle_on" {
  command = plan

  variables {
    bucket_name           = "my-site-bucket"
    enable_website_config = true
    lifecycle_rules = [{
      id         = "expire-old"
      expiration = { days = 30 }
    }]
  }

  assert {
    condition     = length(aws_s3_bucket_website_configuration.this) == 1
    error_message = "Website configuration should be created when enabled."
  }

  assert {
    condition     = length(aws_s3_bucket_lifecycle_configuration.this) == 1
    error_message = "Lifecycle configuration should be created when rules are provided."
  }
}
