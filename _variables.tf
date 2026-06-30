variable "service_name" {
  type    = string
  default = "Athena-Security-Queries"
}

variable "owning_team" {
  type    = string
  default = "SecOps"
}

variable "automation_tf" {
  type    = string
  default = "Terraform"
}

variable "config_bucket_name" {
  description = "S3 bucket containing AWS Config snapshots"
  type        = string
  default     = "company-config"
}

variable "config_s3_prefix" {
  description = "S3 key prefix for Config delivery channel data"
  type        = string
  default     = "config"
}

variable "results_bucket_name" {
  description = "S3 bucket for Athena query results"
  type        = string
  default     = "company-athena-security-results"
}

variable "results_expiration_days" {
  description = "Number of days to retain Athena query results before auto-deletion"
  type        = number
  default     = 90
}

variable "bytes_scanned_cutoff" {
  description = "Maximum bytes a single Athena query can scan before being cancelled (100 GB default)"
  type        = number
  default     = 214748364800 # 200 GB in bytes
}

variable "config_regions" {
  description = "AWS regions monitored by Config"
  type        = list(string)
  default     = ["us-east-1", "us-east-2", "us-west-1", "us-west-2"]
}

variable "cloudtrail_bucket_name" {
  description = "S3 bucket containing org-wide CloudTrail logs (lives in Root account)"
  type        = string
  default     = "company-org-cloudtrail"
}

variable "cloudtrail_s3_prefix" {
  description = "S3 key prefix for CloudTrail delivery"
  type        = string
  default     = "company-org"
}

####################################
# Dashboard variables
####################################

variable "dashboard_bucket_name" {
  description = "S3 bucket name for the Athena dashboard static site"
  type        = string
  default     = "company-athena-dashboard.security.example.com"
}

variable "dashboard_domain" {
  description = "Domain name for the dashboard"
  type        = string
  default     = "company-athena-dashboard.security.example.com"
}

variable "okta_issuer_url" {
  description = "Okta OIDC issuer URL for JWT validation"
  type        = string
  default     = "https://example.okta.com"
}

variable "okta_client_id" {
  description = "Okta OIDC SPA client ID — not sensitive, embedded in frontend JS for PKCE auth flow"
  type        = string
  default     = "0oaEXAMPLECLIENTID00" # Not sensitive
}

variable "hosted_zone_id" {
  description = "Route53 hosted zone ID for security.example.com"
  type        = string
  default     = "Z00000000000000000000"
}

variable "cloudtrail_regions" {
  description = "AWS regions to include in CloudTrail partition projection. Includes all standard regions since the org trail is multi-region and an attacker could operate from any region."
  type        = list(string)
  default = [
    "us-east-1", "us-east-2", "us-west-1", "us-west-2",
    "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-central-2", "eu-north-1", "eu-south-1", "eu-south-2",
    "ap-southeast-1", "ap-southeast-2", "ap-southeast-3", "ap-northeast-1", "ap-northeast-2", "ap-northeast-3", "ap-south-1", "ap-south-2", "ap-east-1",
    "ca-central-1", "ca-west-1",
    "sa-east-1",
    "me-south-1", "me-central-1",
    "af-south-1",
    "il-central-1",
  ]
}
