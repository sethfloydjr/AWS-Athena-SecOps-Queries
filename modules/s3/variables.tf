variable "bucket_name" {
  description = "Name of the S3 bucket"
  type        = string
}

variable "enable_versioning" {
  description = "Enable object versioning on the bucket"
  type        = bool
  default     = true
}

variable "enable_website_config" {
  description = "Create a website configuration (index.html / error.html)"
  type        = bool
  default     = false
}

variable "block_public_acls" {
  description = "S3 public access block — block public ACLs"
  type        = bool
  default     = true
}

variable "block_public_policy" {
  description = "S3 public access block — block public bucket policies"
  type        = bool
  default     = true
}

variable "ignore_public_acls" {
  description = "S3 public access block — ignore public ACLs"
  type        = bool
  default     = true
}

variable "restrict_public_buckets" {
  description = "S3 public access block — restrict public buckets"
  type        = bool
  default     = true
}

variable "lifecycle_rules" {
  description = "List of lifecycle rules to apply to the bucket"
  type = list(object({
    id = string
    filter = optional(object({
      prefix = optional(string)
    }))
    expiration = optional(object({
      days = optional(number)
    }))
    abort_incomplete_multipart_upload = optional(object({
      days_after_initiation = number
    }))
  }))
  default = []
}
