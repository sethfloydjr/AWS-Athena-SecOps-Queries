variable "name" {
  description = "Name of the WAFv2 Web ACL"
  type        = string
}

variable "description" {
  description = "Description of the Web ACL"
  type        = string
  default     = "WAFv2 Web ACL"
}

variable "scope" {
  description = "Web ACL scope — CLOUDFRONT (must be created in us-east-1) or REGIONAL"
  type        = string
  default     = "CLOUDFRONT"

  validation {
    condition     = contains(["CLOUDFRONT", "REGIONAL"], var.scope)
    error_message = "scope must be CLOUDFRONT or REGIONAL."
  }
}

variable "rate_limit" {
  description = "Per-IP request limit per 5-minute window before being blocked"
  type        = number
  default     = 2000
}

variable "managed_rule_groups" {
  description = "AWS managed rule groups to attach, in priority order"
  type = list(object({
    name     = string
    priority = number
  }))
  default = [
    { name = "AWSManagedRulesCommonRuleSet", priority = 10 },
    { name = "AWSManagedRulesKnownBadInputsRuleSet", priority = 20 },
    { name = "AWSManagedRulesAmazonIpReputationList", priority = 30 },
    { name = "AWSManagedRulesAnonymousIpList", priority = 40 },
  ]
}
