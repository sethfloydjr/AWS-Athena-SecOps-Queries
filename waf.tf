###############################################
# WAF — CloudFront Web ACL for the dashboard
#
# CloudFront-scoped WebACLs MUST live in us-east-1, which is the default
# provider region. Previously imported from the security_waf remote state.
###############################################

module "dashboard_waf" {
  source = "./modules/waf"

  name        = "athena-security-dashboard"
  description = "WAF protecting the Athena Security Dashboard CloudFront distribution"
  scope       = "CLOUDFRONT"
}
