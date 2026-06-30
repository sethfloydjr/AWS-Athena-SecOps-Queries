# Native tests for the waf module. Mock provider → no AWS calls, creates nothing.

mock_provider "aws" {}

run "creates_web_acl_with_passed_name_and_scope" {
  command = plan

  variables {
    name  = "my-web-acl"
    scope = "REGIONAL"
  }

  assert {
    condition     = aws_wafv2_web_acl.this.name == "my-web-acl"
    error_message = "Web ACL name should pass through unchanged."
  }

  assert {
    condition     = aws_wafv2_web_acl.this.scope == "REGIONAL"
    error_message = "Web ACL scope should pass through unchanged."
  }
}

run "rejects_invalid_scope" {
  command = plan

  variables {
    name  = "my-web-acl"
    scope = "BOGUS"
  }

  expect_failures = [
    var.scope,
  ]
}
