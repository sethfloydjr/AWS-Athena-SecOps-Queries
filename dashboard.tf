# Athena Security Dashboard
#
# Interactive web dashboard for running security Athena queries without the AWS console.
# Auth: Okta OIDC (PKCE) — requires HTTPS for Web Crypto API (code challenge generation)
# Components: CloudFront + S3 static site, API Gateway HTTP API, Lambda backend
#
# Frontend code: dashboard/frontend/index.html
# Lambda code:   dashboard/lambda/athena_dashboard.py


####################################
# IAM
####################################

resource "aws_iam_role" "dashboard_lambda" {
  name               = "athena-security-dashboard"
  assume_role_policy = data.aws_iam_policy_document.dashboard_lambda_assume.json


}

resource "aws_iam_role_policy" "dashboard_lambda" {
  name   = "athena-security-dashboard"
  role   = aws_iam_role.dashboard_lambda.id
  policy = data.aws_iam_policy_document.dashboard_lambda_policy.json
}


####################################
# LAMBDA
####################################

resource "aws_lambda_function" "dashboard" {
  function_name    = "athena-security-dashboard"
  description      = "Backend for Athena Security Dashboard — runs queries, returns results"
  filename         = data.archive_file.dashboard_lambda.output_path
  source_code_hash = data.archive_file.dashboard_lambda.output_base64sha256
  handler          = "athena_dashboard.handler"
  runtime          = "python3.12"
  timeout          = 30
  memory_size      = 256
  role             = aws_iam_role.dashboard_lambda.arn

  environment {
    variables = {
      WORKGROUP       = "security-incident-response"
      DATABASE        = "security_incident_response"
      RESULTS_BUCKET  = var.results_bucket_name
      MAX_RESULT_ROWS = "1000"
    }
  }


}

resource "aws_cloudwatch_log_group" "dashboard_lambda" {
  name              = "/aws/lambda/athena-security-dashboard"
  retention_in_days = 30


}

resource "aws_lambda_permission" "dashboard_apigw" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.dashboard.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.dashboard.execution_arn}/*/*"
}


####################################
# API GATEWAY
####################################

resource "aws_apigatewayv2_api" "dashboard" {
  name          = "athena-security-dashboard"
  protocol_type = "HTTP"
  description   = "API for Athena Security Dashboard"

  cors_configuration {
    allow_origins = ["https://${var.dashboard_domain}"]
    allow_methods = ["GET", "POST", "DELETE", "OPTIONS"]
    allow_headers = ["Authorization", "Content-Type"]
    max_age       = 3600
  }


}

# Okta JWT Authorizer
resource "aws_apigatewayv2_authorizer" "okta" {
  api_id           = aws_apigatewayv2_api.dashboard.id
  authorizer_type  = "JWT"
  identity_sources = ["$request.header.Authorization"]
  name             = "okta-jwt"

  jwt_configuration {
    audience = [var.okta_client_id]
    issuer   = var.okta_issuer_url
  }
}

# Lambda integration
resource "aws_apigatewayv2_integration" "dashboard_lambda" {
  api_id                 = aws_apigatewayv2_api.dashboard.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.dashboard.invoke_arn
  payload_format_version = "2.0"
}

# Routes
resource "aws_apigatewayv2_route" "get_queries" {
  api_id             = aws_apigatewayv2_api.dashboard.id
  route_key          = "GET /queries"
  target             = "integrations/${aws_apigatewayv2_integration.dashboard_lambda.id}"
  authorization_type = "JWT"
  authorizer_id      = aws_apigatewayv2_authorizer.okta.id
}

resource "aws_apigatewayv2_route" "post_query_start" {
  api_id             = aws_apigatewayv2_api.dashboard.id
  route_key          = "POST /query/start"
  target             = "integrations/${aws_apigatewayv2_integration.dashboard_lambda.id}"
  authorization_type = "JWT"
  authorizer_id      = aws_apigatewayv2_authorizer.okta.id
}

resource "aws_apigatewayv2_route" "get_query_status" {
  api_id             = aws_apigatewayv2_api.dashboard.id
  route_key          = "GET /query/status/{id}"
  target             = "integrations/${aws_apigatewayv2_integration.dashboard_lambda.id}"
  authorization_type = "JWT"
  authorizer_id      = aws_apigatewayv2_authorizer.okta.id
}

resource "aws_apigatewayv2_route" "get_query_results" {
  api_id             = aws_apigatewayv2_api.dashboard.id
  route_key          = "GET /query/results/{id}"
  target             = "integrations/${aws_apigatewayv2_integration.dashboard_lambda.id}"
  authorization_type = "JWT"
  authorizer_id      = aws_apigatewayv2_authorizer.okta.id
}

resource "aws_apigatewayv2_route" "post_query_stop" {
  api_id             = aws_apigatewayv2_api.dashboard.id
  route_key          = "POST /query/stop/{id}"
  target             = "integrations/${aws_apigatewayv2_integration.dashboard_lambda.id}"
  authorization_type = "JWT"
  authorizer_id      = aws_apigatewayv2_authorizer.okta.id
}

resource "aws_apigatewayv2_route" "post_query_save" {
  api_id             = aws_apigatewayv2_api.dashboard.id
  route_key          = "POST /query/save"
  target             = "integrations/${aws_apigatewayv2_integration.dashboard_lambda.id}"
  authorization_type = "JWT"
  authorizer_id      = aws_apigatewayv2_authorizer.okta.id
}

resource "aws_apigatewayv2_route" "delete_query_custom" {
  api_id             = aws_apigatewayv2_api.dashboard.id
  route_key          = "DELETE /query/custom/{id}"
  target             = "integrations/${aws_apigatewayv2_integration.dashboard_lambda.id}"
  authorization_type = "JWT"
  authorizer_id      = aws_apigatewayv2_authorizer.okta.id
}

# Auto-deploy stage
resource "aws_apigatewayv2_stage" "dashboard" {
  api_id      = aws_apigatewayv2_api.dashboard.id
  name        = "$default"
  auto_deploy = true

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.dashboard_api_gateway.arn
    format = jsonencode({
      requestId      = "$context.requestId"
      ip             = "$context.identity.sourceIp"
      requestTime    = "$context.requestTime"
      httpMethod     = "$context.httpMethod"
      routeKey       = "$context.routeKey"
      status         = "$context.status"
      protocol       = "$context.protocol"
      responseLength = "$context.responseLength"
      errorMessage   = "$context.error.message"
    })
  }


}

resource "aws_cloudwatch_log_group" "dashboard_api_gateway" {
  name              = "/aws/apigateway/athena-security-dashboard"
  retention_in_days = 30


}


####################################
# S3 — STATIC FRONTEND (using shared S3 module)
####################################

module "dashboard_s3" {
  source = "./modules/s3"

  providers = {
    aws      = aws
    aws.west = aws.west
  }

  bucket_name             = var.dashboard_bucket_name
  enable_website_config   = true
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true

  lifecycle_rules = [
    {
      id = "abort-incomplete-multipart-uploads"
      abort_incomplete_multipart_upload = {
        days_after_initiation = 2
      }
    }
  ]
}

# Bucket policy — CloudFront OAI access only. The bucket is no longer publicly
# readable; CloudFront serves as the only entry point with HTTPS.
resource "aws_s3_bucket_policy" "dashboard" {
  bucket = module.dashboard_s3.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "CloudFrontOAIAccess"
        Effect    = "Allow"
        Principal = { AWS = aws_cloudfront_origin_access_identity.dashboard.iam_arn }
        Action    = "s3:GetObject"
        Resource  = "${module.dashboard_s3.arn}/*"
      }
    ]
  })
}

# Login page — minimal, no sensitive config exposed
resource "aws_s3_object" "dashboard_index" {
  bucket       = module.dashboard_s3.id
  key          = "index.html"
  content_type = "text/html"
  content      = file("${path.module}/dashboard/frontend/index.html")
  etag         = filemd5("${path.module}/dashboard/frontend/index.html")
}

# Dashboard app — full application, loaded only after Okta auth
resource "aws_s3_object" "dashboard_app" {
  bucket       = module.dashboard_s3.id
  key          = "dashboard.html"
  content_type = "text/html"

  content = replace(
    file("${path.module}/dashboard/frontend/dashboard.html"),
    "$${API_GATEWAY_URL}",
    aws_apigatewayv2_stage.dashboard.invoke_url
  )

  etag = md5(replace(
    file("${path.module}/dashboard/frontend/dashboard.html"),
    "$${API_GATEWAY_URL}",
    aws_apigatewayv2_stage.dashboard.invoke_url
  ))
}

resource "aws_s3_object" "robots_txt" {
  bucket       = module.dashboard_s3.id
  key          = "robots.txt"
  content_type = "text/plain"
  content      = "User-agent: *\nDisallow: /\n"
  etag         = md5("User-agent: *\nDisallow: /\n")
}

resource "aws_s3_object" "security_txt" {
  bucket       = module.dashboard_s3.id
  key          = ".well-known/security.txt"
  content_type = "text/plain"
  content      = "Contact: mailto:security@example.com\nExpires: 2027-05-15T00:00:00Z\nPreferred-Languages: en\n"
  etag         = md5("Contact: mailto:security@example.com\nExpires: 2027-05-15T00:00:00Z\nPreferred-Languages: en\n")
}


####################################
# ACM CERTIFICATE
####################################

resource "aws_acm_certificate" "dashboard" {
  domain_name       = var.dashboard_domain
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_route53_record" "dashboard_cert_validation" {
  for_each = {
    for dvo in aws_acm_certificate.dashboard.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  }

  zone_id = var.hosted_zone_id
  name    = each.value.name
  type    = each.value.type
  ttl     = 60
  records = [each.value.record]
}

resource "aws_acm_certificate_validation" "dashboard" {
  certificate_arn         = aws_acm_certificate.dashboard.arn
  validation_record_fqdns = [for record in aws_route53_record.dashboard_cert_validation : record.fqdn]
}


####################################
# CLOUDFRONT
####################################

resource "aws_cloudfront_origin_access_identity" "dashboard" {
  comment = "OAI for Athena Security Dashboard"
}

resource "aws_cloudfront_function" "dashboard_auth" {
  name    = "athena-dashboard-auth-check"
  runtime = "cloudfront-js-2.0"
  comment = "Validates JWT cookie before serving protected Athena dashboard content"
  publish = true
  code = templatefile("${path.module}/dashboard/frontend/auth-check.js", {
    okta_issuer_url = var.okta_issuer_url
    cookie_name     = "athena_token"
  })
}

# Security response headers — CSP, HSTS, X-Frame-Options, etc.
# Also strips S3 metadata headers (version-id, replication-status, etc.)
resource "aws_cloudfront_response_headers_policy" "dashboard" {
  name    = "athena-dashboard-security-headers"
  comment = "Security headers for Athena Dashboard"

  security_headers_config {
    strict_transport_security {
      access_control_max_age_sec = 31536000
      include_subdomains         = true
      preload                    = true
      override                   = true
    }

    content_type_options {
      override = true
    }

    frame_options {
      frame_option = "DENY"
      override     = true
    }

    referrer_policy {
      referrer_policy = "strict-origin-when-cross-origin"
      override        = true
    }

    content_security_policy {
      content_security_policy = "default-src 'self'; script-src 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' ${var.okta_issuer_url} ${aws_apigatewayv2_stage.dashboard.invoke_url}; frame-ancestors 'none'; base-uri 'self'; form-action 'self' ${var.okta_issuer_url}"
      override                = true
    }
  }

  custom_headers_config {
    items {
      header   = "Permissions-Policy"
      value    = "camera=(), microphone=(), geolocation=()"
      override = true
    }
  }

  # Strip S3 metadata headers that leak infrastructure details
  remove_headers_config {
    items { header = "x-amz-version-id" }
    items { header = "x-amz-replication-status" }
    items { header = "x-amz-expiration" }
    items { header = "x-amz-server-side-encryption" }
    items { header = "server" }
  }
}

resource "aws_cloudfront_distribution" "dashboard" {
  depends_on = [aws_acm_certificate_validation.dashboard]

  enabled             = true
  is_ipv6_enabled     = true
  default_root_object = "index.html"
  aliases             = [var.dashboard_domain]
  web_acl_id          = module.dashboard_waf.web_acl_arn
  comment             = "Athena Security Dashboard — HTTPS frontend, WAF protected"

  origin {
    domain_name = module.dashboard_s3.bucket_regional_domain_name
    origin_id   = "S3-dashboard"

    s3_origin_config {
      origin_access_identity = aws_cloudfront_origin_access_identity.dashboard.cloudfront_access_identity_path
    }
  }

  default_cache_behavior {
    allowed_methods            = ["GET", "HEAD", "OPTIONS"]
    cached_methods             = ["GET", "HEAD"]
    target_origin_id           = "S3-dashboard"
    viewer_protocol_policy     = "redirect-to-https"
    response_headers_policy_id = aws_cloudfront_response_headers_policy.dashboard.id

    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }

    function_association {
      event_type   = "viewer-request"
      function_arn = aws_cloudfront_function.dashboard_auth.arn
    }

    min_ttl     = 0
    default_ttl = 300
    max_ttl     = 3600
  }

  # Serve login page for errors instead of raw S3 XML.
  # response_code preserves the real status so the CloudFront Function's
  # auth check and WAF blocks return proper error codes.
  custom_error_response {
    error_code            = 403
    response_code         = 403
    response_page_path    = "/index.html"
    error_caching_min_ttl = 60
  }

  custom_error_response {
    error_code            = 404
    response_code         = 404
    response_page_path    = "/index.html"
    error_caching_min_ttl = 60
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    acm_certificate_arn      = aws_acm_certificate.dashboard.arn
    ssl_support_method       = "sni-only"
    minimum_protocol_version = "TLSv1.2_2021"
  }
}


####################################
# ROUTE53
####################################

resource "aws_route53_record" "dashboard" {
  zone_id = var.hosted_zone_id
  name    = var.dashboard_domain
  type    = "A"

  alias {
    name                   = aws_cloudfront_distribution.dashboard.domain_name
    zone_id                = aws_cloudfront_distribution.dashboard.hosted_zone_id
    evaluate_target_health = false
  }
}
