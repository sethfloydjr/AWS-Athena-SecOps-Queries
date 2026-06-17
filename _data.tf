data "aws_region" "current" {}
data "aws_caller_identity" "current" {}
data "aws_organizations_organization" "current" {}

####################################
# Dashboard — Lambda zip
####################################

data "archive_file" "dashboard_lambda" {
  type        = "zip"
  source_file = "${path.module}/dashboard/lambda/athena_dashboard.py"
  output_path = "${path.module}/dashboard/lambda/athena_dashboard.zip"
}

####################################
# Dashboard — IAM policies
####################################

data "aws_iam_policy_document" "dashboard_lambda_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "dashboard_lambda_policy" {
  # CloudWatch Logs
  statement {
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["${aws_cloudwatch_log_group.dashboard_lambda.arn}:*"]
  }

  # Athena query operations
  statement {
    effect = "Allow"
    actions = [
      "athena:StartQueryExecution",
      "athena:GetQueryExecution",
      "athena:GetQueryResults",
      "athena:StopQueryExecution",
      "athena:ListNamedQueries",
      "athena:GetNamedQuery",
      "athena:BatchGetNamedQuery",
      "athena:CreateNamedQuery",
      "athena:DeleteNamedQuery",
    ]
    resources = [
      "arn:aws:athena:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:workgroup/security-incident-response",
    ]
  }

  # S3 — read/write Athena results bucket. PutObject is required because Athena
  # writes query results using the caller's (Lambda's) credentials, not a service
  # role. CTAS/UNLOAD abuse is mitigated by the SQL blocklist in the Lambda, not
  # by removing PutObject. Write is scoped to the results/ prefix only.
  statement {
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:GetBucketLocation",
      "s3:ListBucket",
    ]
    resources = [
      "arn:aws:s3:::${var.results_bucket_name}",
      "arn:aws:s3:::${var.results_bucket_name}/*",
    ]
  }

  statement {
    effect = "Allow"
    actions = [
      "s3:PutObject",
    ]
    resources = [
      "arn:aws:s3:::${var.results_bucket_name}/results/*",
    ]
  }

  # S3 — read CloudTrail and Config source buckets (for Athena queries)
  statement {
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:ListBucket",
      "s3:GetBucketLocation",
    ]
    resources = [
      "arn:aws:s3:::${var.cloudtrail_bucket_name}",
      "arn:aws:s3:::${var.cloudtrail_bucket_name}/*",
      "arn:aws:s3:::${var.config_bucket_name}",
      "arn:aws:s3:::${var.config_bucket_name}/*",
    ]
  }

  # Glue — read catalog for Athena table metadata
  statement {
    effect = "Allow"
    actions = [
      "glue:GetDatabase",
      "glue:GetTable",
      "glue:GetPartitions",
    ]
    resources = [
      "arn:aws:glue:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:catalog",
      "arn:aws:glue:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:database/security_incident_response",
      "arn:aws:glue:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:table/security_incident_response/*",
    ]
  }
}
