###############################################
# CloudTrail Queries - API Activity Analysis
###############################################
# These queries target the cloudtrail_logs table which reads from the org-wide
# CloudTrail in the Root account (company-org-cloudtrail).
#
# KEY DIFFERENCES FROM CONFIG QUERIES:
# - No CROSS JOIN UNNEST needed - each row is already one API event
# - Date format is zero-padded: dt = '2025/01/15' (not '2025/1/15')
# - CloudTrail data is larger than Config - always use partition filters
# - Partition projection covers all AWS regions (multi-region trail)


# --------------------------------------------------------------------------
# Console Logins
# --------------------------------------------------------------------------
resource "aws_athena_named_query" "ct_console_logins" {
  name        = "ct_console_logins"
  workgroup   = aws_athena_workgroup.security_ir.id
  database    = aws_glue_catalog_database.security_ir.name
  description = "All AWS console login events (successful and failed) with source IP, MFA status, and user agent. Includes both IAM users and federated (SSO/SAML) logins. IMPORTANT: Always add dt partition filter — scanning all dates is expensive. ConsoleLogin events are logged in us-east-1."

  query = <<-SQL
    -- All console login events across the org
    -- Shows who logged in, from where, and whether MFA was used
    SELECT
        eventtime,
        useridentity.arn                                                            AS principal_arn,
        useridentity.username                                                       AS username,
        useridentity.accountid                                                      AS user_account_id,
        sourceipaddress,
        errorcode,
        errormessage,
        json_extract_scalar(additionaleventdata, '$.MFAUsed')                       AS mfa_used,
        json_extract_scalar(responseelements, '$.ConsoleLogin')                     AS login_result,
        useragent,
        recipientaccountid,
        accountid                                                                   AS partition_account,
        dt                                                                          AS event_date
    FROM ${aws_glue_catalog_database.security_ir.name}.${aws_glue_catalog_table.cloudtrail_logs.name}
    WHERE eventname = 'ConsoleLogin'
        -- AND accountid = '123456789012'
        -- AND dt = '2025/01/15'
        -- AND dt BETWEEN '2025/01/01' AND '2025/01/07'
    ORDER BY eventtime DESC
  SQL
}


# --------------------------------------------------------------------------
# Failed Console Logins
# --------------------------------------------------------------------------
resource "aws_athena_named_query" "ct_failed_console_logins" {
  name        = "ct_failed_console_logins"
  workgroup   = aws_athena_workgroup.security_ir.id
  database    = aws_glue_catalog_database.security_ir.name
  description = "Failed console login attempts only. Multiple failures from the same IP may indicate brute force. Multiple failures for the same user may indicate credential compromise attempts. Always add dt filter. Does not capture Okta login failures — only AWS console auth failures."

  query = <<-SQL
    -- Failed console login attempts
    -- Multiple failures from the same IP may indicate brute force attacks
    -- Multiple failures for the same user may indicate credential compromise attempts
    SELECT
        eventtime,
        useridentity.arn                                                            AS principal_arn,
        useridentity.username                                                       AS username,
        sourceipaddress,
        errorcode,
        errormessage,
        json_extract_scalar(additionaleventdata, '$.MFAUsed')                       AS mfa_used,
        useragent,
        recipientaccountid,
        accountid                                                                   AS partition_account,
        dt                                                                          AS event_date
    FROM ${aws_glue_catalog_database.security_ir.name}.${aws_glue_catalog_table.cloudtrail_logs.name}
    WHERE eventname = 'ConsoleLogin'
        AND errorcode IS NOT NULL
        -- AND accountid = '123456789012'
        -- AND dt BETWEEN '2025/01/01' AND '2025/01/07'
    ORDER BY eventtime DESC
  SQL
}


# --------------------------------------------------------------------------
# IAM Changes
# --------------------------------------------------------------------------
resource "aws_athena_named_query" "ct_iam_changes" {
  name        = "ct_iam_changes"
  workgroup   = aws_athena_workgroup.security_ir.id
  database    = aws_glue_catalog_database.security_ir.name
  description = "IAM user, role, and policy changes including creation, deletion, policy attachments, and access key operations. Use during incidents to detect attacker persistence (new users, roles, keys). IAM events are global and always logged in us-east-1 regardless of region filter."

  query = <<-SQL
    -- IAM changes: user/role creation, policy attachments, access key creation
    -- During an incident, look for attacker persistence (new users, roles, keys)
    -- IAM events are global and logged in us-east-1
    SELECT
        eventtime,
        eventname,
        useridentity.arn                                                            AS who_made_change,
        sourceipaddress,
        requestparameters,
        responseelements,
        errorcode,
        recipientaccountid,
        accountid                                                                   AS partition_account,
        dt                                                                          AS event_date
    FROM ${aws_glue_catalog_database.security_ir.name}.${aws_glue_catalog_table.cloudtrail_logs.name}
    WHERE eventsource = 'iam.amazonaws.com'
        AND eventname IN (
            'CreateUser', 'DeleteUser',
            'CreateRole', 'DeleteRole',
            'CreateAccessKey', 'DeleteAccessKey',
            'CreateLoginProfile', 'UpdateLoginProfile',
            'AttachUserPolicy', 'AttachRolePolicy', 'AttachGroupPolicy',
            'DetachUserPolicy', 'DetachRolePolicy', 'DetachGroupPolicy',
            'PutUserPolicy', 'PutRolePolicy', 'PutGroupPolicy',
            'UpdateAssumeRolePolicy',
            'AddUserToGroup', 'RemoveUserFromGroup'
        )
        -- AND accountid = '123456789012'
        -- AND dt BETWEEN '2025/01/01' AND '2025/01/07'
    ORDER BY eventtime DESC
  SQL
}


# --------------------------------------------------------------------------
# Root Account Usage
# --------------------------------------------------------------------------
resource "aws_athena_named_query" "ct_root_account_usage" {
  name        = "ct_root_account_usage"
  workgroup   = aws_athena_workgroup.security_ir.id
  database    = aws_glue_catalog_database.security_ir.name
  description = "Root account API activity across all org accounts. Should be near zero — any activity warrants investigation. Filters out automated AWS service events (AwsServiceEvent) to reduce noise. If results appear, check sourceipaddress to determine if legitimate (break-glass) or compromised."

  query = <<-SQL
    -- Root account usage across all org accounts
    -- Root should rarely be used - any activity warrants investigation
    -- Filters out AWS service events (automated background actions)
    SELECT
        eventtime,
        eventname,
        eventsource,
        sourceipaddress,
        useragent,
        errorcode,
        requestparameters,
        recipientaccountid,
        accountid                                                                   AS partition_account,
        dt                                                                          AS event_date
    FROM ${aws_glue_catalog_database.security_ir.name}.${aws_glue_catalog_table.cloudtrail_logs.name}
    WHERE useridentity.type = 'Root'
        AND eventtype != 'AwsServiceEvent'
        -- AND accountid = '123456789012'
        -- AND dt BETWEEN '2025/01/01' AND '2025/01/07'
    ORDER BY eventtime DESC
  SQL
}


# --------------------------------------------------------------------------
# Unauthorized API Calls (AccessDenied)
# --------------------------------------------------------------------------
resource "aws_athena_named_query" "ct_unauthorized_api_calls" {
  name        = "ct_unauthorized_api_calls"
  workgroup   = aws_athena_workgroup.security_ir.id
  database    = aws_glue_catalog_database.security_ir.name
  description = "API calls that returned AccessDenied or UnauthorizedAccess errors. A burst of denials from one principal may indicate an attacker probing permissions (reconnaissance). Some noise is normal from automation — look for unusual principals, IPs, or high-frequency patterns."

  query = <<-SQL
    -- API calls that returned AccessDenied or UnauthorizedAccess
    -- A burst of denials from one principal may indicate an attacker probing permissions
    SELECT
        eventtime,
        eventname,
        eventsource,
        errorcode,
        errormessage,
        useridentity.arn                                                            AS principal_arn,
        useridentity.accesskeyid                                                    AS access_key_id,
        sourceipaddress,
        useragent,
        recipientaccountid,
        accountid                                                                   AS partition_account,
        dt                                                                          AS event_date
    FROM ${aws_glue_catalog_database.security_ir.name}.${aws_glue_catalog_table.cloudtrail_logs.name}
    WHERE errorcode IN ('AccessDenied', 'UnauthorizedAccess', 'Client.UnauthorizedAccess')
        -- AND accountid = '123456789012'
        -- AND dt BETWEEN '2025/01/01' AND '2025/01/07'
    ORDER BY eventtime DESC
  SQL
}


# --------------------------------------------------------------------------
# Security Group Changes
# --------------------------------------------------------------------------
resource "aws_athena_named_query" "ct_security_group_changes" {
  name        = "ct_security_group_changes"
  workgroup   = aws_athena_workgroup.security_ir.id
  database    = aws_glue_catalog_database.security_ir.name
  description = "Security group creation, deletion, and rule changes. Shows who made the change, from what IP, and the full request parameters (new rules). Look for rules opened to 0.0.0.0/0 or unexpected port ranges. High volume from automation (Atlantis, GHA runners, ALB controller) is expected."

  query = <<-SQL
    -- Security group creation, deletion, and rule changes
    -- Look for rules being opened to 0.0.0.0/0 or unexpected port ranges
    SELECT
        eventtime,
        eventname,
        useridentity.arn                                                            AS who_made_change,
        sourceipaddress,
        requestparameters,
        responseelements,
        errorcode,
        awsregion,
        recipientaccountid,
        accountid                                                                   AS partition_account,
        dt                                                                          AS event_date
    FROM ${aws_glue_catalog_database.security_ir.name}.${aws_glue_catalog_table.cloudtrail_logs.name}
    WHERE eventsource = 'ec2.amazonaws.com'
        AND eventname IN (
            'AuthorizeSecurityGroupIngress', 'AuthorizeSecurityGroupEgress',
            'RevokeSecurityGroupIngress', 'RevokeSecurityGroupEgress',
            'CreateSecurityGroup', 'DeleteSecurityGroup'
        )
        -- AND accountid = '123456789012'
        -- AND region = 'us-east-1'
        -- AND dt BETWEEN '2025/01/01' AND '2025/01/07'
    ORDER BY eventtime DESC
  SQL
}


# --------------------------------------------------------------------------
# S3 Bucket Policy and Access Changes
# --------------------------------------------------------------------------
resource "aws_athena_named_query" "ct_s3_access_changes" {
  name        = "ct_s3_access_changes"
  workgroup   = aws_athena_workgroup.security_ir.id
  database    = aws_glue_catalog_database.security_ir.name
  description = "S3 bucket policy, ACL, public access block, CORS, website, and encryption changes. Look for policies being removed or widened, ACLs being opened, or public access blocks being disabled. Covers the API events that could expose S3 data — complements the Config-based s3_buckets_public query."

  query = <<-SQL
    -- S3 bucket access configuration changes
    -- Look for policies being removed, ACLs being opened, or public access blocks being disabled
    SELECT
        eventtime,
        eventname,
        useridentity.arn                                                            AS who_made_change,
        sourceipaddress,
        requestparameters,
        responseelements,
        errorcode,
        recipientaccountid,
        accountid                                                                   AS partition_account,
        dt                                                                          AS event_date
    FROM ${aws_glue_catalog_database.security_ir.name}.${aws_glue_catalog_table.cloudtrail_logs.name}
    WHERE eventsource = 's3.amazonaws.com'
        AND eventname IN (
            'PutBucketPolicy', 'DeleteBucketPolicy',
            'PutBucketAcl',
            'PutBucketPublicAccessBlock', 'DeleteBucketPublicAccessBlock',
            'PutBucketCors', 'PutBucketWebsite',
            'PutBucketEncryption', 'DeleteBucketEncryption'
        )
        -- AND accountid = '123456789012'
        -- AND dt BETWEEN '2025/01/01' AND '2025/01/07'
    ORDER BY eventtime DESC
  SQL
}


# --------------------------------------------------------------------------
# CloudTrail Tampering
# --------------------------------------------------------------------------
resource "aws_athena_named_query" "ct_cloudtrail_tampering" {
  name        = "ct_cloudtrail_tampering"
  workgroup   = aws_athena_workgroup.security_ir.id
  database    = aws_glue_catalog_database.security_ir.name
  description = "CloudTrail stop, delete, update, and event selector changes. CRITICAL — an attacker's first move is often to disable logging. ANY result from this query should trigger an immediate investigation. Includes DeleteEventDataStore for CloudTrail Lake."

  query = <<-SQL
    -- CloudTrail configuration changes
    -- An attacker's first move is often to disable logging
    -- ANY of these events should trigger an immediate investigation
    SELECT
        eventtime,
        eventname,
        useridentity.arn                                                            AS who_made_change,
        useridentity.accesskeyid                                                    AS access_key_id,
        sourceipaddress,
        useragent,
        requestparameters,
        errorcode,
        recipientaccountid,
        accountid                                                                   AS partition_account,
        dt                                                                          AS event_date
    FROM ${aws_glue_catalog_database.security_ir.name}.${aws_glue_catalog_table.cloudtrail_logs.name}
    WHERE eventsource = 'cloudtrail.amazonaws.com'
        AND eventname IN (
            'StopLogging', 'DeleteTrail', 'UpdateTrail',
            'PutEventSelectors', 'DeleteEventDataStore'
        )
        -- AND accountid = '123456789012'
        -- AND dt BETWEEN '2025/01/01' AND '2025/01/07'
    ORDER BY eventtime DESC
  SQL
}


# --------------------------------------------------------------------------
# Credential Usage by Source IP
# --------------------------------------------------------------------------
resource "aws_athena_named_query" "ct_credential_usage_by_ip" {
  name        = "ct_credential_usage_by_ip"
  workgroup   = aws_athena_workgroup.security_ir.id
  database    = aws_glue_catalog_database.security_ir.name
  description = "Track all API calls made by a specific access key or principal ARN. Replace ACCESS_KEY_OR_ARN_HERE with the key (AKIA...) or ARN. Parameterized query. Use after finding a compromised key with iam_access_key_lookup. Always add dt filter — full scans are very expensive."

  query = <<-SQL
    -- Track all API calls made by a specific credential
    -- REPLACE 'ACCESS_KEY_OR_ARN_HERE' with the compromised access key ID (AKIA...)
    -- or the principal ARN (arn:aws:iam::123456789012:user/username)
    --
    -- TIP: Use this after finding a compromised key in the iam_access_keys_active Config query
    SELECT
        eventtime,
        eventname,
        eventsource,
        sourceipaddress,
        awsregion,
        errorcode,
        useragent,
        requestparameters,
        recipientaccountid,
        accountid                                                                   AS partition_account,
        dt                                                                          AS event_date
    FROM ${aws_glue_catalog_database.security_ir.name}.${aws_glue_catalog_table.cloudtrail_logs.name}
    WHERE (
        useridentity.accesskeyid = 'ACCESS_KEY_OR_ARN_HERE'
        OR useridentity.arn = 'ACCESS_KEY_OR_ARN_HERE'
    )
        -- AND accountid = '123456789012'
        -- AND dt BETWEEN '2025/01/01' AND '2025/01/07'
    ORDER BY eventtime DESC
  SQL
}


# --------------------------------------------------------------------------
# KMS Key Changes
# --------------------------------------------------------------------------
resource "aws_athena_named_query" "ct_kms_key_changes" {
  name        = "ct_kms_key_changes"
  workgroup   = aws_athena_workgroup.security_ir.id
  database    = aws_glue_catalog_database.security_ir.name
  description = "KMS key management events: disabling, scheduled deletion, policy changes, and grant modifications. Disabling or deleting keys can make encrypted data permanently unrecoverable. Policy changes (PutKeyPolicy, CreateGrant) can grant unauthorized decrypt access."

  query = <<-SQL
    -- KMS key management events
    -- Disabling or deleting keys can make encrypted data unrecoverable
    -- Policy changes can grant unauthorized access to decrypt data
    SELECT
        eventtime,
        eventname,
        useridentity.arn                                                            AS who_made_change,
        sourceipaddress,
        requestparameters,
        responseelements,
        errorcode,
        recipientaccountid,
        accountid                                                                   AS partition_account,
        dt                                                                          AS event_date
    FROM ${aws_glue_catalog_database.security_ir.name}.${aws_glue_catalog_table.cloudtrail_logs.name}
    WHERE eventsource = 'kms.amazonaws.com'
        AND eventname IN (
            'DisableKey', 'ScheduleKeyDeletion', 'CancelKeyDeletion',
            'PutKeyPolicy', 'CreateGrant', 'RevokeGrant',
            'EnableKey', 'CreateKey', 'DeleteImportedKeyMaterial'
        )
        -- AND accountid = '123456789012'
        -- AND dt BETWEEN '2025/01/01' AND '2025/01/07'
    ORDER BY eventtime DESC
  SQL
}
