###############################################
# Visibility Gaps & Data Exposure
###############################################
# Queries focused on identifying missing security controls,
# unencrypted resources, and visibility blind spots.


# --------------------------------------------------------------------------
# IAM Users - MFA Disabled
# --------------------------------------------------------------------------
resource "aws_athena_named_query" "iam_users_mfa_disabled" {
  name        = "iam_users_mfa_disabled"
  workgroup   = aws_athena_workgroup.security_ir.id
  database    = aws_glue_catalog_database.security_ir.name
  description = "Find IAM users with no MFA device attached. High-priority compliance finding. Includes both console and API-only users — filter on loginProfile to find console-enabled users specifically (see iam_users_console_no_mfa). IAM is global — only scans us-east-1."

  query = <<-SQL
    -- Find IAM users with no MFA device attached
    -- IAM is global so we only need region = 'us-east-1'
    SELECT
        ci.awsaccountid                                         AS account_id,
        ci.resourcename                                         AS user_name,
        ci.arn,
        json_extract_scalar(ci.configuration, '$.createDate')   AS create_date,
        json_extract(ci.configuration, '$.mfaDevices')          AS mfa_devices,
        ci.configurationitemcapturetime                         AS snapshot_time,
        accountid                                               AS partition_account,
        dt                                                      AS snapshot_date
    FROM ${aws_glue_catalog_database.security_ir.name}.${aws_glue_catalog_table.config_snapshots.name}
    CROSS JOIN UNNEST(configurationitems) AS t(ci)
    WHERE ci.resourcetype = 'AWS::IAM::User'
        AND ci.configurationitemstatus = 'OK'
        AND region = 'us-east-1'
        AND (
            json_extract(ci.configuration, '$.mfaDevices') = JSON '[]'
            OR json_extract(ci.configuration, '$.mfaDevices') IS NULL
        )
        -- AND accountid = '123456789012'
        -- AND dt = '2025/7/1'
    ORDER BY ci.awsaccountid, ci.resourcename
  SQL
}


# --------------------------------------------------------------------------
# IAM Users - Console Access Without MFA
# --------------------------------------------------------------------------
resource "aws_athena_named_query" "iam_users_console_no_mfa" {
  name        = "iam_users_console_no_mfa"
  workgroup   = aws_athena_workgroup.security_ir.id
  database    = aws_glue_catalog_database.security_ir.name
  description = "Find IAM users with console login enabled (loginProfile exists) but no MFA device. These are the highest-risk accounts — console access without MFA is a common attack vector. Does not include federated/SSO users whose MFA is managed by Okta."

  query = <<-SQL
    -- Find IAM users that can log into the console but have no MFA
    -- These are high-risk: console access without MFA is a common attack vector
    SELECT
        ci.awsaccountid                                                    AS account_id,
        ci.resourcename                                                    AS user_name,
        ci.arn,
        json_extract_scalar(ci.configuration, '$.createDate')              AS create_date,
        json_extract_scalar(ci.configuration,
            '$.loginProfile.createDate')                                   AS console_enabled_date,
        json_extract(ci.configuration, '$.mfaDevices')                     AS mfa_devices,
        ci.configurationitemcapturetime                                    AS snapshot_time,
        accountid                                                          AS partition_account,
        dt                                                                 AS snapshot_date
    FROM ${aws_glue_catalog_database.security_ir.name}.${aws_glue_catalog_table.config_snapshots.name}
    CROSS JOIN UNNEST(configurationitems) AS t(ci)
    WHERE ci.resourcetype = 'AWS::IAM::User'
        AND ci.configurationitemstatus = 'OK'
        AND region = 'us-east-1'
        AND ci.configuration LIKE '%loginProfile%'
        AND (
            json_extract(ci.configuration, '$.mfaDevices') = JSON '[]'
            OR json_extract(ci.configuration, '$.mfaDevices') IS NULL
        )
        -- AND accountid = '123456789012'
        -- AND dt = '2025/7/1'
    ORDER BY ci.awsaccountid, ci.resourcename
  SQL
}


# --------------------------------------------------------------------------
# VPC Flow Log Coverage
# --------------------------------------------------------------------------
resource "aws_athena_named_query" "vpc_flow_log_status" {
  name        = "vpc_flow_log_status"
  workgroup   = aws_athena_workgroup.security_ir.id
  database    = aws_glue_catalog_database.security_ir.name
  description = "Find VPCs without VPC-level flow logs configured — gaps in network visibility for incident investigation. WARNING: Uses a CTE that scans the table twice. Add matching partition filters to BOTH the CTE and the main query to control cost. Subnet-level flow logs are not detected."

  query = <<-SQL
    -- Find VPCs with no VPC-level flow log configured
    -- NOTE: This uses a CTE and scans the table twice
    -- Add partition filters to BOTH the CTE and the main query to control scan cost
    WITH flow_logs AS (
        SELECT
            json_extract_scalar(ci.configuration, '$.resourceId') AS resource_id
        FROM ${aws_glue_catalog_database.security_ir.name}.${aws_glue_catalog_table.config_snapshots.name}
        CROSS JOIN UNNEST(configurationitems) AS t(ci)
        WHERE ci.resourcetype = 'AWS::EC2::FlowLog'
            AND ci.configurationitemstatus = 'OK'
            -- AND accountid = '123456789012'
            -- AND dt = '2025/7/1'
    )
    SELECT
        ci.awsaccountid                                                 AS account_id,
        ci.awsregion                                                    AS aws_region,
        ci.resourceid                                                   AS vpc_id,
        json_extract_scalar(ci.configuration, '$.cidrBlock')            AS cidr_block,
        json_extract_scalar(ci.configuration, '$.isDefault')            AS is_default,
        ci.tags,
        ci.configurationitemcapturetime                                 AS snapshot_time,
        accountid                                                       AS partition_account,
        dt                                                              AS snapshot_date
    FROM ${aws_glue_catalog_database.security_ir.name}.${aws_glue_catalog_table.config_snapshots.name}
    CROSS JOIN UNNEST(configurationitems) AS t(ci)
    WHERE ci.resourcetype = 'AWS::EC2::VPC'
        AND ci.configurationitemstatus = 'OK'
        AND ci.resourceid NOT IN (SELECT resource_id FROM flow_logs WHERE resource_id IS NOT NULL)
        -- AND accountid = '123456789012'
        -- AND dt = '2025/7/1'
    ORDER BY ci.awsaccountid, ci.awsregion
  SQL
}


# --------------------------------------------------------------------------
# S3 Buckets - No Encryption
# --------------------------------------------------------------------------
resource "aws_athena_named_query" "s3_buckets_no_encryption" {
  name        = "s3_buckets_no_encryption"
  workgroup   = aws_athena_workgroup.security_ir.id
  database    = aws_glue_catalog_database.security_ir.name
  description = "Find S3 buckets without an explicit default encryption configuration. Since Jan 2023, AWS applies SSE-S3 to all new objects by default, so unencrypted objects are unlikely. Buckets without an explicit policy may predate this change. S3 is global — only scans us-east-1."

  query = <<-SQL
    -- Find S3 buckets with no explicit default encryption configuration
    -- Note: Since Jan 2023, AWS applies SSE-S3 to new objects by default,
    -- but buckets without an explicit policy may predate this change
    -- S3 is global in Config so we only need region = 'us-east-1'
    SELECT
        ci.awsaccountid                                     AS account_id,
        ci.resourcename                                     AS bucket_name,
        ci.arn,
        element_at(ci.supplementaryconfiguration,
            'ServerSideEncryptionConfiguration')             AS encryption_config,
        ci.configurationitemcapturetime                     AS snapshot_time,
        accountid                                           AS partition_account,
        dt                                                  AS snapshot_date
    FROM ${aws_glue_catalog_database.security_ir.name}.${aws_glue_catalog_table.config_snapshots.name}
    CROSS JOIN UNNEST(configurationitems) AS t(ci)
    WHERE ci.resourcetype = 'AWS::S3::Bucket'
        AND ci.configurationitemstatus = 'OK'
        AND region = 'us-east-1'
        AND (
            element_at(ci.supplementaryconfiguration, 'ServerSideEncryptionConfiguration') IS NULL
            OR element_at(ci.supplementaryconfiguration, 'ServerSideEncryptionConfiguration') NOT LIKE '%"sseAlgorithm"%'
        )
        -- AND accountid = '123456789012'
        -- AND dt = '2025/7/1'
    ORDER BY ci.awsaccountid, ci.resourcename
  SQL
}


# --------------------------------------------------------------------------
# S3 Buckets - No Logging
# --------------------------------------------------------------------------
resource "aws_athena_named_query" "s3_buckets_no_logging" {
  name        = "s3_buckets_no_logging"
  workgroup   = aws_athena_workgroup.security_ir.id
  database    = aws_glue_catalog_database.security_ir.name
  description = "Find S3 buckets without server access logging enabled. Buckets without logging create blind spots during incident investigation — you can't determine who accessed or modified objects. S3 is global — only scans us-east-1."

  query = <<-SQL
    -- Find S3 buckets with no server access logging configured
    -- Buckets without logging create blind spots during incident investigation
    -- S3 is global in Config so we only need region = 'us-east-1'
    SELECT
        ci.awsaccountid                                     AS account_id,
        ci.resourcename                                     AS bucket_name,
        ci.arn,
        element_at(ci.supplementaryconfiguration,
            'BucketLoggingConfiguration')                    AS logging_config,
        ci.configurationitemcapturetime                     AS snapshot_time,
        accountid                                           AS partition_account,
        dt                                                  AS snapshot_date
    FROM ${aws_glue_catalog_database.security_ir.name}.${aws_glue_catalog_table.config_snapshots.name}
    CROSS JOIN UNNEST(configurationitems) AS t(ci)
    WHERE ci.resourcetype = 'AWS::S3::Bucket'
        AND ci.configurationitemstatus = 'OK'
        AND region = 'us-east-1'
        AND (
            element_at(ci.supplementaryconfiguration, 'BucketLoggingConfiguration') IS NULL
            OR element_at(ci.supplementaryconfiguration, 'BucketLoggingConfiguration') LIKE '%"destinationBucketName":null%'
        )
        -- AND accountid = '123456789012'
        -- AND dt = '2025/7/1'
    ORDER BY ci.awsaccountid, ci.resourcename
  SQL
}


# --------------------------------------------------------------------------
# EC2 Instances - No IMDSv2
# --------------------------------------------------------------------------
resource "aws_athena_named_query" "ec2_instances_no_imdsv2" {
  name        = "ec2_instances_no_imdsv2"
  workgroup   = aws_athena_workgroup.security_ir.id
  database    = aws_glue_catalog_database.security_ir.name
  description = "Find EC2 instances not enforcing IMDSv2 (httpTokens != required). IMDSv1 is vulnerable to SSRF attacks that can steal instance credentials from the metadata service. Instances with httpTokens=optional allow both v1 and v2 — they should be set to required."

  query = <<-SQL
    -- Find EC2 instances that allow IMDSv1 (httpTokens is not 'required')
    -- IMDSv1 is vulnerable to SSRF attacks that can steal instance credentials
    SELECT
        ci.awsaccountid                                                         AS account_id,
        ci.awsregion                                                            AS aws_region,
        ci.resourceid                                                           AS instance_id,
        json_extract_scalar(ci.configuration, '$.instanceType')                 AS instance_type,
        json_extract_scalar(ci.configuration, '$.state.name')                   AS state,
        json_extract_scalar(ci.configuration, '$.metadataOptions.httpTokens')   AS http_tokens,
        json_extract_scalar(ci.configuration, '$.metadataOptions.httpEndpoint') AS http_endpoint,
        json_extract_scalar(ci.configuration, '$.privateIpAddress')             AS private_ip,
        json_extract_scalar(ci.configuration, '$.iamInstanceProfile.arn')       AS instance_profile_arn,
        ci.tags,
        ci.configurationitemcapturetime                                         AS snapshot_time,
        accountid                                                               AS partition_account,
        dt                                                                      AS snapshot_date
    FROM ${aws_glue_catalog_database.security_ir.name}.${aws_glue_catalog_table.config_snapshots.name}
    CROSS JOIN UNNEST(configurationitems) AS t(ci)
    WHERE ci.resourcetype = 'AWS::EC2::Instance'
        AND ci.configurationitemstatus = 'OK'
        AND (
            json_extract_scalar(ci.configuration, '$.metadataOptions.httpTokens') != 'required'
            OR json_extract_scalar(ci.configuration, '$.metadataOptions.httpTokens') IS NULL
        )
        -- AND accountid = '123456789012'
        -- AND region = 'us-east-1'
        -- AND dt = '2025/7/1'
    ORDER BY ci.awsaccountid, ci.awsregion, ci.resourceid
  SQL
}


# --------------------------------------------------------------------------
# RDS Instances - Publicly Accessible
# --------------------------------------------------------------------------
resource "aws_athena_named_query" "rds_instances_public" {
  name        = "rds_instances_public"
  workgroup   = aws_athena_workgroup.security_ir.id
  database    = aws_glue_catalog_database.security_ir.name
  description = "Find RDS instances with publiclyAccessible=true, meaning they have a public DNS endpoint. Actual internet reachability depends on security groups and subnet routing — a publicly accessible RDS in a private subnet with no internet gateway is not reachable. Verify with SG rules."

  query = <<-SQL
    -- Find RDS instances that are publicly accessible
    -- publiclyAccessible=true means the instance has a public DNS endpoint
    -- (actual reachability still depends on security groups and routing)
    SELECT
        ci.awsaccountid                                                     AS account_id,
        ci.awsregion                                                        AS aws_region,
        ci.resourceid                                                       AS db_instance_id,
        json_extract_scalar(ci.configuration, '$.engine')                   AS engine,
        json_extract_scalar(ci.configuration, '$.engineVersion')            AS engine_version,
        json_extract_scalar(ci.configuration, '$.dBInstanceClass')          AS instance_class,
        json_extract_scalar(ci.configuration, '$.endpoint.address')         AS endpoint,
        json_extract_scalar(ci.configuration, '$.endpoint.port')            AS port,
        json_extract_scalar(ci.configuration, '$.publiclyAccessible')       AS publicly_accessible,
        json_extract(ci.configuration, '$.vpcSecurityGroups')               AS security_groups,
        ci.configurationitemcapturetime                                     AS snapshot_time,
        accountid                                                           AS partition_account,
        dt                                                                  AS snapshot_date
    FROM ${aws_glue_catalog_database.security_ir.name}.${aws_glue_catalog_table.config_snapshots.name}
    CROSS JOIN UNNEST(configurationitems) AS t(ci)
    WHERE ci.resourcetype = 'AWS::RDS::DBInstance'
        AND ci.configurationitemstatus = 'OK'
        AND json_extract_scalar(ci.configuration, '$.publiclyAccessible') = 'true'
        -- AND accountid = '123456789012'
        -- AND region = 'us-east-1'
        -- AND dt = '2025/7/1'
    ORDER BY ci.awsaccountid, ci.awsregion, ci.resourceid
  SQL
}


# --------------------------------------------------------------------------
# RDS Instances - No Encryption
# --------------------------------------------------------------------------
resource "aws_athena_named_query" "rds_instances_no_encryption" {
  name        = "rds_instances_no_encryption"
  workgroup   = aws_athena_workgroup.security_ir.id
  database    = aws_glue_catalog_database.security_ir.name
  description = "Find RDS instances without storage encryption at rest. Encryption cannot be added after creation — the instance must be snapshot/restored to a new encrypted instance. Newer accounts have default encryption enabled, so results are typically from older instances."

  query = <<-SQL
    -- Find RDS instances without storage encryption enabled
    -- Encryption at rest cannot be enabled after creation - the instance
    -- must be snapshot/restored to add encryption
    SELECT
        ci.awsaccountid                                                     AS account_id,
        ci.awsregion                                                        AS aws_region,
        ci.resourceid                                                       AS db_instance_id,
        json_extract_scalar(ci.configuration, '$.engine')                   AS engine,
        json_extract_scalar(ci.configuration, '$.engineVersion')            AS engine_version,
        json_extract_scalar(ci.configuration, '$.dBInstanceClass')          AS instance_class,
        json_extract_scalar(ci.configuration, '$.storageEncrypted')         AS storage_encrypted,
        json_extract_scalar(ci.configuration, '$.allocatedStorage')         AS allocated_storage_gb,
        json_extract_scalar(ci.configuration, '$.dBInstanceStatus')         AS status,
        ci.configurationitemcapturetime                                     AS snapshot_time,
        accountid                                                           AS partition_account,
        dt                                                                  AS snapshot_date
    FROM ${aws_glue_catalog_database.security_ir.name}.${aws_glue_catalog_table.config_snapshots.name}
    CROSS JOIN UNNEST(configurationitems) AS t(ci)
    WHERE ci.resourcetype = 'AWS::RDS::DBInstance'
        AND ci.configurationitemstatus = 'OK'
        AND json_extract_scalar(ci.configuration, '$.storageEncrypted') = 'false'
        -- AND accountid = '123456789012'
        -- AND region = 'us-east-1'
        -- AND dt = '2025/7/1'
    ORDER BY ci.awsaccountid, ci.awsregion, ci.resourceid
  SQL
}
