###############################################
# Compliance & Inventory
###############################################
# Queries for compliance posture checks, resource inventory,
# and operational visibility across the organization.


# --------------------------------------------------------------------------
# Lambda Functions - Inventory
# --------------------------------------------------------------------------
resource "aws_athena_named_query" "lambda_functions_inventory" {
  name        = "lambda_functions_inventory"
  workgroup   = aws_athena_workgroup.security_ir.id
  database    = aws_glue_catalog_database.security_ir.name
  description = "Full Lambda inventory across all accounts and regions with runtime, memory, timeout, code size, and execution role. Useful for finding deprecated runtimes (Python 3.8, Node 14, etc.), oversized functions, or functions with outdated configurations."

  query = <<-SQL
    -- Full Lambda inventory across all accounts and regions
    -- Useful for finding deprecated runtimes, oversized functions, or functions with outdated configs
    SELECT
        ci.awsaccountid                                                         AS account_id,
        ci.awsregion                                                            AS aws_region,
        ci.resourcename                                                         AS function_name,
        ci.arn,
        json_extract_scalar(ci.configuration, '$.runtime')                      AS runtime,
        json_extract_scalar(ci.configuration, '$.handler')                      AS handler,
        json_extract_scalar(ci.configuration, '$.memorySize')                   AS memory_mb,
        json_extract_scalar(ci.configuration, '$.timeout')                      AS timeout_seconds,
        json_extract_scalar(ci.configuration, '$.codeSize')                     AS code_size_bytes,
        json_extract_scalar(ci.configuration, '$.lastModified')                 AS last_modified,
        json_extract_scalar(ci.configuration, '$.role')                         AS execution_role,
        json_extract_scalar(ci.configuration, '$.vpcConfig.vpcId')              AS vpc_id,
        ci.tags,
        ci.configurationitemcapturetime                                         AS snapshot_time,
        accountid                                                               AS partition_account,
        dt                                                                      AS snapshot_date
    FROM ${aws_glue_catalog_database.security_ir.name}.${aws_glue_catalog_table.config_snapshots.name}
    CROSS JOIN UNNEST(configurationitems) AS t(ci)
    WHERE ci.resourcetype = 'AWS::Lambda::Function'
        AND ci.configurationitemstatus = 'OK'
        -- AND accountid = '123456789012'
        -- AND region = 'us-east-1'
        -- AND dt = '2025/7/1'
    ORDER BY ci.awsaccountid, ci.awsregion, ci.resourcename
  SQL
}


# --------------------------------------------------------------------------
# S3 Buckets - Versioning Disabled
# --------------------------------------------------------------------------
resource "aws_athena_named_query" "s3_buckets_versioning_disabled" {
  name        = "s3_buckets_versioning_disabled"
  workgroup   = aws_athena_workgroup.security_ir.id
  database    = aws_glue_catalog_database.security_ir.name
  description = "Find S3 buckets without versioning enabled. Buckets without versioning cannot recover from accidental deletes or overwrites. Includes buckets where versioning was never enabled or was explicitly suspended. S3 is global — only scans us-east-1."

  query = <<-SQL
    -- Find S3 buckets where versioning is not enabled
    -- Buckets without versioning cannot recover from accidental deletes or overwrites
    -- S3 is global in Config so we only need region = 'us-east-1'
    SELECT
        ci.awsaccountid                                     AS account_id,
        ci.resourcename                                     AS bucket_name,
        ci.arn,
        element_at(ci.supplementaryconfiguration,
            'BucketVersioningConfiguration')                 AS versioning_config,
        ci.configurationitemcapturetime                     AS snapshot_time,
        accountid                                           AS partition_account,
        dt                                                  AS snapshot_date
    FROM ${aws_glue_catalog_database.security_ir.name}.${aws_glue_catalog_table.config_snapshots.name}
    CROSS JOIN UNNEST(configurationitems) AS t(ci)
    WHERE ci.resourcetype = 'AWS::S3::Bucket'
        AND ci.configurationitemstatus = 'OK'
        AND region = 'us-east-1'
        AND (
            element_at(ci.supplementaryconfiguration, 'BucketVersioningConfiguration') IS NULL
            OR element_at(ci.supplementaryconfiguration, 'BucketVersioningConfiguration') LIKE '%"status":"Off"%'
            OR element_at(ci.supplementaryconfiguration, 'BucketVersioningConfiguration') NOT LIKE '%"status"%'
        )
        -- AND accountid = '123456789012'
        -- AND dt = '2025/7/1'
    ORDER BY ci.awsaccountid, ci.resourcename
  SQL
}


# --------------------------------------------------------------------------
# EBS Volumes - Unencrypted
# --------------------------------------------------------------------------
resource "aws_athena_named_query" "ebs_volumes_unencrypted" {
  name        = "ebs_volumes_unencrypted"
  workgroup   = aws_athena_workgroup.security_ir.id
  database    = aws_glue_catalog_database.security_ir.name
  description = "Find EBS volumes without encryption at rest. Like RDS, encryption cannot be added to existing volumes — must create an encrypted snapshot and restore to a new volume. Shows attachment status to identify which instances are affected."

  query = <<-SQL
    -- Find EBS volumes that are not encrypted
    -- Like RDS, encryption cannot be added to existing volumes -
    -- must create encrypted snapshot and restore to a new volume
    SELECT
        ci.awsaccountid                                                     AS account_id,
        ci.awsregion                                                        AS aws_region,
        ci.resourceid                                                       AS volume_id,
        json_extract_scalar(ci.configuration, '$.volumeType')               AS volume_type,
        json_extract_scalar(ci.configuration, '$.size')                     AS size_gb,
        json_extract_scalar(ci.configuration, '$.state')                    AS state,
        json_extract_scalar(ci.configuration, '$.encrypted')                AS encrypted,
        json_extract(ci.configuration, '$.attachments')                     AS attachments,
        ci.tags,
        ci.configurationitemcapturetime                                     AS snapshot_time,
        accountid                                                           AS partition_account,
        dt                                                                  AS snapshot_date
    FROM ${aws_glue_catalog_database.security_ir.name}.${aws_glue_catalog_table.config_snapshots.name}
    CROSS JOIN UNNEST(configurationitems) AS t(ci)
    WHERE ci.resourcetype = 'AWS::EC2::Volume'
        AND ci.configurationitemstatus = 'OK'
        AND json_extract_scalar(ci.configuration, '$.encrypted') = 'false'
        -- AND accountid = '123456789012'
        -- AND region = 'us-east-1'
        -- AND dt = '2025/7/1'
    ORDER BY ci.awsaccountid, ci.awsregion, ci.resourceid
  SQL
}


# --------------------------------------------------------------------------
# EBS Volumes - Unattached
# --------------------------------------------------------------------------
resource "aws_athena_named_query" "ebs_volumes_unattached" {
  name        = "ebs_volumes_unattached"
  workgroup   = aws_athena_workgroup.security_ir.id
  database    = aws_glue_catalog_database.security_ir.name
  description = "Find EBS volumes in 'available' state (not attached to any instance). These are likely orphaned from terminated instances — costing money for unused storage and potentially containing sensitive data that should have been deleted."

  query = <<-SQL
    -- Find EBS volumes in 'available' state (not attached to any instance)
    -- These may be orphaned volumes from terminated instances, costing money
    -- and potentially containing sensitive data
    SELECT
        ci.awsaccountid                                                     AS account_id,
        ci.awsregion                                                        AS aws_region,
        ci.resourceid                                                       AS volume_id,
        json_extract_scalar(ci.configuration, '$.volumeType')               AS volume_type,
        json_extract_scalar(ci.configuration, '$.size')                     AS size_gb,
        json_extract_scalar(ci.configuration, '$.encrypted')                AS encrypted,
        json_extract_scalar(ci.configuration, '$.createTime')               AS create_time,
        ci.tags,
        ci.configurationitemcapturetime                                     AS snapshot_time,
        accountid                                                           AS partition_account,
        dt                                                                  AS snapshot_date
    FROM ${aws_glue_catalog_database.security_ir.name}.${aws_glue_catalog_table.config_snapshots.name}
    CROSS JOIN UNNEST(configurationitems) AS t(ci)
    WHERE ci.resourcetype = 'AWS::EC2::Volume'
        AND ci.configurationitemstatus = 'OK'
        AND json_extract_scalar(ci.configuration, '$.state') = 'available'
        -- AND accountid = '123456789012'
        -- AND region = 'us-east-1'
        -- AND dt = '2025/7/1'
    ORDER BY ci.awsaccountid, ci.awsregion, ci.resourceid
  SQL
}


# --------------------------------------------------------------------------
# RDS Instances - No Multi-AZ
# --------------------------------------------------------------------------
resource "aws_athena_named_query" "rds_instances_no_multi_az" {
  name        = "rds_instances_no_multi_az"
  workgroup   = aws_athena_workgroup.security_ir.id
  database    = aws_glue_catalog_database.security_ir.name
  description = "Find RDS instances without Multi-AZ enabled. Single-AZ instances have no automatic failover — an AZ outage takes them offline. Production databases should always be Multi-AZ. Dev/test instances appearing here may be acceptable."

  query = <<-SQL
    -- Find RDS instances running without Multi-AZ
    -- Single-AZ instances have no automatic failover and are vulnerable to AZ outages
    SELECT
        ci.awsaccountid                                                     AS account_id,
        ci.awsregion                                                        AS aws_region,
        ci.resourceid                                                       AS db_instance_id,
        json_extract_scalar(ci.configuration, '$.engine')                   AS engine,
        json_extract_scalar(ci.configuration, '$.engineVersion')            AS engine_version,
        json_extract_scalar(ci.configuration, '$.dBInstanceClass')          AS instance_class,
        json_extract_scalar(ci.configuration, '$.multiAZ')                  AS multi_az,
        json_extract_scalar(ci.configuration, '$.availabilityZone')         AS availability_zone,
        json_extract_scalar(ci.configuration, '$.dBInstanceStatus')         AS status,
        ci.configurationitemcapturetime                                     AS snapshot_time,
        accountid                                                           AS partition_account,
        dt                                                                  AS snapshot_date
    FROM ${aws_glue_catalog_database.security_ir.name}.${aws_glue_catalog_table.config_snapshots.name}
    CROSS JOIN UNNEST(configurationitems) AS t(ci)
    WHERE ci.resourcetype = 'AWS::RDS::DBInstance'
        AND ci.configurationitemstatus = 'OK'
        AND json_extract_scalar(ci.configuration, '$.multiAZ') = 'false'
        -- AND accountid = '123456789012'
        -- AND region = 'us-east-1'
        -- AND dt = '2025/7/1'
    ORDER BY ci.awsaccountid, ci.awsregion, ci.resourceid
  SQL
}


# --------------------------------------------------------------------------
# Resource Count by Type
# --------------------------------------------------------------------------
resource "aws_athena_named_query" "resource_count_by_type" {
  name        = "resource_count_by_type"
  workgroup   = aws_athena_workgroup.security_ir.id
  database    = aws_glue_catalog_database.security_ir.name
  description = "Count all resources by type across the org. Quick inventory overview — shows what resource types exist and how many of each. Large result set without partition filters. Add dt filter to limit to a specific snapshot date."

  query = <<-SQL
    -- Count resources by type across all accounts
    -- Gives a quick inventory overview of what exists in the org
    SELECT
        ci.resourcetype                     AS resource_type,
        COUNT(*)                            AS resource_count
    FROM ${aws_glue_catalog_database.security_ir.name}.${aws_glue_catalog_table.config_snapshots.name}
    CROSS JOIN UNNEST(configurationitems) AS t(ci)
    WHERE ci.configurationitemstatus = 'OK'
        -- AND accountid = '123456789012'
        -- AND dt = '2025/7/1'
    GROUP BY ci.resourcetype
    ORDER BY resource_count DESC
  SQL
}


# --------------------------------------------------------------------------
# Resource Count by Account
# --------------------------------------------------------------------------
resource "aws_athena_named_query" "resource_count_by_account" {
  name        = "resource_count_by_account"
  workgroup   = aws_athena_workgroup.security_ir.id
  database    = aws_glue_catalog_database.security_ir.name
  description = "Count all resources by account with total count and number of distinct resource types. Identify which accounts have the largest footprint. Add dt filter to limit to a specific snapshot date."

  query = <<-SQL
    -- Count resources by account across all types and regions
    -- Useful for identifying which accounts have the largest footprint
    SELECT
        ci.awsaccountid                     AS account_id,
        COUNT(*)                            AS total_resources,
        COUNT(DISTINCT ci.resourcetype)     AS resource_types
    FROM ${aws_glue_catalog_database.security_ir.name}.${aws_glue_catalog_table.config_snapshots.name}
    CROSS JOIN UNNEST(configurationitems) AS t(ci)
    WHERE ci.configurationitemstatus = 'OK'
        -- AND accountid = '123456789012'
        -- AND dt = '2025/7/1'
    GROUP BY ci.awsaccountid
    ORDER BY total_resources DESC
  SQL
}


# --------------------------------------------------------------------------
# Tagged Resources Audit
# --------------------------------------------------------------------------
resource "aws_athena_named_query" "tagged_resources_audit" {
  name        = "tagged_resources_audit"
  workgroup   = aws_athena_workgroup.security_ir.id
  database    = aws_glue_catalog_database.security_ir.name
  description = "Find resources missing required tags (Service_Name, Owning_Team). Only checks taggable resource types: EC2, EBS, SGs, RDS, S3, Lambda, ALBs. Adjust the tag key names in the SQL to match your tagging policy. Large result set — always add partition filters."

  query = <<-SQL
    -- Find resources missing required tags
    -- Adjust the tag keys below to match your organization's tagging policy
    -- Only checks taggable resource types (EC2, RDS, S3, Lambda, etc.)
    SELECT
        ci.awsaccountid                     AS account_id,
        ci.awsregion                        AS aws_region,
        ci.resourcetype                     AS resource_type,
        ci.resourceid                       AS resource_id,
        ci.resourcename                     AS resource_name,
        ci.arn,
        ci.tags,
        CASE WHEN element_at(ci.tags, 'Service_Name') IS NULL THEN 'MISSING' ELSE 'OK' END AS service_name_tag,
        CASE WHEN element_at(ci.tags, 'Owning_Team') IS NULL THEN 'MISSING' ELSE 'OK' END  AS owning_team_tag,
        ci.configurationitemcapturetime     AS snapshot_time,
        accountid                           AS partition_account,
        dt                                  AS snapshot_date
    FROM ${aws_glue_catalog_database.security_ir.name}.${aws_glue_catalog_table.config_snapshots.name}
    CROSS JOIN UNNEST(configurationitems) AS t(ci)
    WHERE ci.configurationitemstatus = 'OK'
        AND ci.resourcetype IN (
            'AWS::EC2::Instance',
            'AWS::EC2::Volume',
            'AWS::EC2::SecurityGroup',
            'AWS::RDS::DBInstance',
            'AWS::S3::Bucket',
            'AWS::Lambda::Function',
            'AWS::ElasticLoadBalancingV2::LoadBalancer'
        )
        AND (
            element_at(ci.tags, 'Service_Name') IS NULL
            OR element_at(ci.tags, 'Owning_Team') IS NULL
        )
        -- AND accountid = '123456789012'
        -- AND region = 'us-east-1'
        -- AND dt = '2025/7/1'
    ORDER BY ci.awsaccountid, ci.resourcetype, ci.resourceid
  SQL
}


# --------------------------------------------------------------------------
# Config Snapshot Timeline
# --------------------------------------------------------------------------
resource "aws_athena_named_query" "config_snapshot_timeline" {
  name        = "config_snapshot_timeline"
  workgroup   = aws_athena_workgroup.security_ir.id
  database    = aws_glue_catalog_database.security_ir.name
  description = "View Config snapshot delivery timeline per account and region. Use to verify Config is actively recording in all accounts — gaps in the timeline indicate Config recorder issues. Shows earliest/latest capture times and number of resource types per snapshot."

  query = <<-SQL
    -- Show Config snapshot delivery timeline per account and region
    -- Useful for verifying Config is actively recording in all accounts
    -- Gaps in the timeline may indicate Config recorder issues
    SELECT
        accountid                                               AS account_id,
        region,
        dt                                                      AS snapshot_date,
        COUNT(*)                                                AS snapshot_files,
        MIN(ci.configurationitemcapturetime)                    AS earliest_capture,
        MAX(ci.configurationitemcapturetime)                    AS latest_capture,
        COUNT(DISTINCT ci.resourcetype)                        AS resource_types_recorded
    FROM ${aws_glue_catalog_database.security_ir.name}.${aws_glue_catalog_table.config_snapshots.name}
    CROSS JOIN UNNEST(configurationitems) AS t(ci)
    WHERE ci.configurationitemstatus = 'OK'
        -- AND accountid = '123456789012'
        -- AND dt BETWEEN '2025/7/1' AND '2025/7/7'
    GROUP BY accountid, region, dt
    ORDER BY accountid, region, dt DESC
  SQL
}
