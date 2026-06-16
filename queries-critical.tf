###############################################
# Named Queries for Incident Response
###############################################
# All queries use the config_snapshots table.
# Query pattern: CROSS JOIN UNNEST(configurationitems) AS t(ci) to flatten
# the snapshot array, then filter on ci.resourcetype, ci.configuration, etc.
#
# PARTITION FILTERS: Always add accountid, region, and/or dt filters when
# possible to limit data scanned and reduce cost. Examples shown in comments.


# --------------------------------------------------------------------------
# IAM Users - All
# --------------------------------------------------------------------------
resource "aws_athena_named_query" "iam_users_all" {
  name        = "iam_users_all"
  workgroup   = aws_athena_workgroup.security_ir.id
  database    = aws_glue_catalog_database.security_ir.name
  description = "List all IAM users across all accounts with creation dates. Queries Config snapshots (point-in-time state, not real-time). IAM is global — only scans us-east-1. Use during credential compromise to inventory who exists."

  query = <<-SQL
    -- List all IAM users across all accounts
    -- IAM is global so we only need region = 'us-east-1'
    SELECT
        ci.awsaccountid                                         AS account_id,
        ci.resourcename                                         AS user_name,
        ci.arn,
        json_extract_scalar(ci.configuration, '$.path')         AS iam_path,
        json_extract_scalar(ci.configuration, '$.createDate')   AS create_date,
        ci.configurationitemcapturetime                         AS snapshot_time,
        accountid                                               AS partition_account,
        dt                                                      AS snapshot_date
    FROM ${aws_glue_catalog_database.security_ir.name}.${aws_glue_catalog_table.config_snapshots.name}
    CROSS JOIN UNNEST(configurationitems) AS t(ci)
    WHERE ci.resourcetype = 'AWS::IAM::User'
        AND ci.configurationitemstatus = 'OK'
        AND region = 'us-east-1'
        -- AND accountid = '123456789012'
        -- AND dt = '2025/7/1'
    ORDER BY ci.awsaccountid, ci.resourcename
  SQL
}


# --------------------------------------------------------------------------
# IAM Access Keys - Active
# --------------------------------------------------------------------------
resource "aws_athena_named_query" "iam_access_keys_active" {
  name        = "iam_access_keys_active"
  workgroup   = aws_athena_workgroup.security_ir.id
  database    = aws_glue_catalog_database.security_ir.name
  description = "Find all IAM users with active access keys across all accounts. Shows key details as JSON. Use to identify keys needing rotation or revocation during an incident. Data is from Config snapshots — keys created after the last snapshot won't appear."

  query = <<-SQL
    -- Find IAM users that have at least one active access key
    -- The access_keys column shows the full key details as JSON
    SELECT
        ci.awsaccountid                                              AS account_id,
        ci.resourcename                                              AS user_name,
        ci.arn,
        json_extract(ci.configuration, '$.accessKeys')               AS access_keys,
        json_extract_scalar(ci.configuration, '$.createDate')        AS user_create_date,
        ci.configurationitemcapturetime                              AS snapshot_time,
        accountid                                                    AS partition_account,
        dt                                                           AS snapshot_date
    FROM ${aws_glue_catalog_database.security_ir.name}.${aws_glue_catalog_table.config_snapshots.name}
    CROSS JOIN UNNEST(configurationitems) AS t(ci)
    WHERE ci.resourcetype = 'AWS::IAM::User'
        AND ci.configurationitemstatus = 'OK'
        AND region = 'us-east-1'
        AND ci.configuration LIKE '%"status":"Active"%'
        -- AND accountid = '123456789012'
        -- AND dt = '2025/7/1'
    ORDER BY ci.awsaccountid, ci.resourcename
  SQL
}


# --------------------------------------------------------------------------
# IAM Policies - Admin Access
# --------------------------------------------------------------------------
resource "aws_athena_named_query" "iam_policies_admin_access" {
  name        = "iam_policies_admin_access"
  workgroup   = aws_athena_workgroup.security_ir.id
  database    = aws_glue_catalog_database.security_ir.name
  description = "Find IAM users, roles, and groups with AdministratorAccess or broad wildcard (Action:* Resource:*) policies. Checks both managed and inline policies via string matching. May miss custom policy names that grant equivalent access without using 'AdministratorAccess' keyword."

  query = <<-SQL
    -- Find IAM principals with admin-level access
    -- Checks for AdministratorAccess managed policy or inline policies with Action:* Resource:*
    SELECT
        ci.awsaccountid                     AS account_id,
        ci.resourcetype                     AS resource_type,
        ci.resourcename                     AS resource_name,
        ci.arn,
        ci.configuration,
        ci.configurationitemcapturetime     AS snapshot_time,
        accountid                           AS partition_account,
        dt                                  AS snapshot_date
    FROM ${aws_glue_catalog_database.security_ir.name}.${aws_glue_catalog_table.config_snapshots.name}
    CROSS JOIN UNNEST(configurationitems) AS t(ci)
    WHERE ci.resourcetype IN ('AWS::IAM::User', 'AWS::IAM::Role', 'AWS::IAM::Group')
        AND ci.configurationitemstatus = 'OK'
        AND region = 'us-east-1'
        AND (
            ci.configuration LIKE '%AdministratorAccess%'
            OR ci.configuration LIKE '%"effect":"Allow"%action":"*"%resource":"*"%'
            OR ci.configuration LIKE '%"Effect":"Allow"%Action":"*"%Resource":"*"%'
        )
        -- AND accountid = '123456789012'
        -- AND dt = '2025/7/1'
    ORDER BY ci.awsaccountid, ci.resourcetype, ci.resourcename
  SQL
}


# --------------------------------------------------------------------------
# IAM Roles - Cross Account Trust
# --------------------------------------------------------------------------
resource "aws_athena_named_query" "iam_roles_cross_account_trust" {
  name        = "iam_roles_cross_account_trust"
  workgroup   = aws_athena_workgroup.security_ir.id
  database    = aws_glue_catalog_database.security_ir.name
  description = "Find IAM roles that trust other AWS accounts via sts:AssumeRole. Review the trust_policy column to identify principals outside your org. Known org account IDs are listed in the SQL comments for reference. Does not detect trust via SAML/OIDC federation — only IAM cross-account."

  query = <<-SQL
    -- Find IAM roles that trust other AWS accounts via sts:AssumeRole
    -- Review the trust_policy column to identify principals outside your org
    -- Known org accounts: ${join(", ", local.org_account_ids)}
    SELECT
        ci.awsaccountid                                                         AS account_id,
        ci.resourcename                                                         AS role_name,
        ci.arn,
        json_extract(ci.configuration, '$.assumeRolePolicyDocument')            AS trust_policy,
        ci.configurationitemcapturetime                                         AS snapshot_time,
        accountid                                                               AS partition_account,
        dt                                                                      AS snapshot_date
    FROM ${aws_glue_catalog_database.security_ir.name}.${aws_glue_catalog_table.config_snapshots.name}
    CROSS JOIN UNNEST(configurationitems) AS t(ci)
    WHERE ci.resourcetype = 'AWS::IAM::Role'
        AND ci.configurationitemstatus = 'OK'
        AND region = 'us-east-1'
        AND ci.configuration LIKE '%sts:AssumeRole%'
        AND ci.configuration LIKE '%arn:aws:iam::%'
        -- AND accountid = '123456789012'
        -- AND dt = '2025/7/1'
    ORDER BY ci.awsaccountid, ci.resourcename
  SQL
}


# --------------------------------------------------------------------------
# Security Groups - Open Ingress (0.0.0.0/0 or ::/0)
# --------------------------------------------------------------------------
resource "aws_athena_named_query" "security_groups_open_ingress" {
  name        = "security_groups_open_ingress"
  workgroup   = aws_athena_workgroup.security_ir.id
  database    = aws_glue_catalog_database.security_ir.name
  description = "Find security groups with ANY inbound rule open to the internet (0.0.0.0/0 or ::/0). Scans all regions. Shows the full ingress_rules JSON — check the port ranges manually. High volume in orgs with ALBs/NLBs (which legitimately use 0.0.0.0/0 on 80/443)."

  query = <<-SQL
    -- Find security groups with any rule open to the internet
    -- Scans all regions since security groups are regional resources
    SELECT
        ci.awsaccountid                                                 AS account_id,
        ci.awsregion                                                    AS aws_region,
        ci.resourceid                                                   AS security_group_id,
        json_extract_scalar(ci.configuration, '$.groupName')            AS group_name,
        json_extract_scalar(ci.configuration, '$.vpcId')                AS vpc_id,
        json_extract_scalar(ci.configuration, '$.description')          AS description,
        json_extract(ci.configuration, '$.ipPermissions')               AS ingress_rules,
        ci.configurationitemcapturetime                                 AS snapshot_time,
        accountid                                                       AS partition_account,
        dt                                                              AS snapshot_date
    FROM ${aws_glue_catalog_database.security_ir.name}.${aws_glue_catalog_table.config_snapshots.name}
    CROSS JOIN UNNEST(configurationitems) AS t(ci)
    WHERE ci.resourcetype = 'AWS::EC2::SecurityGroup'
        AND ci.configurationitemstatus = 'OK'
        AND (ci.configuration LIKE '%0.0.0.0/0%' OR ci.configuration LIKE '%::/0%')
        -- AND accountid = '123456789012'
        -- AND region = 'us-east-1'
        -- AND dt = '2025/7/1'
    ORDER BY ci.awsaccountid, ci.awsregion, ci.resourceid
  SQL
}


# --------------------------------------------------------------------------
# Security Groups - Open SSH (22) or RDP (3389)
# --------------------------------------------------------------------------
resource "aws_athena_named_query" "security_groups_open_ssh_rdp" {
  name        = "security_groups_open_ssh_rdp"
  workgroup   = aws_athena_workgroup.security_ir.id
  database    = aws_glue_catalog_database.security_ir.name
  description = "Find security groups with SSH (22), RDP (3389), or all-traffic (protocol -1) open to the internet. More targeted than open_ingress — these specific ports are the most common attacker entry points. Includes both IPv4 (0.0.0.0/0) and IPv6 (::/0)."

  query = <<-SQL
    -- Find security groups with SSH, RDP, or all-traffic open to the internet
    -- ipProtocol -1 means ALL traffic (all ports, all protocols)
    SELECT
        ci.awsaccountid                                                 AS account_id,
        ci.awsregion                                                    AS aws_region,
        ci.resourceid                                                   AS security_group_id,
        json_extract_scalar(ci.configuration, '$.groupName')            AS group_name,
        json_extract_scalar(ci.configuration, '$.vpcId')                AS vpc_id,
        json_extract(ci.configuration, '$.ipPermissions')               AS ingress_rules,
        ci.configurationitemcapturetime                                 AS snapshot_time,
        accountid                                                       AS partition_account,
        dt                                                              AS snapshot_date
    FROM ${aws_glue_catalog_database.security_ir.name}.${aws_glue_catalog_table.config_snapshots.name}
    CROSS JOIN UNNEST(configurationitems) AS t(ci)
    WHERE ci.resourcetype = 'AWS::EC2::SecurityGroup'
        AND ci.configurationitemstatus = 'OK'
        AND (ci.configuration LIKE '%0.0.0.0/0%' OR ci.configuration LIKE '%::/0%')
        AND (
            ci.configuration LIKE '%"fromPort":22,%'
            OR ci.configuration LIKE '%"fromPort":3389,%'
            OR ci.configuration LIKE '%"ipProtocol":"-1"%'
        )
        -- AND accountid = '123456789012'
        -- AND region = 'us-east-1'
        -- AND dt = '2025/7/1'
    ORDER BY ci.awsaccountid, ci.awsregion, ci.resourceid
  SQL
}


# --------------------------------------------------------------------------
# Public EC2 Instances
# --------------------------------------------------------------------------
resource "aws_athena_named_query" "public_ec2_instances" {
  name        = "public_ec2_instances"
  workgroup   = aws_athena_workgroup.security_ir.id
  database    = aws_glue_catalog_database.security_ir.name
  description = "Find EC2 instances with a public IP address assigned. Includes both auto-assigned and Elastic IPs. Shows instance state (running/stopped) — stopped instances with public IPs still appear. Does not show ELB/NLB public IPs or NAT gateway IPs."

  query = <<-SQL
    -- Find EC2 instances that have a public IP address assigned
    SELECT
        ci.awsaccountid                                                         AS account_id,
        ci.awsregion                                                            AS aws_region,
        ci.resourceid                                                           AS instance_id,
        json_extract_scalar(ci.configuration, '$.publicIpAddress')              AS public_ip,
        json_extract_scalar(ci.configuration, '$.publicDnsName')                AS public_dns,
        json_extract_scalar(ci.configuration, '$.privateIpAddress')             AS private_ip,
        json_extract_scalar(ci.configuration, '$.instanceType')                 AS instance_type,
        json_extract_scalar(ci.configuration, '$.state.name')                   AS state,
        json_extract_scalar(ci.configuration, '$.vpcId')                        AS vpc_id,
        json_extract_scalar(ci.configuration, '$.subnetId')                     AS subnet_id,
        ci.tags,
        ci.configurationitemcapturetime                                         AS snapshot_time,
        accountid                                                               AS partition_account,
        dt                                                                      AS snapshot_date
    FROM ${aws_glue_catalog_database.security_ir.name}.${aws_glue_catalog_table.config_snapshots.name}
    CROSS JOIN UNNEST(configurationitems) AS t(ci)
    WHERE ci.resourcetype = 'AWS::EC2::Instance'
        AND ci.configurationitemstatus = 'OK'
        AND json_extract_scalar(ci.configuration, '$.publicIpAddress') IS NOT NULL
        AND json_extract_scalar(ci.configuration, '$.publicIpAddress') != ''
        -- AND accountid = '123456789012'
        -- AND region = 'us-east-1'
        -- AND dt = '2025/7/1'
    ORDER BY ci.awsaccountid, ci.awsregion, ci.resourceid
  SQL
}


# --------------------------------------------------------------------------
# S3 Buckets - Public
# --------------------------------------------------------------------------
resource "aws_athena_named_query" "s3_buckets_public" {
  name        = "s3_buckets_public"
  workgroup   = aws_athena_workgroup.security_ir.id
  database    = aws_glue_catalog_database.security_ir.name
  description = "Find S3 buckets with public ACLs, AuthenticatedUsers grants, or incomplete public access blocks. NOTE: Does not check bucket policies — buckets made public via bucket policy (Principal: *) won't appear here. Use S3 Access Analyzer for full coverage."

  query = <<-SQL
    -- Find S3 buckets that may be publicly accessible
    -- Checks ACL grants for AllUsers/AuthenticatedUsers and PublicAccessBlock for false settings
    -- S3 is global in Config, so we only need region = 'us-east-1'
    SELECT
        ci.awsaccountid                                     AS account_id,
        ci.resourcename                                     AS bucket_name,
        ci.arn,
        element_at(ci.supplementaryconfiguration,
            'PublicAccessBlockConfiguration')                AS public_access_block,
        element_at(ci.supplementaryconfiguration,
            'AccessControlList')                             AS acl,
        ci.configurationitemcapturetime                     AS snapshot_time,
        accountid                                           AS partition_account,
        dt                                                  AS snapshot_date
    FROM ${aws_glue_catalog_database.security_ir.name}.${aws_glue_catalog_table.config_snapshots.name}
    CROSS JOIN UNNEST(configurationitems) AS t(ci)
    WHERE ci.resourcetype = 'AWS::S3::Bucket'
        AND ci.configurationitemstatus = 'OK'
        AND region = 'us-east-1'
        AND (
            element_at(ci.supplementaryconfiguration, 'AccessControlList') LIKE '%AllUsers%'
            OR element_at(ci.supplementaryconfiguration, 'AccessControlList') LIKE '%AuthenticatedUsers%'
            OR element_at(ci.supplementaryconfiguration, 'PublicAccessBlockConfiguration') LIKE '%false%'
        )
        -- AND accountid = '123456789012'
        -- AND dt = '2025/7/1'
    ORDER BY ci.awsaccountid, ci.resourcename
  SQL
}


# --------------------------------------------------------------------------
# EC2 Instances - Full Inventory by Account and Region
# --------------------------------------------------------------------------
resource "aws_athena_named_query" "ec2_instances_by_account_region" {
  name        = "ec2_instances_by_account_region"
  workgroup   = aws_athena_workgroup.security_ir.id
  database    = aws_glue_catalog_database.security_ir.name
  description = "Full EC2 inventory across all accounts and regions. Find any instance by IP, ID, or tags without logging into each account. Uncomment the filter lines at the bottom to search by private IP or instance ID. Large result set — always add partition filters."

  query = <<-SQL
    -- Full EC2 instance inventory across all accounts and regions
    -- Useful for finding an instance by IP, ID, or tags without logging into each account
    SELECT
        ci.awsaccountid                                                         AS account_id,
        ci.awsregion                                                            AS aws_region,
        ci.resourceid                                                           AS instance_id,
        json_extract_scalar(ci.configuration, '$.instanceType')                 AS instance_type,
        json_extract_scalar(ci.configuration, '$.state.name')                   AS state,
        json_extract_scalar(ci.configuration, '$.privateIpAddress')             AS private_ip,
        json_extract_scalar(ci.configuration, '$.publicIpAddress')              AS public_ip,
        json_extract_scalar(ci.configuration, '$.vpcId')                        AS vpc_id,
        json_extract_scalar(ci.configuration, '$.subnetId')                     AS subnet_id,
        json_extract_scalar(ci.configuration, '$.launchTime')                   AS launch_time,
        json_extract_scalar(ci.configuration, '$.imageId')                      AS ami_id,
        json_extract_scalar(ci.configuration, '$.iamInstanceProfile.arn')       AS instance_profile_arn,
        ci.tags,
        ci.configurationitemcapturetime                                         AS snapshot_time,
        accountid                                                               AS partition_account,
        dt                                                                      AS snapshot_date
    FROM ${aws_glue_catalog_database.security_ir.name}.${aws_glue_catalog_table.config_snapshots.name}
    CROSS JOIN UNNEST(configurationitems) AS t(ci)
    WHERE ci.resourcetype = 'AWS::EC2::Instance'
        AND ci.configurationitemstatus = 'OK'
        -- AND accountid = '123456789012'
        -- AND region = 'us-east-1'
        -- AND dt = '2025/7/1'
        -- AND json_extract_scalar(ci.configuration, '$.privateIpAddress') = '10.0.1.50'
        -- AND ci.resourceid = 'i-0abc123def456'
    ORDER BY ci.awsaccountid, ci.awsregion, ci.resourceid
  SQL
}


# --------------------------------------------------------------------------
# Resource Config by ID
# --------------------------------------------------------------------------
resource "aws_athena_named_query" "resource_config_by_id" {
  name        = "resource_config_by_id"
  workgroup   = aws_athena_workgroup.security_ir.id
  database    = aws_glue_catalog_database.security_ir.name
  description = "Look up the full configuration of any resource by resource ID or ARN. Replace RESOURCE_ID_HERE with the actual ID (e.g., sg-0abc123) or full ARN. Returns full Config JSON including supplementary configuration, tags, and relationships. Parameterized query — fill in the input field."

  query = <<-SQL
    -- Look up the full configuration of any resource by its ID or ARN
    -- REPLACE 'RESOURCE_ID_HERE' with the actual resource ID (e.g., sg-0abc123, i-0def456)
    -- or the full ARN (e.g., arn:aws:iam::123456789012:role/MyRole)
    SELECT
        ci.awsaccountid                     AS account_id,
        ci.awsregion                        AS aws_region,
        ci.resourcetype                     AS resource_type,
        ci.resourceid                       AS resource_id,
        ci.resourcename                     AS resource_name,
        ci.arn,
        ci.configurationitemstatus          AS status,
        ci.configuration,
        ci.supplementaryconfiguration,
        ci.tags,
        ci.relationships,
        ci.configurationitemcapturetime     AS snapshot_time,
        accountid                           AS partition_account,
        dt                                  AS snapshot_date
    FROM ${aws_glue_catalog_database.security_ir.name}.${aws_glue_catalog_table.config_snapshots.name}
    CROSS JOIN UNNEST(configurationitems) AS t(ci)
    WHERE (ci.resourceid = 'RESOURCE_ID_HERE' OR ci.arn = 'RESOURCE_ID_HERE')
        -- AND accountid = '123456789012'
        -- AND region = 'us-east-1'
        -- AND dt BETWEEN '2025/7/1' AND '2025/7/7'
    ORDER BY ci.configurationitemcapturetime DESC
  SQL
}


# --------------------------------------------------------------------------
# IAM Access Key Lookup
# --------------------------------------------------------------------------
resource "aws_athena_named_query" "iam_access_key_lookup" {
  name        = "iam_access_key_lookup"
  workgroup   = aws_athena_workgroup.security_ir.id
  database    = aws_glue_catalog_database.security_ir.name
  description = "Look up which IAM user owns a specific access key and what account it lives in. Replace ACCESS_KEY_ID_HERE with the key (e.g., AKIAIOSFODNN7EXAMPLE). Parameterized query. After finding the owner, use ct_credential_usage_by_ip to see what the key was doing."

  query = <<-SQL
    -- Find the IAM user that owns a specific access key
    -- REPLACE 'ACCESS_KEY_ID_HERE' with the access key ID (e.g., AKIAIOSFODNN7EXAMPLE)
    --
    -- TIP: Use this to identify the owner, then use ct_credential_usage_by_ip
    -- to see what the key has been doing in CloudTrail
    SELECT
        ci.awsaccountid                                              AS account_id,
        ci.resourcename                                              AS user_name,
        ci.arn                                                       AS user_arn,
        json_extract(ci.configuration, '$.accessKeys')               AS access_keys,
        json_extract_scalar(ci.configuration, '$.createDate')        AS user_create_date,
        ci.configurationitemcapturetime                              AS snapshot_time,
        accountid                                                    AS partition_account,
        dt                                                           AS snapshot_date
    FROM ${aws_glue_catalog_database.security_ir.name}.${aws_glue_catalog_table.config_snapshots.name}
    CROSS JOIN UNNEST(configurationitems) AS t(ci)
    WHERE ci.resourcetype = 'AWS::IAM::User'
        AND ci.configurationitemstatus = 'OK'
        AND region = 'us-east-1'
        AND ci.configuration LIKE '%ACCESS_KEY_ID_HERE%'
        -- AND accountid = '123456789012'
        -- AND dt = '2025/7/1'
    ORDER BY ci.awsaccountid, ci.resourcename
  SQL
}
