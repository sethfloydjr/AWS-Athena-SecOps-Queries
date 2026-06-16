###############################################
# Diagnostic Named Queries
###############################################
# Use these queries to validate that partition projection is resolving correctly
# and that Athena can actually find data in both Glue tables.
# Run these first when a query returns unexpected empty results.


# --------------------------------------------------------------------------
# Partition Health Check - CloudTrail
# --------------------------------------------------------------------------
resource "aws_athena_named_query" "diag_cloudtrail_partition_check" {
  name        = "diag_cloudtrail_partition_check"
  workgroup   = aws_athena_workgroup.security_ir.id
  database    = aws_glue_catalog_database.security_ir.name
  description = "Validates cloudtrail_logs partition projection is resolving. Returns distinct accounts/regions/dates found in the last 3 days. Empty result = path or format mismatch."

  query = <<-SQL
    -- Validates that partition projection is resolving correctly for cloudtrail_logs.
    -- Should return rows for each account/region active in the last 3 days.
    -- Empty result means the storage.location.template or dt format does not match
    -- the actual S3 path structure - check the Glue table config.
    SELECT
        accountid,
        region,
        dt,
        COUNT(*) AS event_count
    FROM ${aws_glue_catalog_database.security_ir.name}.${aws_glue_catalog_table.cloudtrail_logs.name}
    WHERE dt >= date_format(current_date - interval '3' day, '%Y/%m/%d')
        AND dt <= date_format(current_date, '%Y/%m/%d')
    GROUP BY accountid, region, dt
    ORDER BY dt DESC, accountid, region
    LIMIT 50
  SQL
}


# --------------------------------------------------------------------------
# Partition Health Check - Config Snapshots
# --------------------------------------------------------------------------
resource "aws_athena_named_query" "diag_config_partition_check" {
  name        = "diag_config_partition_check"
  workgroup   = aws_athena_workgroup.security_ir.id
  database    = aws_glue_catalog_database.security_ir.name
  description = "Validates config_snapshots partition projection is resolving. Returns distinct accounts/regions/dates found in the last 7 days. Empty result = path or format mismatch."

  query = <<-SQL
    -- Validates that partition projection is resolving correctly for config_snapshots.
    -- Config snapshots are delivered less frequently than CloudTrail so we look back 7 days.
    -- Empty result means the storage.location.template or dt format does not match
    -- the actual S3 path structure - check the Glue table config.
    SELECT
        accountid,
        region,
        dt,
        COUNT(*) AS snapshot_count
    FROM ${aws_glue_catalog_database.security_ir.name}.${aws_glue_catalog_table.config_snapshots.name}
    WHERE dt >= date_format(current_date - interval '7' day, '%Y/%c/%e')
        AND dt <= date_format(current_date, '%Y/%c/%e')
    GROUP BY accountid, region, dt
    ORDER BY dt DESC, accountid, region
    LIMIT 50
  SQL
}
