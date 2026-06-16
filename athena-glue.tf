###############################################
# Athena Workgroup
###############################################
resource "aws_athena_workgroup" "security_ir" {
  name = "security-incident-response"

  configuration {
    enforce_workgroup_configuration    = true
    publish_cloudwatch_metrics_enabled = true
    bytes_scanned_cutoff_per_query     = var.bytes_scanned_cutoff

    result_configuration {
      output_location = "s3://${module.athena_results.id}/results/"

      encryption_configuration {
        encryption_option = "SSE_S3"
      }
    }
  }
}


###############################################
# Glue Catalog Database
###############################################
resource "aws_glue_catalog_database" "security_ir" {
  name        = "security_incident_response"
  description = "AWS Config and CloudTrail data for security incident response queries"
}


###############################################
# Glue Table - Config Snapshots
###############################################
# Maps the JSON structure of AWS Config configuration snapshots delivered to S3.
# Uses partition projection so new accounts, regions, and dates are automatically
# discovered without running MSCK REPAIR TABLE.
#
# Config snapshot S3 path:
#   s3://company-config/config/AWSLogs/{account_id}/Config/{region}/{yyyy}/{M}/{d}/ConfigSnapshot/
#
# Query pattern:
#   SELECT ci.* FROM config_snapshots
#   CROSS JOIN UNNEST(configurationitems) AS t(ci)
#   WHERE ci.resourcetype = 'AWS::EC2::SecurityGroup'
#     AND accountid = '123456789012'
#     AND dt = '2025/7/1'

resource "aws_glue_catalog_table" "config_snapshots" {
  name          = "config_snapshots"
  database_name = aws_glue_catalog_database.security_ir.name
  description   = "AWS Config configuration snapshots from all org accounts"
  table_type    = "EXTERNAL_TABLE"

  parameters = {
    "classification"              = "json"
    "compressionType"             = "gzip"
    "projection.enabled"          = "true"
    "projection.accountid.type"   = "enum"
    "projection.accountid.values" = join(",", local.org_account_ids)
    "projection.region.type"      = "enum"
    "projection.region.values"    = join(",", var.config_regions)
    "projection.dt.type"          = "date"
    "projection.dt.range"         = "2025/1/1,NOW"
    "projection.dt.format"        = "yyyy/M/d"
    "projection.dt.interval"      = "1"
    "projection.dt.interval.unit" = "DAYS"
    "storage.location.template"   = "s3://${var.config_bucket_name}/${var.config_s3_prefix}/AWSLogs/$${accountid}/Config/$${region}/$${dt}/ConfigSnapshot"
  }

  partition_keys {
    name = "accountid"
    type = "string"
  }

  partition_keys {
    name = "region"
    type = "string"
  }

  partition_keys {
    name = "dt"
    type = "string"
  }

  storage_descriptor {
    location      = "s3://${var.config_bucket_name}/${var.config_s3_prefix}/AWSLogs/"
    input_format  = "org.apache.hadoop.mapred.TextInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"

    ser_de_info {
      serialization_library = "org.openx.data.jsonserde.JsonSerDe"
      parameters = {
        "serialization.format" = "1"
        "case.insensitive"     = "true"
      }
    }

    columns {
      name = "fileversion"
      type = "string"
    }

    columns {
      name = "configsnapshotid"
      type = "string"
    }

    columns {
      name = "configurationitems"
      type = "array<struct<configurationItemVersion:string,configurationItemCaptureTime:string,configurationItemStatus:string,configurationStateId:string,awsAccountId:string,configurationItemMD5Hash:string,arn:string,resourceType:string,resourceId:string,resourceName:string,awsRegion:string,availabilityZone:string,resourceCreationTime:string,tags:map<string,string>,relatedEvents:array<string>,relationships:array<struct<resourceId:string,resourceType:string,relationshipName:string>>,configuration:string,supplementaryConfiguration:map<string,string>>>"
    }
  }
}


###############################################
# Glue Table - CloudTrail Logs
###############################################
# Maps the JSON structure of AWS CloudTrail event logs delivered to S3.
# Uses the CloudTrail input format which automatically handles the Records
# array wrapper - each row is one API event (no UNNEST needed).
#
# CloudTrail S3 path (org trail):
#   s3://company-org-cloudtrail/company-org/AWSLogs/{org_id}/{account_id}/CloudTrail/{region}/{yyyy}/{MM}/{dd}/
#
# Query pattern (simpler than Config - no UNNEST):
#   SELECT * FROM cloudtrail_logs
#   WHERE eventname = 'ConsoleLogin'
#     AND accountid = '123456789012'
#     AND dt = '2025/01/15'

resource "aws_glue_catalog_table" "cloudtrail_logs" {
  name          = "cloudtrail_logs"
  database_name = aws_glue_catalog_database.security_ir.name
  description   = "AWS CloudTrail API event logs from all org accounts"
  table_type    = "EXTERNAL_TABLE"

  parameters = {
    "classification"              = "cloudtrail"
    "compressionType"             = "gzip"
    "projection.enabled"          = "true"
    "projection.accountid.type"   = "enum"
    "projection.accountid.values" = join(",", local.org_account_ids)
    "projection.region.type"      = "enum"
    "projection.region.values"    = join(",", var.cloudtrail_regions)
    "projection.dt.type"          = "date"
    "projection.dt.range"         = "2025/01/01,NOW"
    "projection.dt.format"        = "yyyy/MM/dd"
    "projection.dt.interval"      = "1"
    "projection.dt.interval.unit" = "DAYS"
    "storage.location.template"   = "s3://${var.cloudtrail_bucket_name}/${var.cloudtrail_s3_prefix}/AWSLogs/${local.org_id}/$${accountid}/CloudTrail/$${region}/$${dt}"
  }

  partition_keys {
    name = "accountid"
    type = "string"
  }

  partition_keys {
    name = "region"
    type = "string"
  }

  partition_keys {
    name = "dt"
    type = "string"
  }

  storage_descriptor {
    location      = "s3://${var.cloudtrail_bucket_name}/${var.cloudtrail_s3_prefix}/AWSLogs/${local.org_id}/"
    input_format  = "com.amazon.emr.cloudtrail.CloudTrailInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"

    ser_de_info {
      serialization_library = "org.apache.hive.hcatalog.data.JsonSerDe"
    }

    columns {
      name = "eventversion"
      type = "string"
    }

    columns {
      name = "useridentity"
      type = "struct<type:string,principalid:string,arn:string,accountid:string,invokedby:string,accesskeyid:string,username:string,sessioncontext:struct<attributes:struct<mfaauthenticated:string,creationdate:string>,sessionissuer:struct<type:string,principalid:string,arn:string,accountid:string,username:string>>>"
    }

    columns {
      name = "eventtime"
      type = "string"
    }

    columns {
      name = "eventsource"
      type = "string"
    }

    columns {
      name = "eventname"
      type = "string"
    }

    columns {
      name = "awsregion"
      type = "string"
    }

    columns {
      name = "sourceipaddress"
      type = "string"
    }

    columns {
      name = "useragent"
      type = "string"
    }

    columns {
      name = "errorcode"
      type = "string"
    }

    columns {
      name = "errormessage"
      type = "string"
    }

    columns {
      name = "requestparameters"
      type = "string"
    }

    columns {
      name = "responseelements"
      type = "string"
    }

    columns {
      name = "additionaleventdata"
      type = "string"
    }

    columns {
      name = "requestid"
      type = "string"
    }

    columns {
      name = "eventid"
      type = "string"
    }

    columns {
      name = "resources"
      type = "array<struct<arn:string,accountid:string,type:string>>"
    }

    columns {
      name = "eventtype"
      type = "string"
    }

    columns {
      name = "apiversion"
      type = "string"
    }

    columns {
      name = "readonly"
      type = "string"
    }

    columns {
      name = "recipientaccountid"
      type = "string"
    }

    columns {
      name = "serviceeventdetails"
      type = "string"
    }

    columns {
      name = "sharedeventid"
      type = "string"
    }

    columns {
      name = "vpcendpointid"
      type = "string"
    }

    columns {
      name = "tlsdetails"
      type = "struct<tlsversion:string,ciphersuite:string,clientprovidedhostheader:string>"
    }
  }
}
