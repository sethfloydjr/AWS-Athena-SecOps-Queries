terraform {
  required_version = ">= 1.15.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0.0, < 7.0.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = ">= 2.0.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
  assume_role {
    role_arn = var.workspace_iam_roles[terraform.workspace]
  }
  default_tags {
    tags = {
      "Service_Name"        = var.service_name
      "Owning_Team"         = var.owning_team
      "Automation"          = var.automation_tf
      "Terraform Base Path" = "path/to/where/you/put/the/code"
    }
  }
}

provider "aws" {
  alias  = "west"
  region = "us-west-2"
  assume_role {
    role_arn = var.workspace_iam_roles[terraform.workspace]
  }
  default_tags {
    tags = {
      "Service_Name"        = var.service_name
      "Owning_Team"         = var.owning_team
      "Automation"          = var.automation_tf
      "Terraform Base Path" = "path/to/where/you/put/the/code"
    }
  }
}
