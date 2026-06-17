terraform {
  required_version = ">= 1.15.6"
  required_providers {
    aws = {
      source                = "hashicorp/aws"
      version               = ">= 6.0.0, < 7.0.0"
      configuration_aliases = [aws.west]
    }
  }
}
