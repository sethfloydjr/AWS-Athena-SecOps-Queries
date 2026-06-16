terraform {
  backend "s3" {
    bucket         = "company-tf-state"
    key            = "athena.tfstate"
    dynamodb_table = "company-tf-state-lock"
    region         = "us-east-1"
  }
}
