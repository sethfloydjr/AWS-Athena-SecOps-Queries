locals {
  org_account_ids = [for account in data.aws_organizations_organization.current.accounts : account.id]
  org_id          = data.aws_organizations_organization.current.id
}
