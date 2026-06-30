variable "workspace_iam_roles" {
  type = map(string)
  default = {
    security = "arn:aws:iam::111111111105:role/TFAdmin" # company-security
  }
}
