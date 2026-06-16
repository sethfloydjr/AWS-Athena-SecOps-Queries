variable "workspace_iam_roles" {
  default = {
    #Uncomment ONLY the workspace that you need to use. DO NOT USE DEFAULT WORKSPACE!!!!!!
    #app           = "arn:aws:iam::111111111101:role/Atlantis" # company-app
    #dev           = "arn:aws:iam::111111111102:role/Atlantis" # company-dev
    #stage         = "arn:aws:iam::111111111103:role/Atlantis" # company-stage
    #prod          = "arn:aws:iam::111111111104:role/Atlantis" # company-prod
    security = "arn:aws:iam::111111111105:role/Atlantis" # company-security
    #sandbox       = "arn:aws:iam::111111111106:role/Atlantis" # company-sandbox
    #qa            = "arn:aws:iam::111111111107:role/Atlantis" # company-qa
    #root          = "arn:aws:iam::111111111108:role/Atlantis" # company-root
    #tooling       = "arn:aws:iam::111111111109:role/Atlantis" # company-tooling
    #datascience   = "arn:aws:iam::111111111110:role/Atlantis" # company-datascience
    #backend_test  = "arn:aws:iam::111111111111:role/Atlantis" # company-backend_test
    #client_test   = "arn:aws:iam::111111111112:role/Atlantis" # company-client_test
  }
}
