variable "aws_region" {
  type    = string
  default = "eu-central-1"
}

variable "project_name" {
    type    = string
    default = ""
}

variable "dbt_docs_lambda_edge_name" {
  type    = string
  default = ""
}


# Cognito
variable "admin_email" {
  type    = string
  default = ""
}

variable "cognito_user_pool_domain_name" {
  type    = string
  default = ""
}

variable "cognito_user_pool_client_name" {
  type    = string
  default = ""
}

variable "cognito_user_pool_name" {
  type    = string
  default = ""
}

# WAF
variable "ip_adresses_cidr" {
  type    = string
  default = "/32"
}

# lambda
variable "lambda_edge_role_name" {
  type    = string
  default = ""
}

variable "lambda_erge_policy_name" {
  type    = string
  default = ""
}