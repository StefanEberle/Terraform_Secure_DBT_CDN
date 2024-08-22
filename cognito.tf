resource "aws_cognito_user_pool" "user_pool" {
  name = var.cognito_user_pool_name

  admin_create_user_config {
    allow_admin_create_user_only = true
  }

  password_policy {
    temporary_password_validity_days = 365
    minimum_length                   = 8
    require_lowercase                = true
    require_numbers                  = true
    require_symbols                  = true
    require_uppercase                = true
  }

  schema {
    name                = "email"
    attribute_data_type = "String"
    mutable             = true
    required            = true
  }

  mfa_configuration = "ON"

  software_token_mfa_configuration {
    enabled = true
  }


}

resource "aws_cognito_user_pool_domain" "user_pool_domain" {
  domain       = var.cognito_user_pool_domain_name
  user_pool_id = aws_cognito_user_pool.user_pool.id
}

resource "aws_cognito_user_pool_client" "user_pool_client" {
  name         = var.cognito_user_pool_client_name
  user_pool_id = aws_cognito_user_pool.user_pool.id

  generate_secret     = true
  explicit_auth_flows = ["ALLOW_USER_SRP_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]

  callback_urls                        = ["https://${aws_cloudfront_distribution.dbt_docs_distribution.domain_name}/"]
  allowed_oauth_flows_user_pool_client = true
  allowed_oauth_flows                  = ["code"]
  allowed_oauth_scopes                 = ["openid", "email", "profile"]

  supported_identity_providers = ["COGNITO"]

  #  Activate token revocation
  enable_token_revocation = true

  # Configure the token validity period
  access_token_validity  = 8 # 1 hour
  id_token_validity      = 8 # 1 hour
  refresh_token_validity = 7 # 7 days
  token_validity_units {
    access_token  = "hours"
    id_token      = "hours"
    refresh_token = "days"
  }

  read_attributes  = ["email", "name"]
  write_attributes = ["email", "name"]

}

resource "aws_cognito_user" "admin_user" {
  user_pool_id = aws_cognito_user_pool.user_pool.id
  username     = var.admin_email

  attributes = {
    email          = var.admin_email
    email_verified = true
  }
}
