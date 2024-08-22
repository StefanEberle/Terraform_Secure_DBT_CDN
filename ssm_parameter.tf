resource "aws_ssm_parameter" "cognito_domain" {
  provider = aws.us-east-1
  name     = "/${var.project_name}/cognito-domain"
  type     = "String"
  value    = aws_cognito_user_pool_domain.user_pool_domain.domain
}

resource "aws_ssm_parameter" "cognito_client_id" {
  provider = aws.us-east-1
  name     = "/${var.project_name}/cognito-client-id"
  type     = "String"
  value    = aws_cognito_user_pool_client.user_pool_client.id
}

resource "aws_ssm_parameter" "cognito_client_secret" {
  provider = aws.us-east-1
  name     = "/${var.project_name}/cognito-client-secret"
  type     = "SecureString"
  value    = aws_cognito_user_pool_client.user_pool_client.client_secret
}

resource "aws_ssm_parameter" "cognito_user_pool_id" {
  provider = aws.us-east-1
  name     = "/${var.project_name}/cognito-user-pool-id"
  type     = "String"
  value    = aws_cognito_user_pool.user_pool.id
}

resource "aws_ssm_parameter" "cloudfront-url" {
  provider = aws.us-east-1
  name     = "/${var.project_name}/cloudfront-url"
  type     = "String"
  value    = aws_cloudfront_distribution.dbt_docs_distribution.domain_name
}
