
output "cognito_login_url" {
  description = "The URL for the Cognito Hosted UI login page"
  value = format(
    "https://%s.auth.%s.amazoncognito.com/login?response_type=code&client_id=%s&redirect_uri=%s",
    aws_cognito_user_pool_domain.user_pool_domain.domain,
    var.aws_region,
    aws_cognito_user_pool_client.user_pool_client.id,
    urlencode("https://${aws_cloudfront_distribution.dbt_docs_distribution.domain_name}/")
  )
}


output "cognito_client_id" {
  value = aws_cognito_user_pool_client.user_pool_client.id
}


output "cloudfront_distribution_domain_name" {
  value       = aws_cloudfront_distribution.dbt_docs_distribution.domain_name
  description = "Die Domain der CloudFront-Distribution für den Zugriff auf die DBT Docs"
}