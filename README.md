# Secure DBT Documentation Deployment with AWS and Terraform

## Project Title and Description

This Terraform project implements a secure infrastructure for deploying dbt documentation via Amazon CloudFront with Cognito authentication and Lambda@Edge. It provides a robust, scalable, and secure solution for companies wanting to make their dbt documentation accessible internally or to selected external users.

## Architecture Overview

```
                   ┌─────────────┐
                   │             │
                   │    User     │
                   │             │
                   └───────┬─────┘
                           │
                           ▼
               ┌───────────────────────┐
               │                       │
               │   Amazon CloudFront   │
               │                       │
               └───────────┬───────────┘
                           │
                           ▼
               ┌───────────────────────┐
               │                       │
               │     Lambda@Edge       │
               │                       │
               └───────────┬───────────┘
                           │
                 ┌─────────┴─────────┐
                 │                   │
        ┌────────▼─────────┐  ┌──────▼───────┐
        │                  │  │              │
        │  Amazon Cognito  │  │  Amazon S3   │
        │                  │  │              │
        └──────────────────┘  └──────────────┘
```

Main components:
- **S3**: Stores the dbt documentation files.
- **CloudFront**: Distributes content globally and securely.
- **Cognito**: Manages user authentication and authorization.
- **Lambda@Edge**: Implements custom authentication and authorization logic.
- **WAF**: Protects against web-based attacks.

## Prerequisites

- AWS account with appropriate permissions
- Terraform (Version ~> 1.7.0)
- Docker
- AWS CLI configured with appropriate profile
- dbt documentation ready for deployment

## Setup and Deployment

### 1. Configuring Terraform Variables

Edit the `variables.tf` file and adjust the values to your requirements:

```hcl
# Configure other variables as needed
variable "project_name" {
  type    = string
  default = "my_dbt_docs_cdn_project"
}

variable "aws_region" {
  type    = string
  default = "eu-central-1"
}

variable "cognito_user_pool_domain_name" {
  type    = string
  default = "my-dbt-docs-domain"
}

variable "cognito_user_pool_client_name" {
  type    = string
  default = "my-dbt-docs-client"
}

variable "cognito_user_pool_name" {
  type    = string
  default = "my-dbt-docs-user-pool"
}

variable "ip_adresses_cidr" {
  type    = string
  default = "10.0.0.0/8"  # Adjust this to your allowed IP range
}

variable "lambda_edge_role_name" {
  type    = string
  default = "dbt-docs-lambda-edge-role"
}

variable "lambda_edge_policy_name" {
  type    = string
  default = "dbt-docs-lambda-edge-policy"
}
```

### 2. AWS Provider Configuration

Add your Terraform provider profile in `main.tf`:

```hcl
provider "aws" {
  region  = var.aws_region
  profile = "your-aws-profile"
}
```

### 3. S3 Bucket Creation

Create an S3 bucket for your dbt documentation:

```bash
aws s3 mb s3://your-dbt-docs-bucket-name --region your-region
```

or in der AWS Console

### 4. Lambda@Edge Configuration

In the `auth.py` file, replace `YOUR_PROJECT_NAME_HERE` with the default value of `var.project_name`:

```python
SSM_COGNITO_DOMAIN: str = f"/YOUR_PROJECT_NAME_HERE/cognito-domain"
SSM_CLIENT_ID: str = f"/YOUR_PROJECT_NAME_HERE/cognito-client-id"
SSM_CLIENT_SECRET: str = f"/YOUR_PROJECT_NAME_HERE/cognito-client-secret"
SSM_USER_POOL_ID: str = f"/YOUR_PROJECT_NAME_HERE/cognito-user-pool-id"
SSM_CLOUDFRONT_URL: str = f"/YOUR_PROJECT_NAME_HERE/cloudfront-url"
```

### 5. Initialize and Apply Terraform

Ensure Docker is running, then:

```bash
terraform init
terraform plan
terraform apply
```

### 6. Upload dbt Documentation

After the infrastructure is created, upload your dbt documentation to the S3 bucket:

```bash
aws s3 cp ./dbt-docs s3://your-dbt-docs-bucket-name/dbt-docs --recursive
```

Ensure you upload the following files:
- index.html
- catalog.json
- manifest.json
- sources.json

or in der AWS Console

### 7. Destroy Infrastructure

When you need to tear down the infrastructure:

1. Empty the DBT Docs S3 bucket:
```bash
aws s3 rm s3://your-dbt-docs-bucket-name --recursive
```

2. Run Terraform destroy (you may need to run it twice due to Lambda@Edge):
```bash
terraform destroy
```

Note: We're investigating the Lambda@Edge deletion issue and will provide an update in future versions.

## Authentication Flow

1. User accesses the CloudFront URL.
2. Lambda@Edge checks for authentication.
3. If not authenticated, redirect to Cognito login page.
4. After successful login, Cognito generates an authorization code.
5. Lambda@Edge exchanges the code for tokens and sets cookies.
6. User is redirected to the original URL and gains access.

## Security Aspects

- **WAF**: Configured with IP whitelist and geographic restrictions.
- **Cognito**: Implements secure user authentication.
- **Lambda@Edge**: Performs token validation and renewal.
- **S3**: Bucket policies restrict access to CloudFront only.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

## Future Improvements

- Split the Lambda@Edge function into multiple functions for better separation of concerns and easier maintenance.
- Introduction of a templating mechanism is planned. This will allow Terraform outputs to be seamlessly integrated into Python scripts, 
  resulting in more dynamic and flexible configuration management.

