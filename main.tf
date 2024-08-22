terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }

/* 
The Docker provider in Terraform is used to manage resources within a Docker environment. 
With this provider, you can create, update and manage Docker containers, images, volumes, 
networks and other resources as part of your Terraform configuration. In the specific case of our 
configuration, the Docker provider is configured to authenticate with a Docker registry 
(here AWS ECR, Elastic Container Registry) to retrieve private Docker images for use in container deployments 
*/

    docker = {
      source  = "kreuzwerker/docker"
      version = "3.0.2"
    }
  }
  required_version = "~> 1.7.0"                       # Specifies the minimum required Terraform version for this configuration
  backend "s3" {
    bucket  = ""                                      # S3 bucket for storing Terraform state files
    key     = "state/terraform.tfstate"               # Path within the S3 bucket for the state file
    region  = "eu-central-1"
    profile = ""                                      # AWS CLI profile to access the S3 bucket
  }
}

provider "aws" {
  alias   = "us-east-1"
  region  = "us-east-1"
  profile = ""
}