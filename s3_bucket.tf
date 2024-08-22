#####################################################################
#                          DBT DOCS                                 #
#####################################################################
module "s3_bucket_dbt_docs" {
  source  = "terraform-aws-modules/s3-bucket/aws"
  version = "~> 3.0"

  bucket = local.dbt_docs_s3_bucket_name

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true

  server_side_encryption_configuration = {
    rule = {
      apply_server_side_encryption_by_default = {
        sse_algorithm = "AES256"
      }
    }
  }

  versioning = {
    enabled = true
  }

  control_object_ownership = true
  object_ownership         = "BucketOwnerPreferred"

  cors_rule = [
    {
      allowed_headers = ["*"]
      allowed_methods = ["GET", "HEAD"]
      allowed_origins = ["*"]
      expose_headers  = ["ETag"]
      max_age_seconds = 3000
    }
  ]

}

data "aws_iam_policy_document" "s3_policy" {
  statement {
    sid    = "AllowCloudFrontOAI"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = [aws_cloudfront_origin_access_identity.dbt_docs_oai.iam_arn]
    }
    actions   = ["s3:GetObject"]
    resources = ["${module.s3_bucket_dbt_docs.s3_bucket_arn}/*"]
  }
}

resource "aws_s3_bucket_policy" "dbt_docs" {
  bucket = module.s3_bucket_dbt_docs.s3_bucket_id
  policy = data.aws_iam_policy_document.s3_policy.json
}

