#####################################################################
#                  AWS Account Informations                         #
#####################################################################

data "aws_caller_identity" "current" {}

locals {
  account_id       = data.aws_caller_identity.current.account_id
  account_username = split("/", data.aws_caller_identity.current.arn)[1]
}


locals {
  dbt_docs_s3_bucket_name = ""
  s3_origin_id            = ""
}