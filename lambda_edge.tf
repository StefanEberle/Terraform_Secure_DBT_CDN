resource "aws_lambda_function" "edge" {
  depends_on = [null_resource.docker_package_lambda_function]

  provider         = aws.us-east-1
  filename         = data.archive_file.lambda_edge.output_path
  function_name    = var.dbt_docs_lambda_edge_name
  role             = aws_iam_role.lambda_edge_exec.arn
  handler          = "auth.lambda_handler"
  runtime          = "python3.10"
  publish          = true
  source_code_hash = data.archive_file.lambda_edge.output_base64sha256
}

resource "null_resource" "docker_package_lambda_function" {
  triggers = {
    requirements = filemd5("${path.module}/lambda_edge/requirements.txt")
    source_code  = filemd5("${path.module}/lambda_edge/auth.py")
    dockerfile   = filemd5("${path.module}/lambda_edge/Dockerfile")
  }

  provisioner "local-exec" {
    command     = <<EOT
      cd ${path.module}/lambda_edge && \
      docker build -t lambda-packager . && \
      docker create --name lambda-package-container lambda-packager && \
      docker cp lambda-package-container:/asset/. ${path.module}/lambda_edge_package_docker && \
      docker rm lambda-package-container && \
      cd ${path.module}/lambda_edge_package_docker && zip -r ../lambda_edge_function_docker.zip .
    EOT
    interpreter = ["bash", "-c"]
  }
}

data "archive_file" "lambda_edge" {
  depends_on = [null_resource.docker_package_lambda_function]

  type        = "zip"
  source_dir  = "${path.module}/lambda_edge/lambda_edge_package_docker"
  output_path = "${path.module}/lambda_edge/lambda_edge_function_docker.zip"
}

resource "aws_iam_role" "lambda_edge_exec" {
  name = var.lambda_edge_role_name

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = [
            "lambda.amazonaws.com",
            "edgelambda.amazonaws.com"
          ]
        }
      }
    ]
  })
}
resource "aws_iam_role_policy" "lambda_edge_policy" {
  name = var.lambda_erge_policy_name
  role = aws_iam_role.lambda_edge_exec.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "cognito-idp:InitiateAuth",
          "cognito-idp:RespondToAuthChallenge"
        ]
        Resource = aws_cognito_user_pool.user_pool.arn
      },
      {
        Effect = "Allow"
        Action = [
          "ssm:GetParameter",
          "ssm:GetParameters",
          "ssm:GetParametersByPath"
        ]
        Resource = "arn:aws:ssm:us-east-1:${local.account_id}:parameter/${var.project_name}/*"
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:${var.aws_region}:${local.account_id}:log-group:/aws/lambda/us-east-1.${var.dbt_docs_lambda_edge_name}:*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_edge_basic" {
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
  role       = aws_iam_role.lambda_edge_exec.name
}

