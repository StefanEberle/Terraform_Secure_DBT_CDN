# Origin Access Identity für CloudFront
resource "aws_cloudfront_origin_access_identity" "dbt_docs_oai" {
  comment = "OAI for dbt docs static website"
}

# CloudFront Distribution
resource "aws_cloudfront_distribution" "dbt_docs_distribution" {
  enabled = true
  #is_ipv6_enabled     = true
  comment             = "Distribution for dbt docs"
  default_root_object = "index.html"

  origin {
    domain_name = module.s3_bucket_dbt_docs.s3_bucket_bucket_regional_domain_name
    origin_id   = local.s3_origin_id
    origin_path = "/dbt-docs"

    s3_origin_config {
      origin_access_identity = aws_cloudfront_origin_access_identity.dbt_docs_oai.cloudfront_access_identity_path
    }
  }

  default_cache_behavior {
    allowed_methods  = ["GET", "HEAD"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = local.s3_origin_id

    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }

    lambda_function_association {
      event_type   = "viewer-request"
      lambda_arn   = aws_lambda_function.edge.qualified_arn
      include_body = false
    }

    viewer_protocol_policy = "redirect-to-https"
    min_ttl                = 0
    default_ttl            = 0
    max_ttl                = 0
  }


  origin {
    domain_name = "www.example.de" # wird nicht verwendet
    origin_id   = "null-origin"
    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }
  }

  ordered_cache_behavior {
    path_pattern     = "*favicon*"
    allowed_methods  = ["GET", "HEAD"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "null-origin"

    forwarded_values {
      query_string = false
      headers      = []
      cookies {
        forward = "none"
      }
    }

    min_ttl                = 300
    default_ttl            = 300
    max_ttl                = 1200
    compress               = true
    viewer_protocol_policy = "redirect-to-https"

  }

  custom_error_response {
    error_code            = 404
    response_code         = 404
    response_page_path    = "/404.html"
    error_caching_min_ttl = 300
  }

  price_class = "PriceClass_100"

  restrictions {
    geo_restriction {
      restriction_type = "whitelist"
      locations        = ["DE"]
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
    minimum_protocol_version       = "TLSv1"
  }

  web_acl_id = aws_wafv2_web_acl.dbt_docs_waf.arn
}

# WAF IP Set
resource "aws_wafv2_ip_set" "allowed_ips" {
  provider           = aws.us-east-1
  name               = "${var.project_name}-allowed-ips"
  description        = "IP addresses allowed to access the CloudFront distribution"
  scope              = "CLOUDFRONT"
  ip_address_version = "IPV4"

  addresses = [
    var.ip_adresses_cidr # Your IP Adresses CIDR
  ]
  tags = {
    Name = "allowed-ips"
  }
}


# Datablock for the HTML content if the IP address is not on the whitelist
data "template_file" "restricted_access_html" {
  template = <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Access Restricted</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            background-color: #f0f0f0;
        }
        .container {
            text-align: center;
            padding: 20px;
            background-color: white;
            border-radius: 5px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h1 {
            color: #d9534f;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Access Restricted</h1>
        <p>This content is not accessible to you!</p>
    </div>
</body>
</html>
EOF
}

# WAF Web ACL
resource "aws_wafv2_web_acl" "dbt_docs_waf" {
  provider    = aws.us-east-1
  name        = "${var.project_name}-waf"
  description = "WAF for dbt docs CloudFront distribution"
  scope       = "CLOUDFRONT"

  custom_response_body {
    key          = "restricted"
    content      = data.template_file.restricted_access_html.rendered
    content_type = "TEXT_HTML"
  }

  default_action {
    block {
      custom_response {
        response_code            = 403
        custom_response_body_key = "restricted"
      }
    }
  }

  rule {
    name     = "allow-ips"
    priority = 1

    action {
      allow {}
    }

    statement {
      or_statement {
        statement {
          ip_set_reference_statement {
            arn = aws_wafv2_ip_set.allowed_ips.arn
          }
        }

        statement {
          byte_match_statement {
            positional_constraint = "EXACTLY"
            search_string         = "DE"
            field_to_match {
              single_header {
                name = "cloudfront-viewer-country"
              }
            }
            text_transformation {
              priority = 0
              type     = "NONE"
            }
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AllowedIPs"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "DBTDocsWAF"
    sampled_requests_enabled   = true
  }
}

