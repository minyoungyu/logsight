########################################
# S3 버킷 4개: 로그, WAF 로그, 플래그, 운영(사이트 파일)
########################################

locals {
  buckets = {
    logs  = "${var.name}-logs-${local.account}-${local.suffix}"
    waf   = "aws-waf-logs-${var.name}-${local.suffix}" # WAF 규칙: 이름이 aws-waf-logs-로 시작
    flags = "${var.name}-flags-${local.suffix}"
    ops   = "${var.name}-ops-${local.suffix}"
  }
}

resource "aws_s3_bucket" "b" {
  for_each      = local.buckets
  bucket        = each.value
  force_destroy = each.key != "logs" # 로그 버킷은 destroy로 지워지지 않게(수집 후 따로 지운다)
}

resource "aws_s3_bucket_public_access_block" "b" {
  for_each                = aws_s3_bucket.b
  bucket                  = each.value.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "b" {
  for_each = aws_s3_bucket.b
  bucket   = each.value.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

# 로그 버킷: 버전 관리 — root를 얻은 참가자가 로그를 덮어써도 원본이 남는다
resource "aws_s3_bucket_versioning" "logs" {
  bucket = aws_s3_bucket.b["logs"].id
  versioning_configuration {
    status = "Enabled"
  }
}

data "aws_elb_service_account" "here" {}

data "aws_iam_policy_document" "logs" {
  statement {
    sid       = "CloudTrailAcl"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.b["logs"].arn]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com", "delivery.logs.amazonaws.com"]
    }
  }
  statement {
    sid       = "CloudTrailWrite"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.b["logs"].arn}/cloudtrail/AWSLogs/${local.account}/*"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }
  statement {
    sid       = "FlowLogsWrite"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.b["logs"].arn}/vpcflow/AWSLogs/${local.account}/*"]
    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }
  }
  # ALB 접속 로그: 리전별 ELB 계정(시드니 783225319266)을 데이터 소스로 받는다. 하드코딩하지 않는다.
  statement {
    sid       = "AlbWrite"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.b["logs"].arn}/alb/AWSLogs/${local.account}/*"]
    principals {
      type        = "AWS"
      identifiers = [data.aws_elb_service_account.here.arn]
    }
  }
  # 운영진 외에는 삭제·정책 변경·버전 관리 끄기 거부(팀 역할 키가 새도 증거가 남는다)
  statement {
    sid    = "ProtectEvidence"
    effect = "Deny"
    actions = [
      "s3:DeleteObject", "s3:DeleteObjectVersion", "s3:PutBucketPolicy",
      "s3:DeleteBucketPolicy", "s3:PutBucketVersioning", "s3:PutLifecycleConfiguration",
    ]
    resources = [aws_s3_bucket.b["logs"].arn, "${aws_s3_bucket.b["logs"].arn}/*"]
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    condition {
      test     = "ArnLike"
      variable = "aws:PrincipalArn"
      values   = ["arn:${data.aws_partition.cur.partition}:iam::${local.account}:role/${var.name}-t*"]
    }
  }
}

resource "aws_s3_bucket_policy" "logs" {
  bucket     = aws_s3_bucket.b["logs"].id
  policy     = data.aws_iam_policy_document.logs.json
  depends_on = [aws_s3_bucket_public_access_block.b]
}

data "aws_iam_policy_document" "waf" {
  statement {
    sid       = "WafAcl"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.b["waf"].arn]
    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }
  }
  statement {
    sid       = "WafWrite"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.b["waf"].arn}/AWSLogs/${local.account}/*"]
    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account]
    }
  }
}

resource "aws_s3_bucket_policy" "waf" {
  bucket     = aws_s3_bucket.b["waf"].id
  policy     = data.aws_iam_policy_document.waf.json
  depends_on = [aws_s3_bucket_public_access_block.b]
}

# 플래그 버킷: F6는 VPC 엔드포인트를 지나온 읽기를 거부 → 웹셸에서 서버 역할로 바로 읽는 지름길을 막는다(3-3)
data "aws_iam_policy_document" "flags" {
  statement {
    sid       = "F6OnlyFromOutside"
    effect    = "Deny"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.b["flags"].arn}/*"]
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceVpce"
      values   = [aws_vpc_endpoint.s3.id]
    }
  }
}

resource "aws_s3_bucket_policy" "flags" {
  bucket     = aws_s3_bucket.b["flags"].id
  policy     = data.aws_iam_policy_document.flags.json
  depends_on = [aws_s3_bucket_public_access_block.b]
}

# F6 객체: tNN/flag6.txt. 단서(버킷 이름·리전)는 서버의 /etc/ctf/app.ini에 둔다(F3 이후 보인다).
resource "aws_s3_object" "f6" {
  for_each = local.teams
  bucket   = aws_s3_bucket.b["flags"].id
  key      = "${each.key}/flag6.txt"
  content  = "LS{${random_id.flag["${each.key}-f6"].hex}}\n"
}

# 문제 사이트: 팀 서버가 부팅 때 S3 게이트웨이로 받는다(서버에 인터넷이 없다)
data "archive_file" "site" {
  type        = "zip"
  source_dir  = "${path.module}/${var.site_dir}"
  output_path = "${path.module}/.build/site.zip"
}

resource "aws_s3_object" "site" {
  bucket = aws_s3_bucket.b["ops"].id
  key    = "site/site.zip"
  source = data.archive_file.site.output_path
  etag   = data.archive_file.site.output_md5
}

resource "aws_s3_object" "shipper" {
  bucket = aws_s3_bucket.b["ops"].id
  key    = "site/ship-logs.sh"
  source = "${path.module}/templates/ship-logs.sh"
  etag   = filemd5("${path.module}/templates/ship-logs.sh")
}
