# LogSight AWS 실습 랩 — 정답을 아는 공격 로그를 만들기 위한 최소 구성.
# "로그 분석·침해 판단 도구"의 독립 측정용 데이터를 만드는 방어(블루팀) 목적의 샌드박스다.
# 올리는 것: VPC(기본), EC2 1대(nginx + 취약 테스트 사이트), S3 2개(가짜 민감데이터 + 로그),
#           EC2에 붙는 S3 읽기 IAM 역할, CloudTrail(관리+S3 데이터 이벤트), VPC Flow Logs.
# 끝나면 `terraform destroy` 한 줄로 전부 지운다.

terraform {
  required_version = ">= 1.3"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.region
  default_tags {
    tags = {
      Project   = "LogSight"
      Purpose   = "security-log-lab"
      Lifecycle = "ephemeral"
    }
  }
}

data "aws_caller_identity" "me" {}
data "aws_region" "current" {}

# 기본 VPC/서브넷을 쓴다(실습이라 새 VPC를 만들지 않는다).
data "aws_vpc" "default" {
  default = true
}

data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}

# Ubuntu 22.04 LTS (Canonical 공식)
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"]
  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }
}

locals {
  suffix = random_id.suffix.hex
}

resource "random_id" "suffix" {
  byte_length = 3
}

########################################
# S3 — 가짜 민감데이터 버킷 + 로그 버킷
########################################

resource "aws_s3_bucket" "sensitive" {
  bucket        = "${var.name}-sensitive-${local.suffix}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "sensitive" {
  bucket                  = aws_s3_bucket.sensitive.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# 공격자가 "탈취한 역할 키로 읽어 가는" 대상. 진짜 개인정보가 아닌 가짜 데이터만 넣는다.
resource "aws_s3_object" "fake_secret" {
  bucket  = aws_s3_bucket.sensitive.id
  key     = "customers/export.csv"
  content = "id,name,email,note\n1,홍길동(가짜),fake1@example.com,synthetic\n2,김철수(가짜),fake2@example.com,synthetic\n"
}

resource "aws_s3_bucket" "logs" {
  bucket        = "${var.name}-logs-${local.suffix}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket                  = aws_s3_bucket.logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# CloudTrail 과 VPC Flow Logs 가 이 버킷에 쓰도록 허용하는 정책.
data "aws_iam_policy_document" "logs_bucket" {
  statement {
    sid     = "CloudTrailAclCheck"
    actions = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.logs.arn]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }
  statement {
    sid       = "CloudTrailWrite"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.logs.arn}/cloudtrail/AWSLogs/${data.aws_caller_identity.me.account_id}/*"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }
  statement {
    sid     = "AWSLogDeliveryAclCheck"
    actions = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.logs.arn]
    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }
  }
  statement {
    sid       = "AWSLogDeliveryWrite"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.logs.arn}/vpcflow/AWSLogs/${data.aws_caller_identity.me.account_id}/*"]
    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }
}

resource "aws_s3_bucket_policy" "logs" {
  bucket = aws_s3_bucket.logs.id
  policy = data.aws_iam_policy_document.logs_bucket.json
}

########################################
# IAM — EC2 에 붙는 "S3 읽기" 역할(연결고리의 핵심)
########################################

data "aws_iam_policy_document" "ec2_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "ec2_app" {
  name               = "${var.name}-ec2-app-${local.suffix}"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume.json
}

# 의도한 권한은 민감 버킷 읽기뿐이다. (공격자가 이 역할 키를 훔쳐 S3 를 읽는 흐름을 재현한다)
data "aws_iam_policy_document" "ec2_app" {
  statement {
    actions   = ["s3:GetObject", "s3:ListBucket"]
    resources = [aws_s3_bucket.sensitive.arn, "${aws_s3_bucket.sensitive.arn}/*"]
  }
}

resource "aws_iam_role_policy" "ec2_app" {
  name   = "s3-read"
  role   = aws_iam_role.ec2_app.id
  policy = data.aws_iam_policy_document.ec2_app.json
}

resource "aws_iam_instance_profile" "ec2_app" {
  name = "${var.name}-ec2-app-${local.suffix}"
  role = aws_iam_role.ec2_app.name
}

########################################
# 보안그룹 — 22/80 을 본인 IP 에만 연다
########################################

resource "aws_security_group" "web" {
  name        = "${var.name}-web-${local.suffix}"
  description = "LogSight lab web/ssh, limited to one IP"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    description = "ssh from me"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.allowed_ip]
  }
  ingress {
    description = "http from me"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [var.allowed_ip]
  }
  egress {
    description = "all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

########################################
# EC2 — nginx + 취약 테스트 사이트
########################################

# IMDSv1 을 켠 상태(http_tokens=optional)로 둔다.
# 이는 "SSRF 등으로 인스턴스 역할 임시 키를 꺼내 가는" 실제 설정 실수를 재현하기 위한 것이며,
# 샌드박스에서만 한다. 실제 서버는 http_tokens=required(IMDSv2 강제) 로 둬야 한다.
resource "aws_instance" "web" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.instance_type
  subnet_id              = data.aws_subnets.default.ids[0]
  vpc_security_group_ids = [aws_security_group.web.id]
  iam_instance_profile   = aws_iam_instance_profile.ec2_app.name
  key_name               = var.key_name != "" ? var.key_name : null

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "optional" # 샌드박스 전용 — 실제 서버는 required
  }

  user_data = templatefile("${path.module}/user_data.sh.tftpl", {
    repo_url = var.repo_url
    repo_ref = var.repo_ref
  })

  tags = { Name = "${var.name}-web" }
}

########################################
# CloudTrail — 관리 이벤트 + 민감 버킷 S3 데이터 이벤트
########################################

resource "aws_cloudtrail" "main" {
  name                          = "${var.name}-trail-${local.suffix}"
  s3_bucket_name                = aws_s3_bucket.logs.id
  s3_key_prefix                 = "cloudtrail"
  include_global_service_events = true
  is_multi_region_trail         = false
  enable_log_file_validation    = true
  depends_on                    = [aws_s3_bucket_policy.logs]

  # S3 객체 단위 읽기(GetObject)를 기록해야 "탈취 키로 민감데이터를 읽었다"가 로그에 남는다.
  event_selector {
    read_write_type           = "All"
    include_management_events = true
    data_resource {
      type   = "AWS::S3::Object"
      values = ["${aws_s3_bucket.sensitive.arn}/"]
    }
  }
}

########################################
# VPC Flow Logs — 기본 VPC → 로그 버킷
########################################

resource "aws_flow_log" "vpc" {
  log_destination      = "${aws_s3_bucket.logs.arn}/vpcflow"
  log_destination_type = "s3"
  traffic_type         = "ALL"
  vpc_id               = data.aws_vpc.default.id
  depends_on           = [aws_s3_bucket_policy.logs]
}
