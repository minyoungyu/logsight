# LogSight CTF 대회 인프라 (시드니 ap-southeast-2, 2인 1팀 10팀, 9시간)
# 설계: "LogSight 검증용 CTF 형식안" 3장, 3-3장. 대회 전용 계정(ctf_server 프로젝트)에만 올린다.
# 상태 파일(terraform.tfstate)에는 플래그 값이 들어 있다. 저장소에 올리지 않는다(.gitignore).

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
  }
}

provider "aws" {
  region = var.region
  default_tags {
    tags = {
      Project   = "LogSight"
      Purpose   = "ctf-log-collection"
      Lifecycle = "ephemeral"
    }
  }
}

data "aws_caller_identity" "me" {}
data "aws_partition" "cur" {}
data "aws_availability_zones" "az" {
  state = "available"
}

# Amazon Linux 2023: 리전 S3에 있는 패키지 저장소를 쓰므로, 인터넷 없는 팀 서버도 S3 게이트웨이 엔드포인트로 dnf 설치가 된다.
# (Ubuntu는 저장소가 S3 밖이라 이미지를 따로 구워야 한다. 그래서 AL2023으로 바꿨다.)
data "aws_ssm_parameter" "al2023" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
}

locals {
  account = data.aws_caller_identity.me.account_id
  suffix  = random_id.suffix.hex
  azs     = slice(data.aws_availability_zones.az.names, 0, 2)
  teams   = { for i in range(1, var.team_count + 1) : format("t%02d", i) => i }
  ami     = nonsensitive(data.aws_ssm_parameter.al2023.value)
  open    = var.contest_open ? ["0.0.0.0/0"] : var.operator_cidrs
}

resource "random_id" "suffix" {
  byte_length = 3
}
