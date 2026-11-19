########################################
# 플래그 값(팀마다 다름). 상태 파일에만 있다 — user-data·태그·이미지·저장소에 두지 않는다(3-3).
########################################

resource "random_id" "flag" {
  for_each    = toset(flatten([for t in keys(local.teams) : [for f in ["f1", "f2", "f3", "f4", "f5", "f6"] : "${t}-${f}"]]))
  byte_length = 8
}

# F1 숨은 경로 이름: 단서 없이는 못 맞히는 무작위 문자열
resource "random_id" "f1_path" {
  for_each    = local.teams
  byte_length = 6
}

# 팀 포트 기본 인증 비밀번호(대회 시작 때 팀에게 배부)
resource "random_password" "basic" {
  for_each = local.teams
  length   = 14
  special  = false
}

########################################
# 팀 역할 ctf-tNN-<F5>. 역할 이름 자체가 F5 정답이다: 메타데이터(IMDS)나 셸의 sts로만 보인다.
# 키가 탈취되면 CloudTrail에 assumed-role/ctf-tNN-…/i-… 로 남아 팀 서버와 AWS 로그를 잇는다.
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

data "aws_iam_policy_document" "team" {
  for_each = local.teams

  statement {
    sid       = "F6ReadOwnPrefix"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.b["flags"].arn}/${each.key}/*"]
  }
  statement {
    sid       = "F6ListOwnPrefix"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.b["flags"].arn]
    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values   = ["${each.key}/*", "${each.key}/"]
    }
  }
  statement {
    sid       = "ShipOwnLogs"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.b["logs"].arn}/hosts/${each.key}/*"]
  }
  statement {
    sid       = "BootSiteFiles"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.b["ops"].arn}/site/*"]
  }
  # SSM 에이전트가 쓰는 최소 권한(플래그 주입용). SendCommand 등 명령 실행 권한은 없다.
  statement {
    sid = "SsmAgent"
    actions = [
      "ssm:UpdateInstanceInformation", "ssm:ListInstanceAssociations", "ssm:UpdateInstanceAssociationStatus",
      "ssm:PutInventory", "ssm:GetDocument", "ssm:DescribeDocument",
      "ssmmessages:CreateControlChannel", "ssmmessages:CreateDataChannel",
      "ssmmessages:OpenControlChannel", "ssmmessages:OpenDataChannel",
      "ec2messages:AcknowledgeMessage", "ec2messages:DeleteMessage", "ec2messages:FailMessage",
      "ec2messages:GetEndpoint", "ec2messages:GetMessages", "ec2messages:SendReply",
    ]
    resources = ["*"]
  }
}

# 권한 경계: 위 정책 밖은 무엇을 붙여도 거부된다
resource "aws_iam_policy" "boundary" {
  name   = "${var.name}-team-boundary-${local.suffix}"
  policy = data.aws_iam_policy_document.boundary.json
}

data "aws_iam_policy_document" "boundary" {
  statement {
    actions = [
      "s3:GetObject", "s3:ListBucket", "s3:PutObject",
      "ssm:UpdateInstanceInformation", "ssm:ListInstanceAssociations", "ssm:UpdateInstanceAssociationStatus",
      "ssm:PutInventory", "ssm:GetDocument", "ssm:DescribeDocument",
      "ssmmessages:*", "ec2messages:*",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role" "team" {
  for_each             = local.teams
  name                 = "${var.name}-${each.key}-${random_id.flag["${each.key}-f5"].hex}"
  assume_role_policy   = data.aws_iam_policy_document.ec2_assume.json
  permissions_boundary = aws_iam_policy.boundary.arn
}

resource "aws_iam_role_policy" "team" {
  for_each = local.teams
  name     = "ctf-team"
  role     = aws_iam_role.team[each.key].id
  policy   = data.aws_iam_policy_document.team[each.key].json
}

resource "aws_iam_instance_profile" "team" {
  for_each = local.teams
  name     = "${var.name}-${each.key}-${local.suffix}"
  role     = aws_iam_role.team[each.key].name
}
