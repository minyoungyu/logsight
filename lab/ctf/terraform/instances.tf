########################################
# 팀 서버 t01~t10 — 프라이빗 서브넷, 퍼블릭 IP 없음, 10.20.10.11~
########################################

resource "aws_instance" "team" {
  for_each               = local.teams
  ami                    = local.ami
  instance_type          = var.team_instance_type
  subnet_id              = aws_subnet.teams.id
  private_ip             = "10.20.10.${10 + each.value}"
  vpc_security_group_ids = [aws_security_group.team.id]
  iam_instance_profile   = aws_iam_instance_profile.team[each.key].name

  credit_specification {
    cpu_credits = "unlimited" # 크레딧 소진으로 느려지지 않게(초과분 최악 약 $7, 3-2)
  }

  # F5: IMDSv1 허용(설정 실수 재현) — 이 대회 서버에서만. 태그는 메타데이터에 노출하지 않는다.
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "optional"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "disabled"
  }

  root_block_device {
    volume_type           = "gp3"
    volume_size           = 16
    delete_on_termination = true
  }

  # 플래그는 여기 넣지 않는다(메타데이터로 보인다). 팀 번호·버킷 이름·기본 인증 비밀번호만 있다.
  user_data = templatefile("${path.module}/templates/team_user_data.sh.tftpl", {
    team        = each.key
    region      = var.region
    ops_bucket  = aws_s3_bucket.b["ops"].id
    logs_bucket = aws_s3_bucket.b["logs"].id
    flag_bucket = aws_s3_bucket.b["flags"].id
    basic_pass  = random_password.basic[each.key].result
    sudo_rule   = var.f4_sudo_rule
  })
  user_data_replace_on_change = true

  tags = { Name = "${var.name}-${each.key}", Team = each.key }

  depends_on = [aws_vpc_endpoint.s3, aws_vpc_endpoint.ssm, aws_s3_object.site, aws_s3_object.shipper, aws_route_table_association.teams]
}

########################################
# 점수판 CTFd — 퍼블릭 서브넷, 팀 서버와 다른 보안그룹
########################################

resource "aws_instance" "ctfd" {
  ami                         = local.ami
  instance_type               = var.ctfd_instance_type
  subnet_id                   = aws_subnet.public[0].id
  associate_public_ip_address = true
  vpc_security_group_ids      = [aws_security_group.ctfd.id]

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  root_block_device {
    volume_type = "gp3"
    volume_size = 20
  }

  user_data = templatefile("${path.module}/templates/ctfd_user_data.sh.tftpl", {
    ctfd_image = var.ctfd_image
  })

  tags = { Name = "${var.name}-ctfd" }
}
