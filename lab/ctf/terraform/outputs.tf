output "alb_dns" {
  description = "참가자 접속 주소: http://<alb_dns>:80NN (팀 tNN)"
  value       = aws_lb.ctf.dns_name
}

output "team_urls" {
  value = { for t, i in local.teams : t => "http://${aws_lb.ctf.dns_name}:${8000 + i}/" }
}

output "ctfd_url" {
  value = "http://${aws_instance.ctfd.public_ip}/"
}

output "team_instances" {
  description = "팀 ↔ 인스턴스 ID ↔ 역할 대응표(정답지 ground_truth용)"
  value = { for t, i in local.teams : t => {
    instance_id = aws_instance.team[t].id
    private_ip  = aws_instance.team[t].private_ip
    role_name   = aws_iam_role.team[t].name
  } }
  sensitive = true # 역할 이름 = F5 정답
}

output "buckets" {
  value = { for k, b in aws_s3_bucket.b : k => b.id }
}

output "basic_auth" {
  description = "팀 포트 기본 인증(아이디 = 팀 번호). 대회 시작 때 팀에게만 배부."
  value       = { for t in keys(local.teams) : t => random_password.basic[t].result }
  sensitive   = true
}

output "flags" {
  description = "팀별 정답. CTFd 등록과 inject_flags.sh가 쓴다. 화면 공유 금지."
  value = { for t in keys(local.teams) : t => {
    f1      = "LS{${random_id.flag["${t}-f1"].hex}}"
    f1_path = random_id.f1_path[t].hex
    f2      = "LS{${random_id.flag["${t}-f2"].hex}}"
    f3      = "LS{${random_id.flag["${t}-f3"].hex}}"
    f4      = "LS{${random_id.flag["${t}-f4"].hex}}"
    f5      = aws_iam_role.team[t].name
    f6      = "LS{${random_id.flag["${t}-f6"].hex}}"
  } }
  sensitive = true
}

output "region" {
  value = var.region
}
