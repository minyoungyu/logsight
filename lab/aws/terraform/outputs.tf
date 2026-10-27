output "web_url" {
  description = "취약 테스트 사이트 주소(본인 IP에서만 열림)"
  value       = "http://${aws_instance.web.public_ip}/"
}

output "web_public_ip" {
  value = aws_instance.web.public_ip
}

output "instance_id" {
  value = aws_instance.web.id
}

output "iam_role_name" {
  description = "EC2 에 붙은 역할 — CloudTrail 의 assumed-role 세션명에 인스턴스 ID가 붙어 연결고리가 된다"
  value       = aws_iam_role.ec2_app.name
}

output "sensitive_bucket" {
  description = "공격 재현에서 탈취 키로 읽을 대상 버킷(가짜 데이터)"
  value       = aws_s3_bucket.sensitive.id
}

output "logs_bucket" {
  description = "CloudTrail·VPC Flow Logs 가 쌓이는 버킷 — collect.sh 로 여기서 받는다"
  value       = aws_s3_bucket.logs.id
}

output "region" {
  value = var.region
}

output "collect_hint" {
  description = "로그 수집 명령"
  value       = "bash lab/aws/collect.sh ${aws_s3_bucket.logs.id} ${var.region} ${aws_instance.web.public_ip}"
}
