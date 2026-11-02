# LogSight AWS 실습 랩 — 입력 변수
# 이 구성은 "내가 소유한 분리된 샌드박스 계정"에만 올린다. 실제 서비스 계정에 올리지 않는다.

variable "region" {
  description = "실습 리전"
  type        = string
  default     = "ap-northeast-2"
}

variable "name" {
  description = "자원 이름 접두사"
  type        = string
  default     = "logsight-lab"
}

variable "allowed_ip" {
  description = <<-EOT
    EC2 22/80 포트에 접근할 수 있는 CIDR. 공격 재현을 하는 본인 PC의 공인 IP 하나만 넣는다(예: "203.0.113.5/32").
    curl -s https://checkip.amazonaws.com 로 확인한다. 0.0.0.0/0 은 넣지 않는다 — 랩이라도 전 세계에 열면 안 된다.
  EOT
  type        = string

  validation {
    condition     = var.allowed_ip != "0.0.0.0/0"
    error_message = "allowed_ip 에 0.0.0.0/0 은 쓸 수 없다. 본인 공인 IP/32 를 넣어라."
  }
}

variable "instance_type" {
  description = "EC2 인스턴스 타입(프리티어 t3.micro)"
  type        = string
  default     = "t3.micro"
}

variable "repo_url" {
  description = "취약 테스트 사이트를 받을 저장소(부팅 시 clone). 공개 저장소여야 한다."
  type        = string
  default     = "https://github.com/minyoungyu/logsight.git"
}

variable "repo_ref" {
  description = "clone 할 브랜치/태그"
  type        = string
  default     = "main"
}

variable "key_name" {
  description = <<-EOT
    nginx·auth 로그를 scp 로 받기 위한 기존 EC2 키페어 이름.
    먼저 콘솔(EC2 > 키페어) 또는 `aws ec2 create-key-pair` 로 만들고 .pem 을 본인 PC에 둔다.
    로그 수집이 필요 없으면 빈 문자열("")로 두면 키 없이 만든다.
  EOT
  type        = string
  default     = ""
}
