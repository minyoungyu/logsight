variable "region" {
  description = "대회 리전. ctf_server 프로젝트는 시드니로 고정돼 있다."
  type        = string
  default     = "ap-southeast-2"
}

variable "name" {
  description = "자원 이름 접두사"
  type        = string
  default     = "ctf"
}

variable "team_count" {
  description = "팀 수(2인 1팀). 팀마다 서버 1대, ALB 포트 1개(8000+팀 번호)."
  type        = number
  default     = 10
  validation {
    condition     = var.team_count >= 1 && var.team_count <= 20
    error_message = "team_count는 1~20."
  }
}

variable "operator_cidrs" {
  description = "운영진 공인 IP 목록(예: [\"203.0.113.5/32\"]). 대회 전후에는 이 IP만 ALB·CTFd에 닿는다."
  type        = list(string)
  validation {
    condition     = length(var.operator_cidrs) > 0 && !contains(var.operator_cidrs, "0.0.0.0/0")
    error_message = "운영진 IP를 /32로 넣는다. 0.0.0.0/0은 contest_open으로만 연다."
  }
}

variable "contest_open" {
  description = "true면 ALB 팀 포트와 CTFd를 0.0.0.0/0에 연다. 대회 10:00에 true로 apply, 19:00에 false로 apply."
  type        = bool
  default     = false
}

variable "team_instance_type" {
  type    = string
  default = "t3.small"
}

variable "ctfd_instance_type" {
  description = "점수판. t3.small(2GB)+스왑 1GB. 리허설에서 메모리가 빠듯하면 t3.medium."
  type        = string
  default     = "t3.small"
}

variable "ctfd_image" {
  description = "CTFd 도커 이미지. 배포 전 최신 3.x 태그로 맞춘다."
  type        = string
  default     = "ctfd/ctfd:3.7.4"
}

variable "site_dir" {
  description = "대회용 문제 사이트 폴더(설계 밖 취약점을 제거한 shopmall CTF 버전). 서버가 부팅 때 S3에서 받아 /var/www/shop에 푼다."
  type        = string
  default     = "../site"
}

variable "f4_sudo_rule" {
  description = "F4용 sudo 규칙 1줄(웹 사용자 nginx). 설계자가 아닌 사람이 바꾼다. 3-3: 이 규칙 외 권한 상승 경로는 0개여야 한다."
  type        = string
  default     = "nginx ALL=(root) NOPASSWD: /usr/bin/find /var/www/shop/uploads *"
}
