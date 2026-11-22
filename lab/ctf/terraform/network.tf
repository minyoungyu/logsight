########################################
# VPC 10.20.0.0/16 — 기본 VPC를 쓰지 않아 Flow 로그에 다른 자원이 섞이지 않는다
########################################

resource "aws_vpc" "ctf" {
  cidr_block           = "10.20.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = "${var.name}-vpc" }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.ctf.id
}

# 퍼블릭 서브넷 2개(ALB는 AZ 2개 필요) — ALB, CTFd
resource "aws_subnet" "public" {
  count                   = 2
  vpc_id                  = aws_vpc.ctf.id
  cidr_block              = "10.20.${count.index}.0/24"
  availability_zone       = local.azs[count.index]
  map_public_ip_on_launch = false
  tags                    = { Name = "${var.name}-public-${count.index}" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.ctf.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }
  tags = { Name = "${var.name}-public" }
}

resource "aws_route_table_association" "public" {
  count          = 2
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# 프라이빗 서브넷 — 팀 서버. 인터넷 경로 없음(NAT 없음). VPC 내부 + S3 게이트웨이 엔드포인트뿐.
resource "aws_subnet" "teams" {
  vpc_id            = aws_vpc.ctf.id
  cidr_block        = "10.20.10.0/24"
  availability_zone = local.azs[0]
  tags              = { Name = "${var.name}-teams" }
}

resource "aws_route_table" "teams" {
  vpc_id = aws_vpc.ctf.id
  tags   = { Name = "${var.name}-teams-no-internet" }
}

resource "aws_route_table_association" "teams" {
  subnet_id      = aws_subnet.teams.id
  route_table_id = aws_route_table.teams.id
}

# S3 게이트웨이 엔드포인트(무료): dnf 패키지(AL2023 저장소), 사이트 파일, 로그 전송, 플래그 버킷.
# 플래그 버킷은 이 엔드포인트를 지나온 F6 읽기를 거부한다(s3.tf) → 탈취한 키를 밖에서 써야만 풀린다.
resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.ctf.id
  service_name      = "com.amazonaws.${var.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.teams.id]
  tags              = { Name = "${var.name}-s3" }
}

# SSM 인터페이스 엔드포인트 3개(팀 서버 AZ 1곳) — 플래그를 user-data가 아닌 SSM으로 넣기 위해
resource "aws_security_group" "endpoints" {
  name        = "${var.name}-endpoints"
  description = "SSM interface endpoints, 443 from team servers"
  vpc_id      = aws_vpc.ctf.id
  ingress {
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.team.id]
  }
}

resource "aws_vpc_endpoint" "ssm" {
  for_each            = toset(["ssm", "ssmmessages", "ec2messages"])
  vpc_id              = aws_vpc.ctf.id
  service_name        = "com.amazonaws.${var.region}.${each.key}"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.teams.id]
  security_group_ids  = [aws_security_group.endpoints.id]
  private_dns_enabled = true
  tags                = { Name = "${var.name}-${each.key}" }
}

data "aws_ec2_managed_prefix_list" "s3" {
  name = "com.amazonaws.${var.region}.s3"
}

########################################
# 보안그룹
########################################

resource "aws_security_group" "alb" {
  name        = "${var.name}-alb"
  description = "CTF ALB team ports"
  vpc_id      = aws_vpc.ctf.id
  ingress {
    description = "team ports (contest_open=true -> everyone, else operators)"
    from_port   = 8001
    to_port     = 8000 + var.team_count
    protocol    = "tcp"
    cidr_blocks = local.open
  }
  egress {
    description = "to team servers"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [aws_subnet.teams.cidr_block]
  }
}

# 팀 서버 공용 보안그룹: 80은 ALB에서만. 팀 서버끼리 받는 규칙이 없어 서로 닿지 않는다.
resource "aws_security_group" "team" {
  name        = "${var.name}-team"
  description = "CTF team servers"
  vpc_id      = aws_vpc.ctf.id
  ingress {
    description     = "http from ALB only"
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }
  egress {
    description     = "S3 via gateway endpoint"
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    prefix_list_ids = [data.aws_ec2_managed_prefix_list.s3.id]
  }
  egress {
    description = "SSM interface endpoints"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [aws_subnet.teams.cidr_block]
  }
}

resource "aws_security_group" "ctfd" {
  name        = "${var.name}-ctfd"
  description = "CTFd scoreboard"
  vpc_id      = aws_vpc.ctf.id
  ingress {
    description = "scoreboard http"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = local.open
  }
  egress {
    description = "package and image download"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
