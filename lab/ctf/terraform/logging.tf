########################################
# CloudTrail — 단일 리전(무료 플랜은 다중 리전 기능 미지원). 관리 이벤트 + 플래그 버킷 데이터 이벤트.
# 시드니 단일 추적은 IAM 등 전역 이벤트 일부를 못 받지만, F6 증명에 필요한 S3 데이터 이벤트는 남는다.
# 무료 플랜에서 GuardDuty가 막혀 있으면, 탈취 키의 외부 사용은 sourceIPAddress가 VPC 밖인 이벤트로 판단한다.
########################################

resource "aws_cloudtrail" "ctf" {
  name                          = "${var.name}-trail-${local.suffix}"
  s3_bucket_name                = aws_s3_bucket.b["logs"].id
  s3_key_prefix                 = "cloudtrail"
  is_multi_region_trail         = false
  include_global_service_events = true
  enable_log_file_validation    = true
  depends_on                    = [aws_s3_bucket_policy.logs]

  event_selector {
    read_write_type           = "All"
    include_management_events = true
    data_resource {
      type   = "AWS::S3::Object"
      values = ["${aws_s3_bucket.b["flags"].arn}/"]
    }
  }
}

# VPC Flow Logs v5 사용자 지정 형식, 1분 집계
locals {
  flow_fields = [
    "version", "account-id", "interface-id", "srcaddr", "dstaddr", "srcport", "dstport",
    "protocol", "packets", "bytes", "start", "end", "action", "log-status",
    "vpc-id", "subnet-id", "instance-id", "tcp-flags", "type", "pkt-srcaddr", "pkt-dstaddr",
    "flow-direction", "traffic-path",
  ]
}

resource "aws_flow_log" "vpc" {
  vpc_id                   = aws_vpc.ctf.id
  traffic_type             = "ALL"
  log_destination_type     = "s3"
  log_destination          = "${aws_s3_bucket.b["logs"].arn}/vpcflow"
  max_aggregation_interval = 60
  log_format               = join(" ", [for f in local.flow_fields : format("$%s%s%s", "{", f, "}")])
  depends_on               = [aws_s3_bucket_policy.logs]
}
