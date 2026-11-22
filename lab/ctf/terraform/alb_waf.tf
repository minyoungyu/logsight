########################################
# ALB — 팀마다 포트 하나(8001~8010) → 팀 서버 80
########################################

resource "aws_lb" "ctf" {
  name                       = "${var.name}-alb-${local.suffix}"
  load_balancer_type         = "application"
  subnets                    = aws_subnet.public[*].id
  security_groups            = [aws_security_group.alb.id]
  idle_timeout               = 60
  drop_invalid_header_fields = true
  xff_header_processing_mode = "append"

  access_logs {
    bucket  = aws_s3_bucket.b["logs"].id
    prefix  = "alb"
    enabled = true
  }
  depends_on = [aws_s3_bucket_policy.logs]
}

resource "aws_lb_target_group" "team" {
  for_each    = local.teams
  name        = "${var.name}-${each.key}-${local.suffix}"
  port        = 80
  protocol    = "HTTP"
  vpc_id      = aws_vpc.ctf.id
  target_type = "instance"
  health_check {
    path                = "/health.txt"
    matcher             = "200"
    interval            = 30
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }
}

resource "aws_lb_target_group_attachment" "team" {
  for_each         = local.teams
  target_group_arn = aws_lb_target_group.team[each.key].arn
  target_id        = aws_instance.team[each.key].id
  port             = 80
}

resource "aws_lb_listener" "team" {
  for_each          = local.teams
  load_balancer_arn = aws_lb.ctf.arn
  port              = 8000 + each.value
  protocol          = "HTTP"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.team[each.key].arn
  }
}

########################################
# WAF — 손으로 하는 공격은 통과(COUNT로 기록), 스캔·대입은 차단(BLOCK도 로그에 남는다)
########################################

resource "aws_wafv2_regex_pattern_set" "scanners" {
  name  = "${var.name}-scanner-ua"
  scope = "REGIONAL"
  regular_expression {
    regex_string = "(?i)(sqlmap|gobuster|dirb|dirbuster|ffuf|nikto|nmap|hydra|wfuzz|feroxbuster|nuclei|masscan|zgrab)"
  }
}

resource "aws_wafv2_ip_set" "shared_ip" {
  name               = "${var.name}-shared-venue-ip"
  description        = "학교 공용 IP 등 여러 팀이 쓰는 IP: 전체 한도를 5분 500건으로 완화"
  scope              = "REGIONAL"
  ip_address_version = "IPV4"
  addresses          = []
  lifecycle {
    ignore_changes = [addresses] # 대회 중 콘솔/CLI로 추가해도 apply가 되돌리지 않게
  }
}

resource "aws_wafv2_web_acl" "ctf" {
  name  = "${var.name}-acl"
  scope = "REGIONAL"
  default_action {
    allow {}
  }

  rule {
    name     = "block-scanner-ua"
    priority = 1
    action {
      block {}
    }
    statement {
      regex_pattern_set_reference_statement {
        arn = aws_wafv2_regex_pattern_set.scanners.arn
        field_to_match {
          single_header {
            name = "user-agent"
          }
        }
        text_transformation {
          priority = 0
          type     = "NONE"
        }
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "scanner-ua"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "rate-login"
    priority = 2
    action {
      block {}
    }
    statement {
      rate_based_statement {
        limit                 = 10
        evaluation_window_sec = 300
        aggregate_key_type    = "IP"
        scope_down_statement {
          byte_match_statement {
            search_string         = "login"
            positional_constraint = "CONTAINS"
            field_to_match {
              uri_path {}
            }
            text_transformation {
              priority = 0
              type     = "LOWERCASE"
            }
          }
        }
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "rate-login"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "rate-shared-ip"
    priority = 3
    action {
      block {}
    }
    statement {
      rate_based_statement {
        limit                 = 500
        evaluation_window_sec = 300
        aggregate_key_type    = "IP"
        scope_down_statement {
          ip_set_reference_statement {
            arn = aws_wafv2_ip_set.shared_ip.arn
          }
        }
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "rate-shared-ip"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "rate-all"
    priority = 4
    action {
      block {}
    }
    statement {
      rate_based_statement {
        limit                 = 100
        evaluation_window_sec = 300
        aggregate_key_type    = "IP"
        scope_down_statement {
          not_statement {
            statement {
              ip_set_reference_statement {
                arn = aws_wafv2_ip_set.shared_ip.arn
              }
            }
          }
        }
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "rate-all"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "aws-sqli-count"
    priority = 5
    override_action {
      count {}
    }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesSQLiRuleSet"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "sqli"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "aws-common-count"
    priority = 6
    override_action {
      count {}
    }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "common"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.name}-acl"
    sampled_requests_enabled   = true
  }
}

resource "aws_wafv2_web_acl_association" "alb" {
  resource_arn = aws_lb.ctf.arn
  web_acl_arn  = aws_wafv2_web_acl.ctf.arn
}

resource "aws_wafv2_web_acl_logging_configuration" "ctf" {
  resource_arn            = aws_wafv2_web_acl.ctf.arn
  log_destination_configs = [aws_s3_bucket.b["waf"].arn]
  depends_on              = [aws_s3_bucket_policy.waf]
}
