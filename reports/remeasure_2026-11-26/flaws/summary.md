- 이벤트 1,939,207건 → 의심 527,584건 → 탐지 1,678건 → 사건 1,897건(반복을 묶으면 1,519건, 공격 유형 56가지, 심각도 {'high': 854, 'medium': 665, 'low': 0}), 처리 22.47초

| 규칙(전체) | 탐지 | 표시 이벤트 |
| --- | --- | --- |
| CT_ACCESS_DENIED_BURST | 635 | 465,935 |
| CT_DISCOVERY_BURST | 971 | 55,330 |
| CT_INSTANCE_CRED_MULTI_IP | 1 | 13,072 |
| CT_ROOT_USAGE | 39 | 10,997 |
| CT_IAM_PERSISTENCE | 6 | 4,734 |
| CT_S3_PUBLIC | 3 | 151 |
| CT_LOGGING_TAMPER | 11 | 73 |
| CT_SNAPSHOT_SHARE | 2 | 47 |
| CT_SECRET_ACCESS | 3 | 41 |
| CT_ACCOUNT_SECURITY | 2 | 15 |
| CT_INSTANCE_EXEC | 4 | 10 |
| CT_CONSOLE_NO_MFA | 1 | 1 |

| 상위 사건 | 심각도 | 점수 | 기간(UTC) | 단계 | 규칙 | 출발지 | 이벤트 | 반복 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| INC-001 | high | 439 | 2017-02-12T19:57 ~ 2017-02-12T21:55 | discovery → initial-access → persistence → exfiltration | CT_ACCESS_DENIED_BURST, CT_DISCOVERY_BURST, CT_IAM_PERSISTENCE, CT_ROOT_USAGE, CT_S3_PUBLIC | 102.243.123.0, 178.188.9.103 | 486 | 1 |
| INC-002 | high | 439 | 2017-02-12T21:58 ~ 2017-02-12T23:49 | discovery → initial-access → persistence → exfiltration | CT_DISCOVERY_BURST, CT_IAM_PERSISTENCE, CT_ROOT_USAGE, CT_S3_PUBLIC, CT_SNAPSHOT_SHARE | 102.243.123.0, 178.188.9.103 | 557 | 1 |
| INC-003 | high | 439 | 2017-05-26T21:11 ~ 2017-05-26T23:09 | discovery → initial-access → credential-access → persistence | CT_ACCESS_DENIED_BURST, CT_DISCOVERY_BURST, CT_IAM_PERSISTENCE, CT_INSTANCE_CRED_MULTI_IP, CT_ROOT_USAGE | 0.255.91.167, 255.253.125.115 | 692 | 1 |
| INC-004 | high | 439 | 2017-08-01T23:17 ~ 2017-08-01T23:51 | discovery → credential-access → persistence → exfiltration | CT_ACCESS_DENIED_BURST, CT_DISCOVERY_BURST, CT_IAM_PERSISTENCE, CT_SECRET_ACCESS, CT_SNAPSHOT_SHARE | 109.254.7.17 | 16 | 1 |
| INC-005 | high | 439 | 2018-01-18T20:09 ~ 2018-01-18T21:22 | discovery → credential-access → persistence → exfiltration | CT_ACCESS_DENIED_BURST, CT_DISCOVERY_BURST, CT_IAM_PERSISTENCE, CT_INSTANCE_CRED_MULTI_IP, CT_SNAPSHOT_SHARE | 138.150.14.253, 250.253.254.5 | 126 | 1 |
| INC-006 | high | 439 | 2018-02-24T10:42 ~ 2018-02-24T12:42 | discovery → credential-access → persistence → exfiltration | CT_ACCESS_DENIED_BURST, CT_DISCOVERY_BURST, CT_IAM_PERSISTENCE, CT_INSTANCE_CRED_MULTI_IP, CT_SNAPSHOT_SHARE | 191.253.250.239, 245.181.7.4 | 479 | 1 |
| INC-007 | high | 439 | 2018-12-09T03:40 ~ 2018-12-09T03:57 | discovery → credential-access → persistence → defense-evasion | CT_ACCESS_DENIED_BURST, CT_ACCOUNT_SECURITY, CT_DISCOVERY_BURST, CT_IAM_PERSISTENCE, CT_INSTANCE_CRED_MULTI_IP | 201.5.45.253 | 56 | 1 |
| INC-008 | high | 439 | 2019-06-07T11:04 ~ 2019-06-07T11:52 | discovery → credential-access → persistence → defense-evasion | CT_ACCESS_DENIED_BURST, CT_DISCOVERY_BURST, CT_IAM_PERSISTENCE, CT_INSTANCE_CRED_MULTI_IP, CT_LOGGING_TAMPER | 2.251.2.5, 253.128.241.232 | 24 | 1 |
| INC-009 | high | 429 | 2017-02-26T19:44 ~ 2017-02-26T20:08 | discovery → initial-access → persistence → exfiltration | CT_DISCOVERY_BURST, CT_IAM_PERSISTENCE, CT_ROOT_USAGE, CT_S3_PUBLIC | 102.243.123.0, 255.253.125.115 | 195 | 1 |
| INC-010 | high | 429 | 2019-03-03T16:27 ~ 2019-03-03T16:43 | discovery → initial-access → persistence → defense-evasion | CT_ACCOUNT_SECURITY, CT_DISCOVERY_BURST, CT_IAM_PERSISTENCE, CT_ROOT_USAGE | 2.7.223.252 | 254 | 1 |
| INC-011 | high | 424 | 2019-11-17T04:29 ~ 2019-11-17T06:23 | discovery → execution → credential-access | CT_ACCESS_DENIED_BURST, CT_DISCOVERY_BURST, CT_INSTANCE_CRED_MULTI_IP, CT_INSTANCE_EXEC, CT_SECRET_ACCESS | 231.253.230.6, 243.36.252.140 | 974 | 1 |
| INC-012 | high | 414 | 2017-02-28T01:24 ~ 2017-02-28T02:00 | discovery → initial-access → exfiltration | CT_ACCESS_DENIED_BURST, CT_DISCOVERY_BURST, CT_ROOT_USAGE, CT_SNAPSHOT_SHARE | 227.143.251.253, 252.254.2.6 | 189 | 1 |
| INC-013 | high | 414 | 2017-03-01T19:10 ~ 2017-03-01T20:43 | discovery → credential-access → persistence | CT_ACCESS_DENIED_BURST, CT_DISCOVERY_BURST, CT_IAM_PERSISTENCE, CT_INSTANCE_CRED_MULTI_IP | 204.252.37.154 | 91 | 1 |
| INC-014 | high | 414 | 2017-03-09T02:45 ~ 2017-03-09T03:20 | discovery → credential-access → persistence | CT_ACCESS_DENIED_BURST, CT_DISCOVERY_BURST, CT_IAM_PERSISTENCE, CT_INSTANCE_CRED_MULTI_IP | 250.2.3.29, 252.143.5.250 | 29 | 1 |
| INC-015 | high | 414 | 2017-03-09T20:37 ~ 2017-03-09T21:53 | discovery → credential-access → persistence | CT_ACCESS_DENIED_BURST, CT_DISCOVERY_BURST, CT_IAM_PERSISTENCE, CT_INSTANCE_CRED_MULTI_IP | 191.253.250.239, 221.220.0.128 | 45 | 1 |
| INC-016 | high | 414 | 2017-03-16T17:26 ~ 2017-03-16T19:24 | discovery → credential-access → persistence | CT_ACCESS_DENIED_BURST, CT_DISCOVERY_BURST, CT_IAM_PERSISTENCE, CT_INSTANCE_CRED_MULTI_IP | 5.3.205.235 | 197 | 1 |
| INC-017 | high | 414 | 2017-05-26T15:39 ~ 2017-05-26T16:14 | discovery → initial-access → credential-access | CT_ACCESS_DENIED_BURST, CT_DISCOVERY_BURST, CT_INSTANCE_CRED_MULTI_IP, CT_ROOT_USAGE | 255.253.125.115, 4.24.227.210 | 159 | 1 |
| INC-018 | high | 414 | 2017-08-01T16:41 ~ 2017-08-01T17:38 | discovery → persistence → exfiltration | CT_ACCESS_DENIED_BURST, CT_DISCOVERY_BURST, CT_IAM_PERSISTENCE, CT_SNAPSHOT_SHARE | 109.254.7.17 | 11 | 1 |
| INC-019 | high | 414 | 2018-01-23T09:25 ~ 2018-01-23T10:36 | discovery → persistence → exfiltration | CT_ACCESS_DENIED_BURST, CT_DISCOVERY_BURST, CT_IAM_PERSISTENCE, CT_SNAPSHOT_SHARE | 166.140.209.2 | 311 | 1 |
| INC-020 | high | 414 | 2018-02-24T12:42 ~ 2018-02-24T14:18 | discovery → credential-access → persistence | CT_ACCESS_DENIED_BURST, CT_DISCOVERY_BURST, CT_IAM_PERSISTENCE, CT_INSTANCE_CRED_MULTI_IP | 191.253.250.239, 245.181.7.4 | 207 | 1 |

| 규칙(상위 10개 사건 기준) | 이벤트 |
| --- | --- |
| CT_ROOT_USAGE | 1,582 |
| CT_DISCOVERY_BURST | 1,373 |
| CT_ACCESS_DENIED_BURST | 223 |
| CT_INSTANCE_CRED_MULTI_IP | 66 |
| CT_IAM_PERSISTENCE | 38 |
| CT_ACCOUNT_SECURITY | 12 |
| CT_SNAPSHOT_SHARE | 7 |
| CT_S3_PUBLIC | 5 |
| CT_LOGGING_TAMPER | 2 |
| CT_SECRET_ACCESS | 1 |

| 파일 | 종류 | 이벤트 | 오류 |
| --- | --- | --- | --- |
| flaws_cloudtrail00.json.gz | cloudtrail | 100,000 |  |
| flaws_cloudtrail01.json.gz | cloudtrail | 100,000 |  |
| flaws_cloudtrail02.json.gz | cloudtrail | 100,000 |  |
| flaws_cloudtrail03.json.gz | cloudtrail | 100,000 |  |
| flaws_cloudtrail04.json.gz | cloudtrail | 100,000 |  |
| flaws_cloudtrail05.json.gz | cloudtrail | 100,000 |  |
| flaws_cloudtrail06.json.gz | cloudtrail | 100,000 |  |
| flaws_cloudtrail07.json.gz | cloudtrail | 100,000 |  |
| flaws_cloudtrail08.json.gz | cloudtrail | 100,000 |  |
| flaws_cloudtrail09.json.gz | cloudtrail | 100,000 |  |
| flaws_cloudtrail10.json.gz | cloudtrail | 100,000 |  |
| flaws_cloudtrail11.json.gz | cloudtrail | 100,000 |  |
| flaws_cloudtrail12.json.gz | cloudtrail | 100,000 |  |
| flaws_cloudtrail13.json.gz | cloudtrail | 100,000 |  |
| flaws_cloudtrail14.json.gz | cloudtrail | 100,000 |  |
| flaws_cloudtrail15.json.gz | cloudtrail | 100,000 |  |
| flaws_cloudtrail16.json.gz | cloudtrail | 100,000 |  |
| flaws_cloudtrail17.json.gz | cloudtrail | 100,000 |  |
| flaws_cloudtrail18.json.gz | cloudtrail | 100,000 |  |
| flaws_cloudtrail19.json.gz | cloudtrail | 39,207 |  |
