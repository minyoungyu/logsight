import json
import sys
from collections import Counter

OK, SIDE, MISS = "맞게 탐지", "다른 이유로만 걸림", "놓침"
J = {
    "AWS AMI Attribute Modification for Exfiltration": (OK, "AMI를 다른 계정에 공유 → CT_SNAPSHOT_SHARE"),
    "AWS Bedrock Delete GuardRails": (MISS, "Bedrock 보호 설정 삭제 규칙 없음"),
    "AWS Bedrock Delete Knowledge Base": (MISS, "Bedrock 자원 삭제 규칙 없음"),
    "AWS Bedrock Delete Model Invocation Logging Configuration": (MISS, "Bedrock 로그 끄기를 로그 변조로 보지 않음"),
    "AWS Bedrock High Number List Foundation Model Failures": (OK, "권한 거부 폭주 → CT_ACCESS_DENIED_BURST"),
    "AWS Bedrock Invoke Model Access Denied": (MISS, "거부 1건, 기준(폭주) 미달"),
    "AWS Concurrent Sessions From Different Ips": (SIDE, "루트 사용으로만 걸림. 같은 세션 여러 IP 규칙 없음"),
    "AWS Console Login Failed During MFA Challenge": (SIDE, "루트 사용으로만 걸림. MFA 실패 규칙 없음"),
    "AWS Create Policy Version to allow all resources": (OK, "권한 정책 변경 → CT_IAM_PERSISTENCE"),
    "AWS CreateAccessKey": (OK, "키 생성 → CT_IAM_PERSISTENCE"),
    "AWS CreateLoginProfile": (OK, "콘솔 비밀번호 생성 → CT_IAM_PERSISTENCE"),
    "AWS Defense Evasion Delete Cloudtrail": (OK, "CT_LOGGING_TAMPER"),
    "AWS Defense Evasion Impair Security Services": (OK, "GuardDuty 탐지기 삭제 → CT_LOGGING_TAMPER"),
    "AWS Defense Evasion PutBucketLifecycle": (MISS, "버킷 수명 주기로 로그 지우기 규칙 없음"),
    "AWS Defense Evasion Stop Logging Cloudtrail": (OK, "CT_LOGGING_TAMPER"),
    "AWS Detect Users creating keys with encrypt policy without MFA": (MISS, "KMS 키로 암호화(랜섬웨어) 규칙 없음"),
    "AWS Detect Users with KMS keys performing encryption S3": (MISS, "KMS 암호화(랜섬웨어) 규칙 없음"),
    "AWS Disable Bucket Versioning": (MISS, "버킷 버전 관리 끄기 규칙 없음"),
    "AWS EC2 Multiple SSH Public Keys Uploaded by a Single Identity": (MISS, "EC2 Instance Connect 키 업로드 규칙 없음"),
    "AWS EC2 Snapshot Shared Externally": (OK, "CT_SNAPSHOT_SHARE"),
    "AWS EC2 Startup Script Modified on Stopped Instance": (MISS, "인스턴스 시작 스크립트(userData) 변경 규칙 없음"),
    "AWS ECR Container Scanning Findings High": (MISS, "ECR 이미지 취약점 결과를 읽지 않음"),
    "AWS ECR Container Scanning Findings Low Informational Unknown": (MISS, "ECR 이미지 취약점 결과를 읽지 않음"),
    "AWS ECR Container Scanning Findings Medium": (MISS, "ECR 이미지 취약점 결과를 읽지 않음"),
    "AWS ECR Container Upload Outside Business Hours": (MISS, "ECR 이미지 업로드 규칙 없음"),
    "AWS ECR Container Upload Unknown User": (MISS, "ECR 이미지 업로드 규칙 없음"),
    "AWS Excessive Security Scanning": (OK, "목록 조회 폭주 → CT_DISCOVERY_BURST"),
    "AWS Exfiltration via Anomalous GetObject API Activity": (OK, "CT_S3_BULK_READ"),
    "AWS Exfiltration via Batch Service": (MISS, "Batch로 데이터 옮기기 규칙 없음"),
    "AWS Exfiltration via Bucket Replication": (MISS, "버킷 복제 설정 규칙 없음"),
    "AWS Exfiltration via DataSync Task": (MISS, "DataSync 작업 규칙 없음"),
    "AWS Exfiltration via EC2 Snapshot": (OK, "CT_SNAPSHOT_SHARE"),
    "AWS High Number Of Failed Authentications For User": (SIDE, "MFA 없는 로그인으로만 걸림. 콘솔 로그인 연속 실패 규칙 없음"),
    "AWS IAM AccessDenied Discovery Events": (OK, "CT_ACCESS_DENIED_BURST"),
    "AWS IAM Assume Role Policy Brute Force": (MISS, "역할 이름 대입(AssumeRole 실패) 규칙 없음"),
    "AWS IAM Delete Policy": (MISS, "정책 삭제 규칙 없음"),
    "AWS IAM Failure Group Deletion": (MISS, "그룹 삭제 규칙 없음"),
    "AWS IAM Role Created with External Trust": (OK, "역할 생성 → CT_IAM_PERSISTENCE"),
    "AWS IAM Successful Group Deletion": (MISS, "그룹 삭제 규칙 없음"),
    "AWS Lambda UpdateFunctionCode": (MISS, "Lambda 코드 변경 규칙 없음"),
    "AWS Multi-Factor Authentication Disabled": (SIDE, "루트 사용으로만 걸림. MFA 끄기 규칙 없음"),
    "AWS Multiple Failed MFA Requests For User": (SIDE, "루트 사용으로만 걸림. MFA 실패 규칙 없음"),
    "AWS Network Access Control List Created with All Open Ports": (MISS, "NACL 전체 개방을 보지 않음(다른 보안그룹 변경만 걸림)"),
    "AWS Network Access Control List Deleted": (MISS, "NACL 항목 삭제 규칙 없음(다른 보안그룹 변경만 걸림)"),
    "AWS New MFA Method Registered For User": (SIDE, "루트 사용으로만 걸림. MFA 장치 추가 규칙 없음"),
    "AWS Password Policy Changes": (SIDE, "루트 사용으로만 걸림. 비밀번호 정책 변경 규칙 없음"),
    "AWS Repeated CloudWatch Logs Read Operations": (MISS, "CloudWatch 로그 대량 읽기 규칙 없음"),
    "AWS SAML Update identity provider": (MISS, "SAML 공급자 변경 규칙 없음"),
    "AWS SetDefaultPolicyVersion": (MISS, "정책 기본 버전 바꾸기 규칙 없음"),
    "AWS Successful Console Authentication From Multiple IPs": (SIDE, "MFA 없는 로그인·루트 사용으로만 걸림. 여러 IP 로그인 규칙 없음"),
    "AWS Successful Single-Factor Authentication": (OK, "CT_CONSOLE_NO_MFA"),
    "AWS UpdateLoginProfile": (OK, "콘솔 비밀번호 변경 → CT_IAM_PERSISTENCE"),
}
p = sys.argv[1]
d = json.load(open(p, encoding="utf-8"))
c, cu = Counter(), Counter()
for r in d["rows"]:
    j = J[r["detection"]]
    r["judgement"], r["judgement_reason"] = j
    c[j[0]] += 1
    if not r.get("duplicate_data"):
        cu[j[0]] += 1
d["judgement_rule"] = ("맞게 탐지: LogSight 규칙이 그 행동 자체를 설명한다. 다른 이유로만 걸림: 같은 이벤트가 루트 사용·MFA 없는 로그인 "
                       "같은 다른 규칙으로만 표시됐다. 놓침: 행동에 해당하는 표시가 없다. 판정은 측정 뒤 사람이 했고 이유를 행마다 적었다.")
d["summary"] = {"by_detection": dict(c), "by_unique_dataset": dict(cu)}
json.dump(d, open(p, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
print(c, cu, len(d["rows"]))
