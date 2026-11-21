"""GuardDuty 탐지 유형을 비전문가가 읽는 한국어로 바꾼다("탐지는 AWS, 해석과 조치는 LogFinder").

GuardDuty 결과의 제목·설명은 영어이고 유형 이름(예: `Backdoor:EC2/C&CActivity.B!DNS`)은 전문 용어다.
이 모듈은 유형 이름 하나로 다음을 만든다.

- title: 한국어 제목(예: "서버(EC2)가 공격자의 명령 서버와 통신")
- plain: 무슨 뜻인지 한 문장
- action: 먼저 할 일 한 문장과 그 단계(번지는 것 막기 0 / 들어온 길 닫기 1 / 원인 고치기 2)
- level: specific(유형별로 직접 쓴 문장) | composed(위협 목적·자원·행동 낱말을 조합) | raw(모르는 낱말이 있어 영어가 남음)

전체 유형 목록은 samples/guardduty/finding_types.tsv(AWS 공식 문서), 몇 종을 풀어 주는지는
`python scripts/gd_coverage.py`로 잰다.
"""
from __future__ import annotations

import re

# 위협 목적(유형 이름의 앞부분)
PURPOSE_KO = {
    "Backdoor": "공격자 조종", "Behavior": "평소와 다른 행동", "CredentialAccess": "비밀번호·키 탈취",
    "CryptoCurrency": "코인 채굴", "DefenseEvasion": "탐지 피하기", "Discovery": "정찰(둘러보기)",
    "Execution": "악성 실행", "Exfiltration": "데이터 빼내기", "Impact": "피해 일으키기",
    "InitialAccess": "처음 침입", "Object": "악성 파일", "PenTest": "해킹 도구 사용", "Persistence": "다시 들어올 문 만들기",
    "Policy": "위험한 설정", "PrivilegeEscalation": "권한 올리기", "Recon": "정찰(둘러보기)",
    "Stealth": "흔적 감추기", "Trojan": "악성코드 감염 의심", "UnauthorizedAccess": "허가 없는 접근",
    "AttackSequence": "여러 단계로 이어진 공격",
}

# 대상 자원(유형 이름의 가운데)
RESOURCE_KO = {
    "EC2": "서버(EC2)", "IAMUser": "AWS 사용자·키", "IAM": "AWS 자격증명", "S3": "S3 저장소",
    "Kubernetes": "쿠버네티스(EKS)", "EKS": "쿠버네티스(EKS)", "ECS": "컨테이너(ECS)", "Container": "컨테이너",
    "Lambda": "Lambda 함수", "RDS": "데이터베이스(RDS)", "Runtime": "서버·컨테이너 안 프로그램",
}

# 행동(유형 이름의 뒷부분, '.'·'!' 앞)
BEHAVIOR_KO = {
    "AnomalousBehavior": "평소와 다른 호출", "MaliciousIPCaller": "알려진 악성 IP에서 호출",
    "TorIPCaller": "익명망(Tor)에서 호출", "TorClient": "익명망(Tor)에 접속", "TorRelay": "익명망(Tor) 중계 노드로 동작",
    "C&CActivity": "공격자의 명령 서버와 통신", "DenialOfService": "다른 곳을 공격(서비스 거부)하는 데 쓰임",
    "Spambot": "스팸 메일 발송", "NetworkPortUnusual": "평소 쓰지 않던 포트로 통신",
    "TrafficVolumeUnusual": "평소보다 훨씬 많은 데이터를 보냄", "BitcoinTool": "코인 채굴 서버와 통신",
    "BitcoinDomainRequest": "코인 채굴 주소에 접속", "MaliciousDomainRequest": "악성 주소에 접속",
    "AbusedDomainRequest": "악용되는 주소에 접속", "SuspiciousDomainRequest": "의심스러운 주소에 접속",
    "BlackholeTraffic": "막힌(블랙홀) 주소로 통신 시도", "DGADomainRequest": "악성코드가 자동 생성한 주소에 접속",
    "DNSDataExfiltration": "DNS 요청에 데이터를 숨겨 빼냄", "DriveBySourceTraffic": "악성코드 유포 주소와 통신",
    "DropPoint": "탈취 데이터 수집 서버와 통신", "PhishingDomainRequest": "피싱 주소에 접속",
    "MetadataDNSRebind": "서버 메타데이터(역할 키)를 노린 DNS 우회 요청",
    "UnusualDNSResolver": "평소와 다른 DNS 서버 사용", "UnusualDoHActivity": "암호화 DNS(DoH)로 통신을 숨김",
    "UnusualDoTActivity": "암호화 DNS(DoT)로 통신을 숨김", "PortSweep": "다른 서버들의 포트를 훑음",
    "WinRMBruteForce": "윈도우 원격 관리(WinRM) 비밀번호 대입", "PortProbeUnprotectedPort": "열린 포트를 외부에서 두드림",
    "PortProbeEMRUnprotectedPort": "열린 EMR 포트를 외부에서 두드림", "Portscan": "다른 서버의 포트를 훑음",
    "RDPBruteForce": "원격 데스크톱(RDP) 비밀번호 대입", "SSHBruteForce": "SSH 비밀번호 대입",
    "ConsoleLoginSuccess": "평소와 다른 곳에서 콘솔 로그인 성공",
    "InstanceCredentialExfiltration": "서버 역할 키가 서버 밖에서 쓰임",
    "ResourceCredentialExfiltration": "AWS 서비스에 붙은 역할 키가 그 서비스 밖에서 쓰임",
    "CompromisedCredentials": "유출된 자격증명이 쓰임", "RootCredentialUsage": "루트 계정 사용",
    "ShortTermRootCredentialUsage": "루트 계정의 임시 자격증명 사용", "PasswordPolicyChange": "비밀번호 정책을 약하게 바꿈",
    "CloudTrailLoggingDisabled": "CloudTrail 기록을 끔", "ServerAccessLoggingDisabled": "S3 접근 기록을 끔",
    "BedrockLoggingDisabled": "AI(Bedrock) 호출 기록을 끔",
    "AccountBlockPublicAccessDisabled": "계정 전체의 S3 공개 차단을 끔",
    "BucketBlockPublicAccessDisabled": "버킷의 공개 차단을 끔", "BucketPublicAccessGranted": "버킷을 누구나 읽게 공개함",
    "BucketAnonymousAccessGranted": "버킷을 로그인 없이 읽게 공개함",
    "KaliLinux": "해킹용 운영체제(Kali)에서 호출", "ParrotLinux": "해킹용 운영체제(Parrot)에서 호출",
    "PentooLinux": "해킹용 운영체제(Pentoo)에서 호출", "ObjectRead": "평소와 다르게 객체를 읽음",
    "SuccessfulAnonymousAccess": "로그인 없이(익명으로) 요청이 성공", "ExecInKubeSystemPod": "시스템 파드 안에서 명령 실행",
    "AdminAccessToDefaultServiceAccount": "기본 서비스 계정에 관리자 권한을 줌",
    "AnonymousAccessGranted": "익명 사용자에게 권한을 줌", "KubeflowDashboardExposed": "Kubeflow 대시보드가 인터넷에 열림",
    "ExposedDashboard": "쿠버네티스 대시보드가 인터넷에 열림", "MaliciousFile": "악성 파일 발견",
    "SuspiciousFile": "의심스러운 파일 발견", "FilelessExecution": "파일 없이 메모리에서 프로그램 실행",
    "KernelModuleLoaded": "커널 모듈을 올림", "SensitiveFileModified": "중요한 시스템 파일을 고침",
    "ProcessInjection": "다른 프로그램에 코드를 끼워 넣음", "PtraceAntiDebugging": "분석을 피하는 동작",
    "SuspiciousCommand": "의심스러운 명령 실행", "MaliciousFileExecuted": "악성 파일 실행",
    "NewBinaryExecuted": "새로 생긴 실행 파일 실행", "NewLibraryLoaded": "새로 생긴 라이브러리 로드",
    "SuspiciousShellCreated": "의심스러운 셸을 엶", "SuspiciousTool": "해킹 도구 실행", "ReverseShell": "공격자에게 셸을 열어 줌(리버스 셸)",
    "CryptoMinerExecuted": "코인 채굴 프로그램 실행", "CGroupsReleaseAgentModified": "컨테이너 탈출 시도(cgroup 조작)",
    "ContainerMountsHostDirectory": "컨테이너가 서버 폴더를 붙임", "DockerSocketAccessed": "도커 제어 소켓에 접근",
    "ElevationToRoot": "root 권한으로 올림", "RuncContainerEscape": "컨테이너 탈출 시도(runc)",
    "UserfaultfdUsage": "커널 취약점 공격에 쓰이는 기능 사용",
    "AnomalousModelInvocation": "AI 모델을 평소와 다르게 호출", "CostHarvesting": "AI 모델을 몰래 써서 요금을 일으킴",
    "PromptInjection": "AI에 대한 프롬프트 주입", "CompromisedCluster": "클러스터가 뚫린 정황",
    "CompromisedData": "S3 데이터가 뚫린 정황", "CompromisedInstanceGroup": "서버 여러 대가 뚫린 정황",
}

# 행동 뒤 꼬리표
SUFFIX_KO = {"Custom": "우리가 등록한 위협 목록", "DNS": "DNS 기록으로 확인"}

# 유형별로 직접 쓴 풀이: 부분 문자열 → (제목, 풀이, 먼저 할 일, 단계). 위에서부터 처음 맞는 것을 쓴다
SPECIFIC: list[tuple[str, str, str, str, int]] = [
    ("AttackSequence:", "GuardDuty가 여러 신호를 하나의 공격으로 묶음",
     "GuardDuty가 서로 다른 의심 신호를 같은 공격의 단계로 보고 하나로 묶었습니다. 가장 심각한 등급입니다.",
     "GuardDuty 콘솔에서 이 결과의 '신호' 목록을 열어 나오는 키·서버부터 막으세요", 0),
    ("InstanceCredentialExfiltration.OutsideAWS", "서버 역할 키가 AWS 밖에서 쓰임",
     "서버에만 있어야 할 임시 키가 인터넷의 다른 컴퓨터에서 쓰였습니다. 웹 취약점(SSRF 등)으로 키가 새었을 가능성이 큽니다.",
     "이 서버 역할의 기존 세션을 무효화하고(이전에 발급된 키 거부) IMDSv2를 강제하세요", 0),
    ("InstanceCredentialExfiltration.InsideAWS", "서버 역할 키가 다른 AWS 계정에서 쓰임",
     "서버에만 있어야 할 임시 키가 다른 AWS 계정의 컴퓨터에서 쓰였습니다. 키가 새었을 가능성이 큽니다.",
     "이 서버 역할의 기존 세션을 무효화하고(이전에 발급된 키 거부) IMDSv2를 강제하세요", 0),
    ("ResourceCredentialExfiltration", "AWS 서비스의 역할 키가 밖에서 쓰임",
     "Lambda·ECS 같은 서비스에 붙은 임시 키가 그 서비스 밖에서 쓰였습니다. 키가 새었을 가능성이 큽니다.",
     "이 역할의 기존 세션을 무효화하고, 키를 꺼낼 수 있었던 코드·환경변수를 확인하세요", 0),
    ("CompromisedCredentials", "유출된 자격증명이 쓰임",
     "인터넷에 유출된 것으로 알려진 키나 비밀번호로 AWS가 호출됐습니다.",
     "이 액세스 키를 비활성화하고 같은 사용자의 다른 키·콘솔 비밀번호도 바꾸세요", 0),
    ("ConsoleLoginSuccess", "평소와 다른 곳에서 AWS 콘솔 로그인 성공",
     "이 사용자가 평소와 다른 곳에서 콘솔에 로그인했습니다. 본인이 아니면 비밀번호가 새었습니다.",
     "본인에게 확인하고, 아니면 비밀번호를 바꾸고 MFA를 켜세요", 0),
    ("RootCredentialUsage", "루트 계정이 쓰임",
     "모든 권한을 가진 루트 계정으로 작업했습니다. 평소에는 쓰지 않아야 하는 계정입니다.",
     "누가 루트로 무엇을 했는지 확인하고, 루트에 MFA가 켜져 있는지 보세요", 0),
    ("CloudTrailLoggingDisabled", "CloudTrail 기록이 꺼짐",
     "AWS에서 누가 무엇을 했는지 남기는 기록이 꺼졌습니다. 공격자가 흔적을 지울 때 흔히 합니다.",
     "CloudTrail 기록을 바로 다시 켜고, 끈 계정의 키를 확인하세요", 0),
    ("PasswordPolicyChange", "비밀번호 정책이 약해짐",
     "계정의 비밀번호 규칙이 바뀌었습니다. 약하게 바꿨다면 공격자가 쉽게 들어올 수 있습니다.",
     "바뀐 정책을 원래대로 되돌리고 누가 바꿨는지 확인하세요", 2),
    ("BucketPublicAccessGranted", "S3 버킷이 누구나 읽게 공개됨",
     "버킷 정책이나 권한이 바뀌어 인터넷의 누구나 이 버킷을 읽을 수 있게 됐습니다.",
     "버킷의 공개 설정을 되돌리고 '퍼블릭 액세스 차단'을 켜세요", 1),
    ("BucketAnonymousAccessGranted", "S3 버킷이 로그인 없이 읽게 공개됨",
     "버킷 권한이 바뀌어 로그인하지 않은 사람도 이 버킷을 읽을 수 있게 됐습니다.",
     "버킷의 공개 설정을 되돌리고 '퍼블릭 액세스 차단'을 켜세요", 1),
    ("BlockPublicAccessDisabled", "S3 공개 차단이 꺼짐",
     "버킷이 실수로 공개되지 않게 막는 설정이 꺼졌습니다. 아직 공개된 것은 아닐 수 있습니다.",
     "의도한 변경이 아니면 '퍼블릭 액세스 차단'을 다시 켜세요", 1),
    ("Exfiltration:S3", "S3 데이터가 평소와 다르게 빠져나감",
     "평소와 다른 주체·위치에서 S3 객체를 많이 읽었습니다. 데이터 유출일 수 있습니다.",
     "버킷을 읽은 키를 비활성화하고, 어떤 객체를 읽었는지 S3 데이터 이벤트로 확인하세요", 0),
    ("Impact:S3/AnomalousBehavior.Delete", "S3 데이터가 평소와 다르게 지워짐",
     "평소와 다른 주체가 S3 객체를 많이 지웠습니다. 랜섬웨어나 파괴 공격일 수 있습니다.",
     "지운 키를 비활성화하고 버전 관리·백업에서 복구할 수 있는지 확인하세요", 0),
    ("SSHBruteForce", "SSH 비밀번호 대입 공격",
     "누군가 서버의 SSH에 비밀번호를 계속 바꿔 넣고 있습니다. 결국 들어왔는지는 서버의 auth.log에만 남습니다.",
     "SSH(22번 포트)를 관리자 IP에만 열고, auth.log로 로그인 성공이 있었는지 확인하세요", 1),
    ("RDPBruteForce", "원격 데스크톱 비밀번호 대입 공격",
     "누군가 서버의 원격 데스크톱(RDP)에 비밀번호를 계속 바꿔 넣고 있습니다.",
     "RDP(3389번 포트)를 관리자 IP에만 여세요", 1),
    ("PortProbe", "열린 포트를 외부에서 두드림",
     "인터넷에서 이 서버의 열린 포트에 접속을 시도하고 있습니다. 공격 전에 흔히 보이는 일입니다.",
     "필요 없는 포트를 보안그룹에서 닫으세요", 1),
    ("C&CActivity", "공격자의 명령 서버와 통신",
     "이 서버(또는 함수)가 공격자가 원격으로 조종할 때 쓰는 주소와 통신했습니다. 이미 감염됐을 가능성이 큽니다.",
     "서버를 격리하고(보안그룹 교체) 디스크 스냅샷으로 증거를 남긴 뒤 새로 만드세요", 0),
    ("BitcoinTool", "코인 채굴 서버와 통신",
     "이 서버가 코인 채굴에 쓰이는 주소와 통신했습니다. 누군가 서버를 몰래 채굴에 쓰고 있을 수 있습니다.",
     "서버를 격리하고 채굴 프로그램이 어떻게 들어왔는지 확인하세요", 0),
    ("CryptoMinerExecuted", "코인 채굴 프로그램 실행",
     "서버나 컨테이너에서 코인 채굴 프로그램이 실행됐습니다. 이미 뚫린 상태입니다.",
     "서버를 격리하고 채굴 프로그램이 어떻게 들어왔는지 확인하세요", 0),
    ("ReverseShell", "공격자에게 셸이 열림",
     "서버의 프로그램이 공격자 쪽으로 명령 창(셸)을 열어 주었습니다. 공격자가 서버를 조작할 수 있는 상태입니다.",
     "서버를 바로 격리하고 디스크 스냅샷으로 증거를 남기세요", 0),
    ("MetadataDNSRebind", "서버 역할 키를 노린 요청",
     "서버의 메타데이터 주소(역할 키가 있는 곳)를 DNS로 우회해 부르려는 요청이 있었습니다. 웹 취약점으로 키를 빼내려는 시도입니다.",
     "IMDSv2를 강제하고 이 서버 역할 키가 밖에서 쓰였는지 CloudTrail로 확인하세요", 1),
    ("DenialOfService", "다른 곳을 공격하는 데 쓰임",
     "이 서버가 다른 곳을 마비시키는 공격(서비스 거부)에 쓰이고 있습니다. 이미 감염됐을 가능성이 큽니다.",
     "서버를 격리하고 디스크 스냅샷으로 증거를 남기세요", 0),
    ("Spambot", "스팸 메일 발송",
     "이 서버가 스팸 메일을 보내고 있습니다. 감염됐거나 메일 기능이 악용되고 있습니다.",
     "서버를 격리하고 25번 포트 밖으로 나가는 통신을 막으세요", 0),
    ("PenTest:", "해킹용 운영체제에서 호출",
     "해킹 도구가 기본으로 깔린 운영체제에서 AWS를 호출했습니다. 우리 팀의 점검이 아니면 키가 새었습니다.",
     "우리 팀 점검인지 확인하고, 아니면 이 키를 비활성화하세요", 0),
    ("SuccessfulAnonymousAccess", "쿠버네티스에 로그인 없이 요청이 성공",
     "로그인하지 않은 사용자의 요청이 쿠버네티스에서 성공했습니다. 클러스터가 인터넷에 열려 있을 수 있습니다.",
     "익명 접근 권한을 지우고 클러스터 API를 관리자 IP에만 여세요", 1),
    ("RDS/AnomalousBehavior.SuccessfulBruteForce", "데이터베이스 비밀번호가 뚫림",
     "데이터베이스에 비밀번호를 여러 번 넣다가 결국 로그인에 성공했습니다.",
     "그 DB 사용자의 비밀번호를 바꾸고 DB 접속을 앱 서버에만 허용하세요", 0),
    ("SuccessfulLogin", "데이터베이스에 의심스러운 로그인 성공",
     "평소와 다르거나 알려진 악성 위치에서 데이터베이스에 로그인했습니다.",
     "그 DB 사용자의 비밀번호를 바꾸고 DB 접속을 앱 서버에만 허용하세요", 0),
    ("MaliciousFileExecuted", "악성 파일 실행",
     "서버나 컨테이너에서 악성으로 알려진 파일이 실행됐습니다. 이미 뚫린 상태입니다.",
     "서버를 격리하고 디스크 스냅샷으로 증거를 남기세요", 0),
    ("MaliciousFile", "악성 파일 발견",
     "GuardDuty가 디스크나 저장소에서 악성 파일을 찾았습니다.",
     "파일이 있는 서버·객체를 격리하고 어떻게 들어왔는지 확인하세요", 0),
]

# 자원별 기본 조치(유형별 문장이 없을 때): (조치, 단계)
DEFAULT_ACTION = {
    "IAMUser": ("이 키를 쓴 사람이 우리 팀인지 확인하고, 아니면 키를 비활성화하세요", 0),
    "IAM": ("관련 키·역할을 확인하고, 우리 팀이 아니면 비활성화하세요", 0),
    "EC2": ("서버를 격리하고(보안그룹 교체) 디스크 스냅샷으로 증거를 남기세요", 0),
    "Runtime": ("서버·컨테이너를 격리하고 디스크 스냅샷으로 증거를 남기세요", 0),
    "Container": ("컨테이너를 멈추고 이미지를 확인하세요", 0),
    "ECS": ("작업(task)을 멈추고 이미지를 확인하세요", 0),
    "Kubernetes": ("의심 파드·권한을 확인하고, 클러스터 API를 관리자 IP에만 여세요", 0),
    "Lambda": ("함수의 코드·환경변수를 확인하고 의심 버전의 배포를 멈추세요", 0),
    "RDS": ("DB 사용자 비밀번호를 바꾸고 DB 접속을 앱 서버에만 허용하세요", 0),
    "S3": ("버킷에 접근한 키를 확인하고, 우리 팀이 아니면 비활성화하세요", 0),
}
# 감염이 확실하지 않은 행동: 바로 격리하지 말고 어떤 프로그램이 했는지부터 본다
SOFT_BEHAVIOR = {"SuspiciousDomainRequest", "AbusedDomainRequest", "UnusualDNSResolver", "UnusualDoHActivity",
                 "UnusualDoTActivity", "NetworkPortUnusual", "TrafficVolumeUnusual", "BlackholeTraffic",
                 "NewBinaryExecuted", "NewLibraryLoaded", "SuspiciousShellCreated", "PtraceAntiDebugging"}
SOFT_ACTION = ("서버에서 어떤 프로그램이 이 일을 했는지 확인하고, 모르는 프로그램이면 서버를 격리하세요", 2)
# 서버·주체가 피해자가 아니라 '바깥에서 두드림'인 목적은 단계를 1(들어온 길 닫기)로
INBOUND_PURPOSE = {"Recon", "Discovery", "UnauthorizedAccess"}

_TYPE = re.compile(r"^([A-Za-z]+):([A-Za-z0-9]+)/([^.!]+)(?:\.([^!]+))?(?:!(.+))?$")


def parse(typ: str) -> dict:
    """'Backdoor:EC2/C&CActivity.B!DNS' → purpose, resource, behavior, variant, tag."""
    m = _TYPE.match(str(typ or ""))
    if not m:
        return {}
    return dict(zip(("purpose", "resource", "behavior", "variant", "tag"), m.groups()))


def describe(typ: str) -> dict:
    """GuardDuty 유형 이름 → 한국어 제목·풀이·먼저 할 일·단계·수준."""
    p = parse(typ)
    for key, title, plain, action, phase in SPECIFIC:
        if key in typ:
            return {"title": title, "plain": plain, "action": action, "phase": phase, "level": "specific"}
    if not p:
        return {"title": str(typ), "plain": "", "action": "", "phase": 2, "level": "raw"}
    purpose = PURPOSE_KO.get(p["purpose"])
    res = RESOURCE_KO.get(p["resource"])
    beh = BEHAVIOR_KO.get(p["behavior"])
    known = all((purpose, res, beh))
    tag = [SUFFIX_KO[t] for t in (p.get("variant"), p.get("tag")) if t in SUFFIX_KO]
    title = f"{res or p['resource']}: {beh or p['behavior']}" + (f" ({', '.join(tag)})" if tag else "")
    plain = (f"GuardDuty가 {res or p['resource']}에서 '{purpose or p['purpose']}'에 해당하는 일을 보았습니다"
             f"({beh or p['behavior']}).")
    action, phase = DEFAULT_ACTION.get(p["resource"], ("GuardDuty 콘솔에서 이 결과의 대상 자원을 확인하세요", 2))
    if p["resource"] in ("EC2", "Runtime") and (p["behavior"] in SOFT_BEHAVIOR or p["purpose"] == "Discovery"):
        action, phase = SOFT_ACTION
    if p["resource"] == "RDS" and p.get("variant") == "FailedLogin":
        action, phase = "DB 접속을 앱 서버에만 허용하고, 같은 출발지의 로그인 성공이 있었는지 확인하세요", 1
    if p["purpose"] in INBOUND_PURPOSE and p["resource"] in ("EC2", "RDS", "Kubernetes", "S3"):
        phase = 1
    return {"title": title, "plain": plain, "action": action, "phase": phase,
            "level": "composed" if known else "raw"}
