"""규칙 표에 쓴 MITRE ATT&CK 기법의 이름과 전술(ATT&CK v15.1, Enterprise).

scripts/attack_techniques.py가 MITRE 공식 STIX 데이터에서 만든다. 손으로 고치지 않는다.
"""

ATTACK_VERSION = "15.1"
SOURCE = "https://github.com/mitre/cti/tree/ATT%26CK-v15.1"

TECHNIQUES: dict[str, dict] = {
    'T1030': {"name": 'Data Transfer Size Limits', "tactics": ['exfiltration']},
    'T1046': {"name": 'Network Service Discovery', "tactics": ['discovery']},
    'T1059': {"name": 'Command and Scripting Interpreter', "tactics": ['execution']},
    'T1059.007': {"name": 'JavaScript', "tactics": ['execution']},
    'T1078': {"name": 'Valid Accounts', "tactics": ['defense-evasion', 'persistence', 'privilege-escalation', 'initial-access']},
    'T1078.004': {"name": 'Cloud Accounts', "tactics": ['defense-evasion', 'persistence', 'privilege-escalation', 'initial-access']},
    'T1083': {"name": 'File and Directory Discovery', "tactics": ['discovery']},
    'T1098': {"name": 'Account Manipulation', "tactics": ['persistence', 'privilege-escalation']},
    'T1105': {"name": 'Ingress Tool Transfer', "tactics": ['command-and-control']},
    'T1110': {"name": 'Brute Force', "tactics": ['credential-access']},
    'T1133': {"name": 'External Remote Services', "tactics": ['persistence', 'initial-access']},
    'T1136': {"name": 'Create Account', "tactics": ['persistence']},
    'T1136.001': {"name": 'Local Account', "tactics": ['persistence']},
    'T1190': {"name": 'Exploit Public-Facing Application', "tactics": ['initial-access']},
    'T1213': {"name": 'Data from Information Repositories', "tactics": ['collection']},
    'T1485': {"name": 'Data Destruction', "tactics": ['impact']},
    'T1496': {"name": 'Resource Hijacking', "tactics": ['impact']},
    'T1505': {"name": 'Server Software Component', "tactics": ['persistence']},
    'T1505.003': {"name": 'Web Shell', "tactics": ['persistence']},
    'T1525': {"name": 'Implant Internal Image', "tactics": ['persistence']},
    'T1530': {"name": 'Data from Cloud Storage', "tactics": ['collection']},
    'T1537': {"name": 'Transfer Data to Cloud Account', "tactics": ['exfiltration']},
    'T1548': {"name": 'Abuse Elevation Control Mechanism', "tactics": ['privilege-escalation', 'defense-evasion']},
    'T1548.003': {"name": 'Sudo and Sudo Caching', "tactics": ['privilege-escalation', 'defense-evasion']},
    'T1552': {"name": 'Unsecured Credentials', "tactics": ['credential-access']},
    'T1552.005': {"name": 'Cloud Instance Metadata API', "tactics": ['credential-access']},
    'T1555': {"name": 'Credentials from Password Stores', "tactics": ['credential-access']},
    'T1555.006': {"name": 'Cloud Secrets Management Stores', "tactics": ['credential-access']},
    'T1556': {"name": 'Modify Authentication Process', "tactics": ['credential-access', 'defense-evasion', 'persistence']},
    'T1556.006': {"name": 'Multi-Factor Authentication', "tactics": ['credential-access', 'defense-evasion', 'persistence']},
    'T1562': {"name": 'Impair Defenses', "tactics": ['defense-evasion']},
    'T1562.007': {"name": 'Disable or Modify Cloud Firewall', "tactics": ['defense-evasion']},
    'T1562.008': {"name": 'Disable or Modify Cloud Logs', "tactics": ['defense-evasion']},
    'T1566': {"name": 'Phishing', "tactics": ['initial-access']},
    'T1580': {"name": 'Cloud Infrastructure Discovery', "tactics": ['discovery']},
    'T1594': {"name": 'Search Victim-Owned Websites', "tactics": ['reconnaissance']},
    'T1595': {"name": 'Active Scanning', "tactics": ['reconnaissance']},
    'T1595.002': {"name": 'Vulnerability Scanning', "tactics": ['reconnaissance']},
    'T1595.003': {"name": 'Wordlist Scanning', "tactics": ['reconnaissance']},
    'T1651': {"name": 'Cloud Administration Command', "tactics": ['execution']},
}
