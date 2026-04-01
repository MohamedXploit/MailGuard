from mailguard.analyzers.mta_sts import parse_mta_sts_policy


def test_parse_mta_sts_policy() -> None:
    raw = """version: STSv1
mode: enforce
mx: *.mail.example.com
max_age: 86400
"""
    policy = parse_mta_sts_policy(raw)
    assert policy.valid is True
    assert policy.mode == "enforce"
    assert policy.mx_patterns == ["*.mail.example.com"]
    assert policy.max_age == 86400
