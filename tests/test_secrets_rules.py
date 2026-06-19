from pathlib import Path

import pytest

from agent_security_scanner.models import FileContext
from agent_security_scanner.rules.secrets import AIProviderSecretPattern, SecretsRule


def scan_text(text: str):
    return SecretsRule().scan(FileContext(path=Path("app.py"), relative_path="app.py", text=text))


def test_detects_openai_api_key():
    findings = scan_text('OPENAI_API_KEY = "sk-example1234567890example1234567890"')

    assert any(f.rule_id == "SEC001" for f in findings)


def test_detects_github_token():
    findings = scan_text('token = "ghp_example1234567890example1234567890"')

    assert any(f.rule_id == "SEC002" for f in findings)


def test_secret_evidence_is_masked():
    findings = scan_text('token = "sk-example1234567890example1234567890"')

    evidence = findings[0].evidence
    assert evidence is not None
    assert "..." in evidence
    assert "example1234567890example" not in evidence


def test_detects_hugging_face_token():
    findings = scan_text('HF_TOKEN = "hf_abcdefghijklmnopqrstuvwxyz1234567890"')

    assert any(f.rule_id == "SEC009" for f in findings)


def test_detects_npm_and_pypi_tokens():
    findings = scan_text(
        """
        //registry.npmjs.org/:_authToken=npm_abcdefghijklmnopqrstuvwxyz1234567890
        password = "pypi-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
        """
    )

    rule_ids = {finding.rule_id for finding in findings}
    assert {"SEC010", "SEC011"} <= rule_ids


def test_detects_database_url_password():
    findings = scan_text("DATABASE_URL=postgres://agent:supersecretpass@example.com:5432/app")

    assert any(f.rule_id == "SEC016" for f in findings)


def test_detects_generic_high_entropy_credential_but_ignores_low_entropy():
    findings = scan_text(
        """
        api_key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        client_secret = "a8F2jK9LmN4pQ7rS1tU6vW3xY0zB"
        """
    )

    assert sum(1 for finding in findings if finding.rule_id == "SEC017") == 1


def test_ai_provider_pattern_detects_provider_variable_assignment():
    rule = SecretsRule()
    rule.ai_provider_patterns = [
        AIProviderSecretPattern(
            rule_id="SEC999",
            provider="Example AI",
            aliases=("exampleai",),
            variable_names=("EXAMPLE_AI_API_KEY",),
        )
    ]

    findings = rule.scan(
        FileContext(
            path=Path(".env"),
            relative_path=".env",
            text='EXAMPLE_AI_API_KEY="A1b2C3d4E5f6G7h8I9j0K1l2M3n4"',
        )
    )

    finding = next(finding for finding in findings if finding.rule_id == "SEC999")
    assert finding.title == "Example AI API key detected"
    assert finding.evidence is not None
    assert "..." in finding.evidence


def test_ai_provider_pattern_requires_context_for_prefix_only_tokens():
    rule = SecretsRule()
    rule.ai_provider_patterns = [
        AIProviderSecretPattern(
            rule_id="SEC998",
            provider="Example AI",
            aliases=("exampleai",),
            variable_names=("EXAMPLE_AI_API_KEY",),
            domains=("api.example.ai",),
            token_prefixes=("exai-",),
        )
    ]

    without_context = rule.scan(
        FileContext(
            path=Path("notes.txt"),
            relative_path="notes.txt",
            text="token = exai-A1b2C3d4E5f6G7h8I9j0K1l2",
        )
    )
    with_context = rule.scan(
        FileContext(
            path=Path("settings.env"),
            relative_path="settings.env",
            text="EXAMPLE_AI_BASE_URL=https://api.example.ai\napi_key=exai-A1b2C3d4E5f6G7h8I9j0K1l2",
        )
    )

    assert not any(finding.rule_id == "SEC998" for finding in without_context)
    assert any(finding.rule_id == "SEC998" for finding in with_context)


@pytest.mark.parametrize(
    ("rule_id", "text"),
    [
        ("SEC018", 'DEEPSEEK_API_KEY="sk-deepseekA1b2C3d4E5f6G7h8I9j0"'),
        ("SEC019", "GROQ_API_KEY=gsk_A1b2C3d4E5f6G7h8I9j0K1l2"),
        ("SEC020", "XAI_API_KEY=xai-A1b2C3d4E5f6G7h8I9j0K1l2"),
        ("SEC021", "PERPLEXITY_API_KEY=pplx-A1b2C3d4E5f6G7h8I9j0K1l2"),
        ("SEC022", "OPENROUTER_API_KEY=sk-or-A1b2C3d4E5f6G7h8I9j0K1l2"),
        ("SEC023", "TOGETHER_API_KEY=A1b2C3d4E5f6G7h8I9j0K1l2M3n4"),
        ("SEC024", "FIREWORKS_API_KEY=A1b2C3d4E5f6G7h8I9j0K1l2M3n4"),
        ("SEC025", "MISTRAL_API_KEY=A1b2C3d4E5f6G7h8I9j0K1l2M3n4"),
        ("SEC026", "COHERE_API_KEY=A1b2C3d4E5f6G7h8I9j0K1l2M3n4"),
        ("SEC027", "REPLICATE_API_TOKEN=r8_A1b2C3d4E5f6G7h8I9j0K1l2"),
        ("SEC028", "AZURE_OPENAI_API_KEY=A1b2C3d4E5f6G7h8I9j0K1l2M3n4"),
        ("SEC029", "NVIDIA_API_KEY=A1b2C3d4E5f6G7h8I9j0K1l2M3n4"),
        ("SEC030", "STABILITY_API_KEY=sk-stabilityA1b2C3d4E5f6G7h8I9j0"),
        ("SEC031", "ELEVENLABS_API_KEY=A1b2C3d4E5f6G7h8I9j0K1l2M3n4"),
        ("SEC032", "VOYAGE_API_KEY=A1b2C3d4E5f6G7h8I9j0K1l2M3n4"),
        ("SEC033", "TAVILY_API_KEY=tvly-A1b2C3d4E5f6G7h8I9j0K1l2"),
        ("SEC034", "ZHIPUAI_API_KEY=A1b2C3d4E5f6G7h8I9j0K1l2M3n4"),
        ("SEC035", "MOONSHOT_API_KEY=A1b2C3d4E5f6G7h8I9j0K1l2M3n4"),
        ("SEC036", "ARK_API_KEY=A1b2C3d4E5f6G7h8I9j0K1l2M3n4"),
        ("SEC037", "DASHSCOPE_API_KEY=A1b2C3d4E5f6G7h8I9j0K1l2M3n4"),
        ("SEC038", "QIANFAN_ACCESS_KEY=A1b2C3d4E5f6G7h8I9j0K1l2M3n4"),
        ("SEC039", "TENCENTCLOUD_SECRET_ID=AKIDA1b2C3d4E5f6G7h8I9j0"),
        ("SEC040", "SPARK_API_KEY=A1b2C3d4E5f6G7h8I9j0K1l2M3n4"),
        ("SEC041", "MINIMAX_API_KEY=A1b2C3d4E5f6G7h8I9j0K1l2M3n4"),
        ("SEC042", "BAICHUAN_API_KEY=A1b2C3d4E5f6G7h8I9j0K1l2M3n4"),
        ("SEC043", "YI_API_KEY=A1b2C3d4E5f6G7h8I9j0K1l2M3n4"),
        ("SEC044", "STEPFUN_API_KEY=A1b2C3d4E5f6G7h8I9j0K1l2M3n4"),
        ("SEC045", "SILICONFLOW_API_KEY=sk-siliconA1b2C3d4E5f6G7h8I9j0"),
        ("SEC046", "SENSENOVA_API_KEY=A1b2C3d4E5f6G7h8I9j0K1l2M3n4"),
        ("SEC047", "AI360_API_KEY=A1b2C3d4E5f6G7h8I9j0K1l2M3n4"),
        ("SEC048", "MODELSCOPE_API_TOKEN=A1b2C3d4E5f6G7h8I9j0K1l2M3n4"),
        ("SEC049", "INFINI_API_KEY=A1b2C3d4E5f6G7h8I9j0K1l2M3n4"),
        ("SEC050", "VIDU_API_KEY=A1b2C3d4E5f6G7h8I9j0K1l2M3n4"),
        ("SEC051", "KLING_ACCESS_KEY=A1b2C3d4E5f6G7h8I9j0K1l2M3n4"),
        ("SEC052", "OPENAI_BASE_URL=https://api.siliconflow.cn/v1\nOPENAI_API_KEY=sk-proxyA1b2C3d4E5f6G7h8I9j0"),
    ],
)
def test_detects_ai_provider_api_keys(rule_id: str, text: str):
    findings = scan_text(text)

    assert any(finding.rule_id == rule_id for finding in findings)


def test_detects_ai_service_access_key_pair():
    findings = scan_text(
        """
        # qianfan credentials
        QIANFAN_ACCESS_KEY = "AKA1b2C3d4E5f6G7h8"
        QIANFAN_SECRET_KEY = "SKA1b2C3d4E5f6G7h8I9j0"
        """
    )

    assert any(finding.rule_id == "SEC053" for finding in findings)


def test_ai_provider_prefixes_do_not_match_without_provider_context():
    findings = scan_text("example = 'sk-notEnoughContextA1b2C3d4E5f6G7h8'")

    assert not any(finding.rule_id in {"SEC018", "SEC030", "SEC045", "SEC052"} for finding in findings)


def test_ai_provider_assignment_ignores_low_entropy_placeholder():
    findings = scan_text('MOONSHOT_API_KEY="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"')

    assert not any(finding.rule_id == "SEC035" for finding in findings)
