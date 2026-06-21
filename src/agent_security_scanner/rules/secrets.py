from __future__ import annotations

import re
from dataclasses import dataclass
from math import log2
from typing import Sequence

from agent_security_scanner.models import Category, FileContext, Finding, Severity
from agent_security_scanner.rules.base import Rule
from agent_security_scanner.utils.text import line_col_from_offset, mask_secret


@dataclass(frozen=True)
class SecretPattern:
    rule_id: str
    title: str
    regex: re.Pattern[str]
    severity: Severity = Severity.CRITICAL
    group: int = 0
    require_context: bool = False
    min_entropy: float | None = None


@dataclass(frozen=True)
class AIProviderSecretPattern:
    rule_id: str
    provider: str
    aliases: tuple[str, ...]
    variable_names: tuple[str, ...]
    domains: tuple[str, ...] = ()
    context_keywords: tuple[str, ...] = ()
    token_prefixes: tuple[str, ...] = ()
    token_regexes: tuple[re.Pattern[str], ...] = ()
    severity: Severity = Severity.CRITICAL
    min_entropy: float = 3.5
    min_value_length: int = 20
    require_context: bool = True
    confidence: str = "high"


@dataclass(frozen=True)
class AIProviderKeyPairPattern:
    rule_id: str
    provider: str
    public_key_names: tuple[str, ...]
    private_key_names: tuple[str, ...]
    context_keywords: tuple[str, ...] = ()
    severity: Severity = Severity.HIGH
    min_entropy: float = 3.0
    min_value_length: int = 8
    max_line_distance: int = 8


AI_PROVIDER_SECRET_PATTERNS: tuple[AIProviderSecretPattern, ...] = (
    AIProviderSecretPattern(
        "SEC018",
        "DeepSeek",
        ("deepseek",),
        ("DEEPSEEK_API_KEY",),
        ("api.deepseek.com",),
        ("deepseek-chat", "deepseek-reasoner"),
        ("sk-",),
    ),
    AIProviderSecretPattern(
        "SEC019",
        "Groq",
        ("groq",),
        ("GROQ_API_KEY",),
        ("api.groq.com",),
        ("llama3-groq", "mixtral"),
        ("gsk_",),
    ),
    AIProviderSecretPattern(
        "SEC020",
        "xAI / Grok",
        ("xai", "grok"),
        ("XAI_API_KEY", "GROK_API_KEY"),
        ("api.x.ai",),
        ("grok-",),
        ("xai-",),
    ),
    AIProviderSecretPattern(
        "SEC021",
        "Perplexity",
        ("perplexity", "pplx"),
        ("PERPLEXITY_API_KEY", "PPLX_API_KEY"),
        ("api.perplexity.ai",),
        ("sonar",),
        ("pplx-",),
        severity=Severity.HIGH,
    ),
    AIProviderSecretPattern(
        "SEC022",
        "OpenRouter",
        ("openrouter",),
        ("OPENROUTER_API_KEY",),
        ("openrouter.ai",),
        ("openrouter",),
        ("sk-or-",),
        severity=Severity.HIGH,
    ),
    AIProviderSecretPattern(
        "SEC023",
        "Together AI",
        ("together", "togetherai"),
        ("TOGETHER_API_KEY", "TOGETHERAI_API_KEY"),
        ("api.together.xyz",),
        ("together ai",),
        severity=Severity.HIGH,
    ),
    AIProviderSecretPattern(
        "SEC024",
        "Fireworks AI",
        ("fireworks", "fireworksai"),
        ("FIREWORKS_API_KEY", "FIREWORKS_AI_API_KEY"),
        ("api.fireworks.ai",),
        ("fireworks ai",),
        severity=Severity.HIGH,
    ),
    AIProviderSecretPattern(
        "SEC025",
        "Mistral AI",
        ("mistral",),
        ("MISTRAL_API_KEY", "MISTRALAI_API_KEY"),
        ("api.mistral.ai",),
        ("mistral",),
        severity=Severity.HIGH,
    ),
    AIProviderSecretPattern(
        "SEC026",
        "Cohere",
        ("cohere",),
        ("COHERE_API_KEY",),
        ("api.cohere.ai",),
        ("command-r",),
        severity=Severity.HIGH,
    ),
    AIProviderSecretPattern(
        "SEC027",
        "Replicate",
        ("replicate",),
        ("REPLICATE_API_TOKEN", "REPLICATE_API_KEY"),
        ("api.replicate.com",),
        ("replicate",),
        ("r8_",),
        severity=Severity.HIGH,
    ),
    AIProviderSecretPattern(
        "SEC028",
        "Azure OpenAI",
        ("azure openai", "azure ai"),
        ("AZURE_OPENAI_API_KEY", "AZURE_AI_API_KEY"),
        ("openai.azure.com", "cognitiveservices.azure.com"),
        ("AZURE_OPENAI_ENDPOINT", "api-key"),
        severity=Severity.HIGH,
    ),
    AIProviderSecretPattern(
        "SEC029",
        "NVIDIA NIM / NGC",
        ("nvidia nim", "ngc", "nvidia"),
        ("NVIDIA_API_KEY", "NGC_API_KEY", "NVIDIA_NIM_API_KEY"),
        ("integrate.api.nvidia.com", "api.nvcf.nvidia.com"),
        ("nvidia nim", "ngc"),
        severity=Severity.HIGH,
    ),
    AIProviderSecretPattern(
        "SEC030",
        "Stability AI",
        ("stability", "stabilityai"),
        ("STABILITY_API_KEY", "STABILITYAI_API_KEY"),
        ("api.stability.ai",),
        ("stable-diffusion",),
        ("sk-",),
        severity=Severity.HIGH,
    ),
    AIProviderSecretPattern(
        "SEC031",
        "ElevenLabs",
        ("elevenlabs", "eleven labs"),
        ("ELEVENLABS_API_KEY", "ELEVEN_LABS_API_KEY", "XI_API_KEY"),
        ("api.elevenlabs.io",),
        ("xi-api-key",),
        severity=Severity.HIGH,
    ),
    AIProviderSecretPattern(
        "SEC032",
        "Voyage AI",
        ("voyage", "voyageai"),
        ("VOYAGE_API_KEY", "VOYAGEAI_API_KEY"),
        ("api.voyageai.com",),
        ("voyage-",),
        severity=Severity.HIGH,
    ),
    AIProviderSecretPattern(
        "SEC033",
        "Tavily",
        ("tavily",),
        ("TAVILY_API_KEY",),
        ("api.tavily.com",),
        ("tavily",),
        ("tvly-",),
        severity=Severity.HIGH,
    ),
    AIProviderSecretPattern(
        "SEC034",
        "Zhipu GLM / Z.ai",
        ("zhipu", "zhipuai", "z.ai", "glm", "bigmodel"),
        ("ZHIPUAI_API_KEY", "ZAI_API_KEY", "BIGMODEL_API_KEY", "GLM_API_KEY"),
        ("open.bigmodel.cn", "bigmodel.cn"),
        ("glm-4", "chatglm"),
    ),
    AIProviderSecretPattern(
        "SEC035",
        "Kimi / Moonshot",
        ("kimi", "moonshot"),
        ("MOONSHOT_API_KEY", "KIMI_API_KEY"),
        ("api.moonshot.cn", "platform.moonshot.cn"),
        ("moonshot-v1", "kimi"),
    ),
    AIProviderSecretPattern(
        "SEC036",
        "Volcengine Ark / Doubao / Seedance",
        ("volcengine", "ark", "doubao", "seedance", "seedream"),
        ("ARK_API_KEY", "VOLCENGINE_API_KEY", "DOUBAO_API_KEY", "SEEDANCE_API_KEY", "SEEDREAM_API_KEY"),
        ("ark.cn-beijing.volces.com", "volces.com"),
        ("doubao", "seedance", "seedream", "volcengine"),
    ),
    AIProviderSecretPattern(
        "SEC037",
        "Alibaba Bailian / Qwen / DashScope",
        ("dashscope", "qwen", "tongyi", "bailian", "aliyun"),
        ("DASHSCOPE_API_KEY", "QWEN_API_KEY", "BAILIAN_API_KEY", "TONGYI_API_KEY"),
        ("dashscope.aliyuncs.com", "bailian.console.aliyun.com"),
        ("qwen", "dashscope", "bailian"),
    ),
    AIProviderSecretPattern(
        "SEC038",
        "Baidu Qianfan / ERNIE",
        ("qianfan", "baidu", "ernie", "wenxin"),
        ("QIANFAN_ACCESS_KEY", "QIANFAN_SECRET_KEY", "BAIDU_API_KEY", "BAIDU_SECRET_KEY"),
        ("qianfan.baidubce.com", "aip.baidubce.com"),
        ("ernie", "wenxin", "qianfan"),
        severity=Severity.HIGH,
    ),
    AIProviderSecretPattern(
        "SEC039",
        "Tencent Hunyuan",
        ("tencent", "hunyuan", "tencentcloud"),
        ("TENCENTCLOUD_SECRET_ID", "TENCENTCLOUD_SECRET_KEY", "HUNYUAN_API_KEY"),
        ("hunyuan.tencentcloudapi.com",),
        ("hunyuan", "tencentcloud"),
        ("AKID",),
        severity=Severity.HIGH,
        min_entropy=2.5,
    ),
    AIProviderSecretPattern(
        "SEC040",
        "iFlytek Spark",
        ("iflytek", "xfyun", "spark", "xinghuo"),
        ("SPARK_API_KEY", "XF_API_KEY", "XFYUN_API_KEY", "SPARK_API_SECRET", "XFYUN_API_SECRET"),
        ("spark-api.xf-yun.com", "spark-api.xf-yun.com.cn", "xfyun.cn"),
        ("spark", "iflytek", "apiSecret"),
        severity=Severity.HIGH,
    ),
    AIProviderSecretPattern(
        "SEC041",
        "MiniMax / Hailuo / Minmo",
        ("minimax", "hailuo", "minmo"),
        ("MINIMAX_API_KEY", "HAILUO_API_KEY", "MINMO_API_KEY"),
        ("api.minimaxi.com", "api.minimax.chat"),
        ("minimax", "hailuo", "minmo"),
        severity=Severity.HIGH,
    ),
    AIProviderSecretPattern(
        "SEC042",
        "Baichuan AI",
        ("baichuan",),
        ("BAICHUAN_API_KEY", "BAICHUAN_SECRET_KEY"),
        ("api.baichuan-ai.com", "platform.baichuan-ai.com"),
        ("baichuan",),
        severity=Severity.HIGH,
    ),
    AIProviderSecretPattern(
        "SEC043",
        "01.AI / Yi",
        ("01.ai", "lingyiwanwu", "yi"),
        ("YI_API_KEY", "LINGYIWANWU_API_KEY", "ZEROONE_API_KEY", "ONEAI_API_KEY"),
        ("api.lingyiwanwu.com", "platform.lingyiwanwu.com"),
        ("yi-large", "lingyiwanwu"),
        severity=Severity.HIGH,
    ),
    AIProviderSecretPattern(
        "SEC044",
        "StepFun",
        ("stepfun", "step"),
        ("STEP_API_KEY", "STEPFUN_API_KEY"),
        ("api.stepfun.com",),
        ("step-", "stepfun"),
        severity=Severity.HIGH,
    ),
    AIProviderSecretPattern(
        "SEC045",
        "SiliconFlow",
        ("siliconflow", "silicon flow"),
        ("SILICONFLOW_API_KEY",),
        ("api.siliconflow.cn",),
        ("siliconflow",),
        ("sk-",),
        severity=Severity.HIGH,
    ),
    AIProviderSecretPattern(
        "SEC046",
        "SenseNova",
        ("sensenova", "sensetime"),
        ("SENSENOVA_API_KEY", "SENSENOVA_ACCESS_KEY_ID", "SENSENOVA_SECRET_ACCESS_KEY"),
        ("api.sensenova.cn", "platform.sensenova.cn"),
        ("sensenova", "sensetime"),
        severity=Severity.HIGH,
    ),
    AIProviderSecretPattern(
        "SEC047",
        "360 Zhinao",
        ("360", "ai360", "zhinao"),
        ("AI360_API_KEY", "ZHI_NAO_API_KEY", "ZHINAO_API_KEY", "QIHOO_API_KEY"),
        ("api.360.cn", "ai.360.cn"),
        ("zhinao", "360"),
        severity=Severity.HIGH,
    ),
    AIProviderSecretPattern(
        "SEC048",
        "ModelScope",
        ("modelscope", "moda"),
        ("MODELSCOPE_API_TOKEN", "MODELSCOPE_API_KEY"),
        ("modelscope.cn", "api-inference.modelscope.cn"),
        ("modelscope",),
        severity=Severity.HIGH,
    ),
    AIProviderSecretPattern(
        "SEC049",
        "Infini-AI",
        ("infini", "infini-ai", "infiniai"),
        ("INFINI_API_KEY", "INFINI_AI_API_KEY", "INFINIAI_API_KEY"),
        ("cloud.infini-ai.com", "api.infini-ai.com"),
        ("infini-ai",),
        severity=Severity.HIGH,
    ),
    AIProviderSecretPattern(
        "SEC050",
        "Vidu / Shengshu",
        ("vidu", "shengshu"),
        ("VIDU_API_KEY", "SHENGSHU_API_KEY"),
        ("api.vidu.cn", "shengshu-ai.com"),
        ("vidu", "shengshu"),
        severity=Severity.HIGH,
    ),
    AIProviderSecretPattern(
        "SEC051",
        "Kling AI",
        ("kling", "klingai", "kuaishou"),
        ("KLING_ACCESS_KEY", "KLING_SECRET_KEY", "KLINGAI_API_KEY", "KWAI_API_KEY"),
        ("api.klingai.com", "kling.kuaishou.com"),
        ("kling", "kuaishou"),
        severity=Severity.HIGH,
    ),
    AIProviderSecretPattern(
        "SEC052",
        "OpenAI-compatible proxy",
        ("openai compatible", "openai-compatible", "one-api", "new-api", "litellm"),
        ("OPENAI_API_KEY", "OPENAI_COMPATIBLE_API_KEY"),
        (
            "api.deepseek.com",
            "api.moonshot.cn",
            "ark.cn-beijing.volces.com",
            "dashscope.aliyuncs.com",
            "api.siliconflow.cn",
            "openrouter.ai",
            "one-api",
            "new-api",
            "litellm",
        ),
        ("OPENAI_BASE_URL", "BASE_URL", "api_base", "base_url"),
        ("sk-",),
        severity=Severity.HIGH,
    ),
)


AI_PROVIDER_KEY_PAIR_PATTERNS: tuple[AIProviderKeyPairPattern, ...] = (
    AIProviderKeyPairPattern(
        "SEC053",
        "AI service access key pair",
        (
            "ACCESS_KEY_ID",
            "ACCESSKEYID",
            "ACCESS_KEY",
            "API_KEY",
            "APP_ID",
            "APPID",
            "SECRET_ID",
            "TENCENTCLOUD_SECRET_ID",
            "KLING_ACCESS_KEY",
            "SENSENOVA_ACCESS_KEY_ID",
            "QIANFAN_ACCESS_KEY",
        ),
        (
            "ACCESS_KEY_SECRET",
            "ACCESSKEYSECRET",
            "SECRET_ACCESS_KEY",
            "API_SECRET",
            "APP_SECRET",
            "APISECRET",
            "SECRET_KEY",
            "TENCENTCLOUD_SECRET_KEY",
            "KLING_SECRET_KEY",
            "SENSENOVA_SECRET_ACCESS_KEY",
            "QIANFAN_SECRET_KEY",
        ),
        (
            "qianfan",
            "baidu",
            "tencent",
            "hunyuan",
            "iflytek",
            "xfyun",
            "spark",
            "kling",
            "sensenova",
            "aliyun",
            "volcengine",
            "ai",
        ),
        Severity.HIGH,
    ),
)


class SecretsRule(Rule):
    patterns = [
        SecretPattern(
            "SEC001",
            "OpenAI API key detected",
            re.compile(r"\bsk-[A-Za-z0-9][A-Za-z0-9_-]{20,}\b"),
        ),
        SecretPattern(
            "SEC002",
            "GitHub token detected",
            re.compile(r"\b(?:ghp|gho|ghu|ghs)_[A-Za-z0-9_]{20,}\b|\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
        ),
        SecretPattern(
            "SEC003",
            "Anthropic API key detected",
            re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"),
        ),
        SecretPattern(
            "SEC004",
            "Bearer token detected",
            re.compile(r"(?i)\bAuthorization\s*:\s*Bearer\s+([A-Za-z0-9._~+/=-]{24,})"),
            Severity.HIGH,
            group=1,
        ),
        SecretPattern(
            "SEC005",
            "Private key block detected",
            re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
        ),
        SecretPattern(
            "SEC006",
            "AWS access key detected",
            re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
        ),
        SecretPattern(
            "SEC007",
            "Slack token detected",
            re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"),
        ),
        SecretPattern(
            "SEC008",
            "Discord token or webhook detected",
            re.compile(
                r"\b(?:mfa\.[A-Za-z0-9_-]{20,}|[A-Za-z0-9_-]{23,28}\.[A-Za-z0-9_-]{6,8}\.[A-Za-z0-9_-]{27,})\b"
                r"|https://discord(?:app)?\.com/api/webhooks/[0-9]{17,20}/[A-Za-z0-9_-]{40,}",
            ),
            require_context=True,
        ),
        SecretPattern(
            "SEC009",
            "Hugging Face token detected",
            re.compile(r"\bhf_[A-Za-z0-9]{30,}\b"),
        ),
        SecretPattern(
            "SEC010",
            "npm access token detected",
            re.compile(r"\bnpm_[A-Za-z0-9]{30,}\b"),
        ),
        SecretPattern(
            "SEC011",
            "PyPI API token detected",
            re.compile(r"\bpypi-[A-Za-z0-9_-]{40,}\b"),
        ),
        SecretPattern(
            "SEC012",
            "Stripe API key detected",
            re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}\b"),
        ),
        SecretPattern(
            "SEC013",
            "Google API key detected",
            re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
        ),
        SecretPattern(
            "SEC014",
            "Azure Storage connection string detected",
            re.compile(r"(?i)\bDefaultEndpointsProtocol=https?;AccountName=[^;\s]+;AccountKey=([A-Za-z0-9+/=]{40,})"),
            group=1,
        ),
        SecretPattern(
            "SEC015",
            "JWT detected",
            re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
            Severity.HIGH,
            require_context=True,
        ),
        SecretPattern(
            "SEC016",
            "Database URL with embedded password detected",
            re.compile(r"(?i)\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis)://[^:\s/@]+:([^@\s]{8,})@[^)\s\"']+"),
            Severity.HIGH,
            group=1,
        ),
        SecretPattern(
            "SEC017",
            "Generic high-entropy credential detected",
            re.compile(r"(?i)\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|secret|password)\b\s*[:=]\s*[\"']?([A-Za-z0-9._~+/=-]{24,})[\"']?"),
            Severity.HIGH,
            group=1,
            min_entropy=3.5,
        ),
    ]
    ai_provider_patterns: tuple[AIProviderSecretPattern, ...] = AI_PROVIDER_SECRET_PATTERNS
    ai_provider_key_pair_patterns: tuple[AIProviderKeyPairPattern, ...] = AI_PROVIDER_KEY_PAIR_PATTERNS

    def scan(self, context: FileContext) -> list[Finding]:
        findings: list[Finding] = []
        for pattern in self.patterns:
            for match in pattern.regex.finditer(context.text):
                value = match.group(pattern.group) if pattern.group and match.groups() else match.group(0)
                if pattern.require_context and not _has_secret_context(context.text, match.start(), match.end()):
                    continue
                if pattern.min_entropy is not None and _shannon_entropy(value) < pattern.min_entropy:
                    continue
                line, column = line_col_from_offset(context.text, match.start(pattern.group or 0))
                findings.append(
                    Finding(
                        rule_id=pattern.rule_id,
                        title=pattern.title,
                        description="A credential-like value appears to be stored in source-controlled text.",
                        severity=pattern.severity,
                        category=Category.SECRETS,
                        file_path=context.relative_path,
                        line=line,
                        column=column,
                        evidence=mask_secret(value),
                        recommendation="Move the secret to a local environment variable or a dedicated secret manager, then rotate the exposed value.",
                    )
                )
        findings.extend(_scan_ai_provider_secrets(context, self.ai_provider_patterns))
        findings.extend(_scan_ai_provider_key_pairs(context, self.ai_provider_key_pair_patterns))
        return _dedupe(findings)


SECRET_CONTEXT_RE = re.compile(
    r"(?i)(token|secret|password|passwd|pwd|api[_-]?key|authorization|credential|webhook|discord|jwt|bearer)"
)


def _has_secret_context(text: str, start: int, end: int) -> bool:
    before = max(0, start - 96)
    after = min(len(text), end + 32)
    return bool(SECRET_CONTEXT_RE.search(text[before:after]))


def _scan_ai_provider_secrets(context: FileContext, patterns: Sequence[AIProviderSecretPattern]) -> list[Finding]:
    findings: list[Finding] = []
    for pattern in patterns:
        findings.extend(_scan_provider_token_prefixes(context, pattern))
        findings.extend(_scan_provider_token_regexes(context, pattern))
        findings.extend(_scan_provider_assignments(context, pattern))
    return findings


def _scan_provider_token_prefixes(context: FileContext, pattern: AIProviderSecretPattern) -> list[Finding]:
    findings: list[Finding] = []
    for prefix in pattern.token_prefixes:
        min_tail_length = max(1, pattern.min_value_length - len(prefix))
        regex = re.compile(rf"\b{re.escape(prefix)}[A-Za-z0-9._~+/=-]{{{min_tail_length},}}\b")
        for match in regex.finditer(context.text):
            value = match.group(0)
            if pattern.require_context and not _has_provider_context(context.text, match.start(), match.end(), pattern):
                continue
            if _shannon_entropy(value) < pattern.min_entropy:
                continue
            findings.append(_provider_finding(context, pattern, value, match.start()))
    return findings


def _scan_provider_token_regexes(context: FileContext, pattern: AIProviderSecretPattern) -> list[Finding]:
    findings: list[Finding] = []
    for regex in pattern.token_regexes:
        for match in regex.finditer(context.text):
            value = match.group(1) if match.groups() else match.group(0)
            if pattern.require_context and not _has_provider_context(context.text, match.start(), match.end(), pattern):
                continue
            if _shannon_entropy(value) < pattern.min_entropy:
                continue
            findings.append(_provider_finding(context, pattern, value, match.start(1 if match.groups() else 0)))
    return findings


def _scan_provider_assignments(context: FileContext, pattern: AIProviderSecretPattern) -> list[Finding]:
    findings: list[Finding] = []
    for variable in pattern.variable_names:
        regex = re.compile(
            rf"(?i)(?:export\s+)?[\"']?\b{re.escape(variable)}\b[\"']?\s*(?:[:=]|=>)\s*[\"']?([A-Za-z0-9._~+/=-]{{{pattern.min_value_length},}})[\"']?"
        )
        for match in regex.finditer(context.text):
            value = match.group(1)
            if _shannon_entropy(value) < pattern.min_entropy:
                continue
            findings.append(_provider_finding(context, pattern, value, match.start(1)))
    return findings


def _has_provider_context(text: str, start: int, end: int, pattern: AIProviderSecretPattern) -> bool:
    before = max(0, start - 160)
    after = min(len(text), end + 96)
    window = text[before:after].lower()
    markers = [
        pattern.provider.lower(),
        *(alias.lower() for alias in pattern.aliases),
        *(domain.lower() for domain in pattern.domains),
        *(keyword.lower() for keyword in pattern.context_keywords),
    ]
    markers.extend(variable.lower() for variable in pattern.variable_names)
    return any(marker and marker in window for marker in markers)


def _provider_finding(context: FileContext, pattern: AIProviderSecretPattern, value: str, offset: int) -> Finding:
    line, column = line_col_from_offset(context.text, offset)
    return Finding(
        rule_id=pattern.rule_id,
        title=f"{pattern.provider} API key detected",
        description=f"A credential-like value for {pattern.provider} appears to be stored in source-controlled text.",
        severity=pattern.severity,
        category=Category.SECRETS,
        file_path=context.relative_path,
        line=line,
        column=column,
        evidence=mask_secret(value),
        recommendation=f"Move the {pattern.provider} key to a local environment variable or a dedicated secret manager, then rotate the exposed value.",
    )


def _scan_ai_provider_key_pairs(context: FileContext, patterns: Sequence[AIProviderKeyPairPattern]) -> list[Finding]:
    findings: list[Finding] = []
    assignments = _collect_assignments(context.text)
    for pattern in patterns:
        public_matches = [item for item in assignments if _key_name_matches(item[0], pattern.public_key_names)]
        private_matches = [item for item in assignments if _key_name_matches(item[0], pattern.private_key_names)]
        for public_name, public_value, public_line, public_offset in public_matches:
            for private_name, private_value, private_line, _private_offset in private_matches:
                if abs(public_line - private_line) > pattern.max_line_distance:
                    continue
                if not _key_pair_has_context(context.text, public_offset, pattern):
                    continue
                if len(public_value) < pattern.min_value_length or len(private_value) < pattern.min_value_length:
                    continue
                if _shannon_entropy(private_value) < pattern.min_entropy:
                    continue
                findings.append(
                    _key_pair_finding(
                        context,
                        pattern,
                        f"{public_name}=... {private_name}=...",
                        public_line,
                        public_offset,
                    )
                )
                break
    return findings


ASSIGNMENT_RE = re.compile(
    r"(?im)(?:^|[\s,{])(?:export\s+)?[\"']?([A-Z][A-Z0-9_]*(?:KEY|SECRET|TOKEN|ID|APPID))[\"']?\s*(?:[:=]|=>)\s*[\"']?([A-Za-z0-9._~+/=-]{6,})[\"']?"
)


def _collect_assignments(text: str) -> list[tuple[str, str, int, int]]:
    assignments: list[tuple[str, str, int, int]] = []
    for match in ASSIGNMENT_RE.finditer(text):
        key = match.group(1).upper()
        value = match.group(2)
        line, _column = line_col_from_offset(text, match.start(1))
        assignments.append((key, value, line, match.start(1)))
    return assignments


def _key_name_matches(value: str, candidates: tuple[str, ...]) -> bool:
    normalized = value.upper()
    return any(normalized == candidate.upper() or normalized.endswith("_" + candidate.upper()) for candidate in candidates)


def _key_pair_has_context(text: str, offset: int, pattern: AIProviderKeyPairPattern) -> bool:
    before = max(0, offset - 240)
    after = min(len(text), offset + 240)
    window = text[before:after].lower()
    return any(keyword.lower() in window for keyword in pattern.context_keywords)


def _key_pair_finding(
    context: FileContext,
    pattern: AIProviderKeyPairPattern,
    evidence: str,
    line: int,
    offset: int,
) -> Finding:
    _line, column = line_col_from_offset(context.text, offset)
    return Finding(
        rule_id=pattern.rule_id,
        title=f"{pattern.provider} detected",
        description="A paired access key and secret key for an AI or cloud AI service appear to be stored together.",
        severity=pattern.severity,
        category=Category.SECRETS,
        file_path=context.relative_path,
        line=line,
        column=column,
        evidence=evidence,
        recommendation="Move the access key pair to a local environment variable or a dedicated secret manager, then rotate the exposed values.",
    )


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {char: value.count(char) for char in set(value)}
    length = len(value)
    return -sum((count / length) * log2(count / length) for count in counts.values())


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, int | None, str | None]] = set()
    result: list[Finding] = []
    for finding in findings:
        key = (finding.rule_id, finding.file_path, finding.line, finding.evidence)
        if key in seen:
            continue
        seen.add(key)
        result.append(finding)
    return result
