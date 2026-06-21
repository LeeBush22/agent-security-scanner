from agent_security_scanner.rules.ai_tools import AIToolConfigRule
from agent_security_scanner.rules.filesystem import FilesystemRiskRule
from agent_security_scanner.rules.github_actions import GitHubActionsRule
from agent_security_scanner.rules.mcp import MCPConfigRule
from agent_security_scanner.rules.secrets import SecretsRule
from agent_security_scanner.rules.shell import ShellDangerRule
from agent_security_scanner.rules.supply_chain import SupplyChainRule

DEFAULT_RULES = [
    SecretsRule(),
    AIToolConfigRule(),
    MCPConfigRule(),
    ShellDangerRule(),
    GitHubActionsRule(),
    SupplyChainRule(),
    FilesystemRiskRule(),
]

__all__ = [
    "DEFAULT_RULES",
    "AIToolConfigRule",
    "FilesystemRiskRule",
    "GitHubActionsRule",
    "MCPConfigRule",
    "SecretsRule",
    "ShellDangerRule",
    "SupplyChainRule",
]
