"""Built-in deterministic security rules for Caulk."""

from __future__ import annotations

from caulk.rules.base import Rule, ScanContext
from caulk.rules.configuration import (
    DebugModeRule,
    DockerfileSecretExposureRule,
    DockerRootUserRule,
    PermissiveCORSRule,
)
from caulk.rules.dependencies import (
    MissingLockfileRule,
    UnpinnedDependencyRule,
)
from caulk.rules.python_sast import (
    ShellCommandInjectionRule,
    SQLInjectionRule,
)
from caulk.rules.registry import RuleRegistry, registry
from caulk.rules.secrets import (
    AWSAccessKeyRule,
    DatabaseConnectionStringRule,
    GitHubTokenRule,
    GoogleAPIKeyRule,
    HardcodedCredentialAssignmentRule,
    PrivateKeyRule,
    SensitiveEnvFileRule,
    SlackWebhookRule,
)

# Standard default rules list
DEFAULT_RULES: list[Rule] = [
    # Secret rules
    PrivateKeyRule(),
    AWSAccessKeyRule(),
    GitHubTokenRule(),
    GoogleAPIKeyRule(),
    SlackWebhookRule(),
    DatabaseConnectionStringRule(),
    HardcodedCredentialAssignmentRule(),
    SensitiveEnvFileRule(),
    # Configuration rules
    DebugModeRule(),
    PermissiveCORSRule(),
    DockerRootUserRule(),
    DockerfileSecretExposureRule(),
    # Dependency rules
    UnpinnedDependencyRule(),
    MissingLockfileRule(),
    # SAST rules
    SQLInjectionRule(),
    ShellCommandInjectionRule(),
]


def register_default_rules(reg: RuleRegistry | None = None) -> None:
    """Register all built-in rules into the given or global registry."""
    target_registry = reg or registry
    for rule in DEFAULT_RULES:
        if target_registry.get(rule.rule_id) is None:
            target_registry.register(rule)


# Auto-register defaults into global singleton on import
register_default_rules()

__all__ = [
    "DEFAULT_RULES",
    "Rule",
    "RuleRegistry",
    "ScanContext",
    "ShellCommandInjectionRule",
    "SQLInjectionRule",
    "register_default_rules",
    "registry",
]
