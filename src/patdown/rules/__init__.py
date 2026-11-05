"""Rule registry. Every rule has a stable ID (PDxxx) used in baselines and SARIF."""
from __future__ import annotations

from patdown.rules.base import Rule
from patdown.rules.unicode_rules import (
    BidiRule, ConfusableRule, InvisibleUnicodeRule, LookalikeLettersRule,
    PrivateUseRule, TagSmugglingRule, VariationSelectorRule,
)
from patdown.rules.injection import (
    ConcealmentRule, CrossToolReferenceRule, FakeAuthorizationRule,
    InstructionOverrideRule, RoleHijackRule, ToolPoisoningRule,
)
from patdown.rules.exfil import DestructiveCommandRule, ExfilUrlRule, PipeToShellRule, SensitivePathRule
from patdown.rules.secrets import HardcodedSecretRule, SecretInConfigRule
from patdown.rules.encoded import EncodedPayloadRule
from patdown.rules.hidden_html import HiddenHtmlRule, LinkMismatchRule
from patdown.rules.mcp_config import McpConfigRule
from patdown.rules.hooks import HooksRule
from patdown.rules.skills import SkillRule

ALL_RULES: list[Rule] = [
    InvisibleUnicodeRule(),
    BidiRule(),
    TagSmugglingRule(),
    VariationSelectorRule(),
    PrivateUseRule(),
    ConfusableRule(),
    LookalikeLettersRule(),
    InstructionOverrideRule(),
    RoleHijackRule(),
    ConcealmentRule(),
    FakeAuthorizationRule(),
    ToolPoisoningRule(),
    CrossToolReferenceRule(),
    ExfilUrlRule(),
    PipeToShellRule(),
    SensitivePathRule(),
    DestructiveCommandRule(),
    HardcodedSecretRule(),
    SecretInConfigRule(),
    EncodedPayloadRule(),
    HiddenHtmlRule(),
    LinkMismatchRule(),
    McpConfigRule(),
    HooksRule(),
    SkillRule(),
]

# Rules re-run over decoded / embedded content (base64 blobs, hidden comments,
# tag-smuggled text, hook command strings, MCP server command lines, ...).
NESTED_RULE_IDS = {
    "PD010", "PD011", "PD012", "PD013", "PD014", "PD016",
    "PD020", "PD021", "PD022", "PD023", "PD030",
}

RULES_BY_ID: dict[str, Rule] = {r.id: r for r in ALL_RULES}


def rule_by_id(rule_id: str) -> Rule | None:
    return RULES_BY_ID.get(rule_id.upper())
