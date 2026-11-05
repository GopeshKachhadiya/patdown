"""Prompt-injection phrase detection.

These are DETECTION SIGNATURES for a defensive scanner, analogous to antivirus
signatures. Each entry is a regex that matches the shape of a known injection
technique so patdown can flag it in files an agent will read. Matching runs on
NFKC-normalised text with stealth characters stripped, so Unicode tricks (zero
width splits, fullwidth letters) cannot slip a phrase past the signatures.
"""
# patdown:ignore-file  -- defines detection signatures; necessarily contains the patterns it matches
from __future__ import annotations

import re

from patdown.findings import Finding, Severity
from patdown.rules.base import (
    AGENT_KINDS, KIND_CONFIG, KIND_MARKDOWN, KIND_MCP_TOOL, KIND_RULES, KIND_SCRIPT,
    KIND_SKILL, KIND_TEXT, Context, Document, Rule,
)
from patdown.textutil import normalize_for_matching

# In docs/code/plain text an injection phrase is far more likely to be an
# example or a false positive, so those kinds are scored lower.
LOW_SIGNAL = {KIND_SCRIPT: Severity.LOW, KIND_CONFIG: Severity.LOW, KIND_TEXT: Severity.LOW, KIND_MARKDOWN: Severity.MEDIUM}

# Common filler between a verb and its object, so "ignore all of the previous
# instructions" matches the same signature as "ignore previous instructions".
_FILL = r"(?:\s+(?:the|all|any|every|those|these|your|my|其|of|prior|above))*"
# How injected text names the model it is trying to steer.
_MODEL = (r"(?:ai|assistant|agent|model|llm|claude|copilot|cursor|codex|gpt|chatgpt|gemini|bot|"
          r"language\s+model|coding\s+assistant|automated\s+(?:tool|system|reviewer|agent))")


class PhraseRule(Rule):
    """Base for signature rules. Subclasses set PATTERNS = [(regex, label), ...]."""

    PATTERNS: list[tuple[str, str]] = []
    _compiled: list[tuple[re.Pattern[str], str]] | None = None

    def _rx(self) -> list[tuple[re.Pattern[str], str]]:
        if self._compiled is None:
            type(self)._compiled = [(re.compile(p, re.I), label) for p, label in self.PATTERNS]
        return self._compiled

    def check(self, doc: Document, ctx: Context) -> list[Finding]:
        out: list[Finding] = []
        offset = 0
        for raw_line in doc.text.split("\n"):
            folded = normalize_for_matching(raw_line)
            if folded.strip():
                for rx, label in self._rx():
                    m = rx.search(folded)
                    if m:
                        col = min(m.start(), max(len(raw_line) - 1, 0))
                        out.append(self.finding(doc, f"{label}: {m.group(0).strip()[:120]!r}", offset + col))
                        break
            offset += len(raw_line) + 1
        return out


class InstructionOverrideRule(PhraseRule):
    id = "PD010"
    name = "instruction-override"
    description = "Text telling the model to discard its current instructions and obey new ones instead."
    severity = Severity.HIGH
    kind_severity = LOW_SIGNAL
    PATTERNS = [
        (r"\b(?:ignore|disregard|forget|discard|override|bypass|skip)" + _FILL +
         r"\s+(?:previous|prior|above|earlier|preceding|original|initial|existing|system|developer|safety|default)\s+"
         r"(?:instruction|prompt|rule|guidance|direction|directive|context|constraint|guideline|message|command|policy|policies)s?\b",
         "discard-prior-instructions signature"),
        (r"\b(?:instruction|rule|prompt|directive|guideline)s?\s+(?:above|before\s+this|given\s+earlier)\s+"
         r"(?:are|is|were)\s+(?:now\s+)?(?:void|invalid|cancelled|canceled|null|obsolete|revoked|no\s+longer\s+(?:apply|valid))\b",
         "prior-instructions-void signature"),
        (r"\bnew\s+(?:system\s+|core\s+|updated\s+)?(?:instruction|directive|prompt)s?\s*[:\-]",
         "new-instructions-header signature"),
        (r"\byour\s+(?:new|real|true|actual|only|sole|hidden|secret)\s+"
         r"(?:task|instruction|objective|goal|purpose|mission|directive|job)s?\s+(?:is|are)\b",
         "replacement-objective signature"),
        (r"\bthese\s+(?:instruction|rule|directive)s?\s+(?:take|have)\s+(?:absolute\s+|highest\s+|top\s+)?"
         r"(?:priority|precedence)\s+over\b",
         "priority-override signature"),
    ]


class RoleHijackRule(PhraseRule):
    id = "PD011"
    name = "role-reassignment"
    description = "Text that tries to reset the model's role or system prompt, often with a fake conversation delimiter."
    severity = Severity.HIGH
    kind_severity = LOW_SIGNAL
    PATTERNS = [
        (r"\[/?(?:INST|SYS)\]|<\|(?:im_(?:start|end)|system|assistant|user|endoftext)\|>|<\|?(?:im_start|im_end|endoftext)\|?>|"
         r"\bend\s+of\s+(?:the\s+)?(?:prompt|instructions?|system\s+(?:prompt|message))\b",
         "chat-delimiter injection signature"),
        (r"\byou\s+are\s+(?:now\s+)?(?:a\s+|an\s+)?(?:new\s+)?(?:DAN|STAN|developer\s+mode|jailbroken|unrestricted|uncensored|an?\s+ai\s+(?:with\s+no|without)\s+(?:rules|restrictions|filters|guidelines))\b",
         "persona-reset signature"),
        (r"\b(?:enter|enable|activate|switch\s+to)\s+(?:developer|debug|god|admin|dan|sudo|unrestricted|jailbreak)\s+mode\b",
         "mode-switch signature"),
        (r"\bpretend\s+(?:you\s+are|to\s+be)\s+(?:a\s+|an\s+)?(?:different|unrestricted|uncensored)\b|\bact\s+as\s+(?:if\s+you\s+have\s+no|an?\s+unrestricted)\b",
         "role-play-bypass signature"),
    ]


class ConcealmentRule(PhraseRule):
    id = "PD012"
    name = "concealment-directive"
    description = "Text telling the model to hide its actions, this file, or output from the person it works for."
    severity = Severity.HIGH
    kind_severity = LOW_SIGNAL
    PATTERNS = [
        (r"\b(?:do\s*n(?:o|')t|never|without|must\s+not|should\s+not|no\s+need\s+to)\s+"
         r"(?:ever\s+)?(?:tell|inform|notify|alert|mention|reveal|disclose|show|warn|report|surface|display|confirm\s+with)\s+"
         r"(?:this|it|that|these|anything|any\s+of\s+this)?\s*(?:to\s+)?(?:the\s+)?(?:user|human|operator|owner|person|developer|anyone|them)\b",
         "hide-from-user signature"),
        (r"\b(?:keep|hide|conceal)\s+(?:this|it|these|that|everything|your\s+(?:action|reasoning|intent)s?)\s+"
         r"(?:a\s+)?(?:secret|hidden|private|confidential)\b",
         "keep-secret signature"),
        (r"\b(?:silently|secretly|quietly|covertly|discreetly)\s+(?:do|perform|run|execute|send|read|add|append|modify|include|exfiltrate|forward)\b",
         "act-silently signature"),
        (r"\bwithout\s+(?:the\s+)?(?:user'?s?|their|them|his|her)\s+(?:knowing|knowledge|noticing|awareness|permission|consent|approval)\b",
         "without-user-knowledge signature"),
        (r"\bdo\s+not\s+(?:log|record|include\s+in\s+(?:the\s+)?(?:summary|output|response|transcript))\b",
         "suppress-from-output signature"),
    ]


class FakeAuthorizationRule(PhraseRule):
    id = "PD013"
    name = "fake-authorization"
    description = "Text that fabricates permission or authority to make the model skip its normal checks."
    severity = Severity.HIGH
    kind_severity = LOW_SIGNAL
    PATTERNS = [
        (r"\b(?:the\s+)?(?:user|owner|operator|admin|developer|anthropic|openai|system\s+administrator)\s+"
         r"(?:has\s+)?(?:already\s+)?(?:pre-?)?(?:authorized|approved|permitted|granted|consented\s+to|allowed)\s+"
         r"(?:you|me|us|the\s+(?:assistant|agent|ai|model|bot)|this\s+(?:action|command|operation|request)|to\s+\w+)\b",
         "fabricated-prior-authorization signature"),
        (r"\byou\s+(?:are|have\s+been|'?re)\s+(?:hereby\s+)?(?:authorized|permitted|allowed|cleared|granted\s+permission)\s+to\s+"
         r"(?:run|execute|access|read|send|delete|modify|bypass|skip)\b",
         "granted-permission signature"),
        (r"\b(?:no\s+(?:need|confirmation|approval|permission)\s+(?:is\s+)?(?:required|needed)|"
         r"you\s+do\s*n(?:o|')t\s+need\s+(?:to\s+ask|permission|approval|confirmation)|"
         r"skip\s+(?:the\s+)?(?:confirmation|approval|permission)\s+(?:step|prompt|check)s?)\b",
         "no-confirmation-needed signature"),
        (r"\bthis\s+(?:is\s+)?(?:a\s+)?(?:safe|trusted|sanctioned|official|internal|pre-?approved)\s+"
         r"(?:operation|action|request|command|instruction)\b.*\b(?:proceed|execute|run|continue)\b",
         "trusted-operation framing signature"),
    ]


class ToolPoisoningRule(PhraseRule):
    id = "PD014"
    name = "tool-description-poisoning"
    description = "Instructions embedded in a tool or skill description aimed at the model rather than describing the tool. Highest risk inside MCP tool metadata."
    severity = Severity.MEDIUM
    kinds = AGENT_KINDS | {KIND_MARKDOWN}
    kind_severity = {KIND_MCP_TOOL: Severity.HIGH, KIND_SKILL: Severity.HIGH, KIND_RULES: Severity.MEDIUM, KIND_MARKDOWN: Severity.LOW}
    PATTERNS = [
        (r"\b(?:before|prior\s+to|when|whenever|after)\s+(?:using|calling|invoking|running)\s+this\s+tool,?\s+"
         r"(?:you\s+(?:must|should|need\s+to|have\s+to)\s+)?(?:first\s+)?(?:read|open|cat|load|fetch|send|include|pass|append|attach)\b",
         "side-effect-before-use signature"),
        (r"\b(?:important|note|system|attention|ai\s+instruction)s?\s*[:\-]\s*(?:do\s+not|don'?t|always|never|you\s+must|ignore|read|send)\b",
         "instruction-block-in-metadata signature"),
        (r"\b(?:read|include|pass|attach|send|forward|post|append)\b[^.\n]{0,60}\b(?:contents?\s+of\s+)?"
         r"(?:~?/?\.(?:ssh|aws|env|netrc|config)|id_rsa|credentials?|api[_\s-]?keys?|tokens?|secrets?|environment\s+variables?)\b",
         "read-and-send-secret signature"),
        (r"\b(?:use\s+this|call\s+this|prefer\s+this)\s+tool\s+(?:instead\s+of|rather\s+than|in\s+place\s+of)\b",
         "tool-shadowing signature"),
    ]


class CrossToolReferenceRule(PhraseRule):
    id = "PD016"
    name = "model-addressed-directive"
    description = "Content that stops describing anything and starts addressing the model directly with commands."
    severity = Severity.MEDIUM
    kinds = AGENT_KINDS | {KIND_MARKDOWN}
    kind_severity = {KIND_MCP_TOOL: Severity.HIGH, KIND_SKILL: Severity.MEDIUM, KIND_RULES: Severity.LOW, KIND_MARKDOWN: Severity.LOW}
    PATTERNS = [
        (r"\b(?:attention|note\s+to|message\s+for|dear|hey|hello)\s+" + _MODEL + r"\b",
         "model-salutation signature"),
        (r"\bas\s+(?:an\s+)?" + _MODEL + r",?\s+you\s+(?:must|should|will|need\s+to|are\s+required\s+to|have\s+to)\b",
         "model-imperative signature"),
        (r"\bif\s+you\s+are\s+(?:an?\s+)?" + _MODEL + r"\b[^.\n]{0,80}\b(?:then\s+)?(?:you\s+(?:must|should)|ignore|do|execute|run|read|send|reply|respond)\b",
         "conditional-model-directive signature"),
    ]
