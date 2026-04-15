"""Rule filtering engine with conditional matching and context awareness.

Replaces the global rule application with a context-aware system that:
- Only applies rules when conditions are met
- Prioritizes relevant rules
- Avoids generic/noisy rules
- Provides explanations for rule matches
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from cryptograph.models import CryptoFinding, GraphNode


@dataclass
class RuleMatch:
    """Result of rule matching against a finding."""

    rule_id: str
    message: str
    priority: int  # Higher = more important to report
    is_actionable: bool  # Can user fix this?
    explanation: str  # Why does this rule apply?


class RuleEngine:
    """Evaluates and filters rules based on conditions."""

    def __init__(self, rules_config: dict[str, Any]):
        """Initialize with rules configuration.

        Args:
            rules_config: Dict with 'rules' list containing rule definitions.
        """
        self.rules = rules_config.get("rules", [])
        # Build index for fast lookup
        self.rules_by_id = {rule["id"]: rule for rule in self.rules}

    def match_rules(
        self,
        finding: CryptoFinding,
        node: GraphNode | None = None,
    ) -> list[RuleMatch]:
        """Find applicable rules for a finding.

        Args:
            finding: The cryptographic finding to evaluate.
            node: Optional graph node for detailed signal inspection.

        Returns:
            Sorted list of applicable RuleMatch objects.
        """
        matches: list[RuleMatch] = []

        for rule in self.rules:
            # Check preconditions
            if not self._preconditions_met(finding, rule):
                continue

            # Check match conditions
            match_obj = rule.get("match", {})
            if not self._rule_matches(finding, node, match_obj):
                continue

            # Build match result
            priority = rule.get("priority", 50)  # Default medium priority
            is_actionable = rule.get("actionable", True)
            explanation = self._explain_match(finding, rule, match_obj)

            matches.append(
                RuleMatch(
                    rule_id=rule["id"],
                    message=rule.get("message", ""),
                    priority=priority,
                    is_actionable=is_actionable,
                    explanation=explanation,
                )
            )

        # Sort by priority (higher first), then by rule order
        matches.sort(key=lambda m: (-m.priority, self.rules.index(self.rules_by_id[m.rule_id])))

        return matches

    def _preconditions_met(self, finding: CryptoFinding, rule: dict[str, Any]) -> bool:
        """Check if rule preconditions are satisfied.

        Preconditions determine if a rule is even eligible for evaluation.
        """
        preconditions = rule.get("preconditions", {})

        # Check primitive requirement
        if "primitive_in" in preconditions:
            if finding.primitive not in preconditions["primitive_in"]:
                return False

        # Check algorithm requirement
        if "algorithm_in" in preconditions:
            if finding.algorithm not in preconditions["algorithm_in"]:
                return False

        # Check provider requirement
        if "provider_in" in preconditions:
            if finding.provider not in preconditions["provider_in"]:
                return False

        # Check operation requirement
        signals = finding.context.get("signals", {})
        mode = signals.get("mode")
        if "operation_in" in preconditions:
            # For now, we use primitive as proxy for operation
            if finding.primitive not in preconditions["operation_in"]:
                return False

        return True

    def _rule_matches(
        self,
        finding: CryptoFinding,
        node: GraphNode | None,
        match: dict[str, Any],
    ) -> bool:
        """Check if match conditions are satisfied."""
        if not match:
            return True  # No conditions = always match

        # Single-value matches
        if "api_name" in match and finding.api_name != match["api_name"]:
            return False

        # List matches
        if "api_name_in" in match and finding.api_name not in match["api_name_in"]:
            return False

        if "algorithm_in" in match and finding.algorithm not in match["algorithm_in"]:
            return False

        # Signal-based matches
        signals = finding.context.get("signals", {})

        # Mode matching
        if "mode_in" in match:
            mode = signals.get("mode")
            if mode not in match["mode_in"]:
                return False

        # Key size matching
        if "key_size_less_than" in match:
            key_size = signals.get("key_size")
            if not isinstance(key_size, int) or key_size >= match["key_size_less_than"]:
                return False

        # Argument-based matches
        if "argument_contains" in match:
            needle = match["argument_contains"]
            if not any(needle in arg for arg in finding.arguments):
                return False

        # String literal detection
        if "has_string_literal_argument" in match and match["has_string_literal_argument"]:
            if node and node.properties.get("literal_arguments"):
                # Check if any literal is a string
                if not any(isinstance(val, str) for val in node.properties.get("literal_arguments", [])):
                    return False
            else:
                # No node info, use conservative approach
                return False

        # PBKDF2-specific: check iterations
        if finding.algorithm == "PBKDF2" and "pbkdf2_iterations_less_than" in match:
            threshold = match["pbkdf2_iterations_less_than"]
            iterations = self._extract_pbkdf2_iterations(finding.arguments)
            if not iterations or iterations >= threshold:
                return False

        return True

    def _explain_match(
        self,
        finding: CryptoFinding,
        rule: dict[str, Any],
        match: dict[str, Any],
    ) -> str:
        """Generate human-readable explanation for why a rule matched."""
        rule_id = rule["id"]

        # Common patterns with explicit explanations
        if rule_id == "AES_ECB_MODE":
            return "AES is used with ECB mode, which reveals patterns in encrypted data"

        if rule_id == "PBKDF2_LOW_ITERATIONS":
            iterations = self._extract_pbkdf2_iterations(finding.arguments)
            return f"PBKDF2 configured with {iterations} iterations; minimum 100,000 recommended"

        if rule_id == "RSA_SMALL_KEY":
            key_size = finding.context.get("signals", {}).get("key_size")
            return f"RSA key size {key_size} bits; minimum 2048 bits required"

        if rule_id == "WEAK_PRNG":
            return f"Weak RNG {finding.api_name} used for cryptographic operation; use os.urandom()"

        if rule_id == "DEPRECATED_HASH":
            return f"{finding.algorithm} is cryptographically broken; use SHA-256 or SHA-512"

        if rule_id == "ECB_MODE_OBJECT":
            return "ECB mode object instantiated; ECB should not be used for data encryption"

        if rule_id == "LEGACY_BLOCK_CIPHER":
            return f"{finding.algorithm} is deprecated; migrate to AES or ChaCha20"

        # Generic fallback
        preconditions = rule.get("preconditions", {})
        if preconditions:
            conds = [f"{k}={v}" for k, v in preconditions.items()]
            return f"Rule {rule_id} matched: {', '.join(conds)}"

        return f"Rule {rule_id} matched cryptographic asset"

    @staticmethod
    def _extract_pbkdf2_iterations(arguments: list[str]) -> int | None:
        """Extract iteration count from PBKDF2 arguments."""
        for arg in arguments:
            if "iterations" in arg.lower():
                try:
                    parts = arg.split("=")
                    if len(parts) == 2:
                        return int(parts[1])
                except ValueError:
                    pass
        return None

    def filter_for_asset(
        self,
        finding: CryptoFinding,
        node: GraphNode | None = None,
    ) -> dict[str, list[RuleMatch]]:
        """Get all applicable rules grouped by category.

        Returns:
            Dict with categories: 'critical', 'actionable', 'informational'
        """
        all_matches = self.match_rules(finding, node)

        grouped: dict[str, list[RuleMatch]] = {
            "critical": [],
            "actionable": [],
            "informational": [],
        }

        for match in all_matches:
            if match.priority >= 80:
                grouped["critical"].append(match)
            elif match.is_actionable:
                grouped["actionable"].append(match)
            else:
                grouped["informational"].append(match)

        return grouped
