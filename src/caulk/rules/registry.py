"""Rule registry and lookup for Caulk security checks."""

from __future__ import annotations

from collections.abc import Iterable

from caulk.models import FindingCategory
from caulk.rules.base import Rule


class RuleRegistry:
    """Central registry of deterministic security rules."""

    def __init__(self) -> None:
        self._rules: dict[str, Rule] = {}

    def register(self, rule: Rule) -> None:
        """Register a new rule instance."""
        if rule.rule_id in self._rules:
            raise ValueError(f"Duplicate rule ID registered: {rule.rule_id}")
        self._rules[rule.rule_id] = rule

    def get(self, rule_id: str) -> Rule | None:
        """Get rule by rule_id."""
        return self._rules.get(rule_id)

    def all_rules(self) -> list[Rule]:
        """Return all registered rules sorted deterministically by rule ID."""
        return sorted(self._rules.values(), key=lambda r: r.rule_id)

    def filter_rules(
        self,
        categories: Iterable[FindingCategory] | None = None,
        disabled_ids: set[str] | None = None,
        ecosystems: set[str] | None = None,
    ) -> list[Rule]:
        """Filter rules by category, disabled list, and project ecosystems."""
        disabled = disabled_ids or set()
        cat_set = set(categories) if categories else None

        filtered: list[Rule] = []
        for rule in self.all_rules():
            if rule.rule_id in disabled:
                continue
            if cat_set and rule.category not in cat_set:
                continue
            if ecosystems is not None and not rule.applies_to_ecosystem(ecosystems):
                continue
            filtered.append(rule)

        return filtered


# Global registry singleton
registry = RuleRegistry()
