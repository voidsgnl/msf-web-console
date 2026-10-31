"""
Three-valued evaluation of NVD CPE configuration trees (AND / OR / negate).

NVD publishes each CVE's applicability as configurations -> nodes -> cpeMatch
entries, where every node has an operator (AND/OR) and an optional negate
flag. Evaluating that tree needs three outcomes rather than two, because the
caller usually cannot confirm every entry (for example the target's operating
system is unknown):

  True   - the entry/node is satisfied by the detected target
  False  - the entry/node is definitely not satisfied
  None   - unknown: the data cannot confirm or rule it out
  OTHER  - the entry describes some other product, so it says nothing about
           the target we identified (ignored by OR, "unknown" inside AND)

The caller supplies a `leaf` function that maps one cpe_match dict to one of
those outcomes; this module only handles the boolean structure.
"""
from __future__ import annotations

from typing import Any, Callable

OTHER = object()


def _negate(value: Any) -> Any:
    if value is None or value is OTHER:
        return value
    return not value


def combine(operator: str | None, values: list[Any]) -> Any:
    """Combine child outcomes with AND or OR (default OR)."""
    if not values:
        return None
    if (operator or "OR").strip().upper() == "AND":
        if any(v is False for v in values):
            return False
        if any(v is None or v is OTHER for v in values):
            return None
        return True
    if any(v is True for v in values):
        return True
    if any(v is None for v in values):
        return None
    if any(v is False for v in values):
        return False
    return OTHER


def evaluate_node(node: dict[str, Any], leaf: Callable[[dict[str, Any]], Any]) -> Any:
    values = [leaf(m) for m in node.get("cpe_matches") or [] if isinstance(m, dict)]
    values.extend(
        evaluate_node(child, leaf)
        for child in node.get("children") or []
        if isinstance(child, dict)
    )
    result = combine(node.get("operator"), values)
    return _negate(result) if node.get("negate") else result


def evaluate_configuration(config: dict[str, Any], leaf: Callable[[dict[str, Any]], Any]) -> Any:
    nodes = config.get("nodes")
    if not nodes:
        # Flat shape (only "cpe_matches"): treat it as a single OR node.
        return evaluate_node(
            {"operator": "OR", "cpe_matches": config.get("cpe_matches") or []}, leaf
        )
    values = [evaluate_node(node, leaf) for node in nodes if isinstance(node, dict)]
    # NVD marks multi-node configurations with an explicit operator. If it is
    # missing, assume AND so we never claim "affected" without every node.
    operator = config.get("operator") or ("AND" if len(values) > 1 else "OR")
    result = combine(operator, values)
    return _negate(result) if config.get("negate") else result


def evaluate_configurations(
    configs: list[dict[str, Any]], leaf: Callable[[dict[str, Any]], Any]
) -> Any:
    """Separate NVD configurations for one CVE are alternatives (OR)."""
    values = [evaluate_configuration(c, leaf) for c in configs if isinstance(c, dict)]
    return combine("OR", values)
