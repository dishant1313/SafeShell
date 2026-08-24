"""Policy engine with safe AST-whitelist evaluation."""

import ast
import os
from typing import Dict, List

import yaml

from safeshell.schemas import PolicyDecision


class PolicyExpressionError(Exception):
    pass


class SafeEvaluator(ast.NodeVisitor):
    def __init__(self, context: Dict[str, any]):
        self.context = context

    def visit_Expression(self, node):
        return self.visit(node.body)

    def visit_BoolOp(self, node):
        if isinstance(node.op, ast.And):
            return all(self.visit(val) for val in node.values)
        elif isinstance(node.op, ast.Or):
            return any(self.visit(val) for val in node.values)
        raise PolicyExpressionError(f"Unsupported BoolOp: {type(node.op)}")

    def visit_Compare(self, node):
        left = self.visit(node.left)
        for op, comp in zip(node.ops, node.comparators):
            right = self.visit(comp)
            if isinstance(op, ast.Eq):
                if not (left == right):
                    return False
            elif isinstance(op, ast.NotEq):
                if not (left != right):
                    return False
            elif isinstance(op, ast.Lt):
                if not (left < right):
                    return False
            elif isinstance(op, ast.LtE):
                if not (left <= right):
                    return False
            elif isinstance(op, ast.Gt):
                if not (left > right):
                    return False
            elif isinstance(op, ast.GtE):
                if not (left >= right):
                    return False
            else:
                raise PolicyExpressionError(f"Unsupported comparison operator: {type(op)}")
            left = right
        return True

    def visit_Name(self, node):
        if node.id in self.context:
            return self.context[node.id]
        raise PolicyExpressionError(f"Unauthorized variable: {node.id}")

    def visit_Constant(self, node):
        if not isinstance(node.value, (str, int, float, bool)):
            raise PolicyExpressionError(f"Unsupported constant type: {type(node.value)}")
        return node.value

    def generic_visit(self, node):
        raise PolicyExpressionError(f"Unauthorized AST node: {type(node)}")


def _compile(expr: str, context: Dict[str, any]) -> bool:
    try:
        tree = ast.parse(expr, mode="eval")
    except SyntaxError as e:
        raise PolicyExpressionError(f"Syntax error in expression: {e}")

    # Pre-validate all nodes to prevent short-circuiting bypasses
    allowed_nodes = (
        ast.Expression,
        ast.BoolOp,
        ast.And,
        ast.Or,
        ast.Compare,
        ast.Eq,
        ast.NotEq,
        ast.Lt,
        ast.LtE,
        ast.Gt,
        ast.GtE,
        ast.Name,
        ast.Constant,
        ast.Load,
    )
    for node in ast.walk(tree):
        if not isinstance(node, allowed_nodes):
            raise PolicyExpressionError(
                f"Unauthorized AST node found during static check: {type(node)}"
            )

    evaluator = SafeEvaluator(context)
    return evaluator.visit(tree)


_POLICY_CONFIG = None


def load_policy_config() -> Dict[str, List[Dict[str, str]]]:
    global _POLICY_CONFIG
    if _POLICY_CONFIG is not None:
        return _POLICY_CONFIG

    config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config", "policy.yaml")
    with open(config_path, "r") as f:
        _POLICY_CONFIG = yaml.safe_load(f)

    # validate at load time
    test_context = {"tier": "low", "brs": 0, "guarantee": "T1"}
    for cat in ["deny", "require_human", "auto_approve"]:
        for rule in _POLICY_CONFIG.get(cat, []):
            _compile(rule["when"], test_context)

    return _POLICY_CONFIG


def evaluate(tier: str, brs: int, guarantee: str = "T1") -> PolicyDecision:
    try:
        config = load_policy_config()
    except Exception as e:
        # fail-closed on config error
        return PolicyDecision(action="require_human", rule=f"config_error: {e}")

    context = {"tier": tier, "brs": brs, "guarantee": guarantee}

    for rule in config.get("deny", []):
        if _compile(rule["when"], context):
            return PolicyDecision(action="deny", rule=rule["when"])

    for rule in config.get("require_human", []):
        if _compile(rule["when"], context):
            return PolicyDecision(action="require_human", rule=rule["when"])

    for rule in config.get("auto_approve", []):
        if _compile(rule["when"], context):
            return PolicyDecision(action="auto_approve", rule=rule["when"])

    return PolicyDecision(action="require_human", rule="default_fallback")
