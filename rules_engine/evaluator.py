import operator
from typing import List, Dict, Any

class RuleEvaluator:
    def __init__(self):
        self.ops = {
            "equals": operator.eq,
            "not_equals": operator.ne,
            "contains": lambda a, b: b in a if a else False,
            "not_exists": lambda a, b: a is None,
            "exists": lambda a, b: a is not None,
            "gt": operator.gt,
            "lt": operator.lt,
        }

    def evaluate(self, rules: List[Dict[str, Any]], resources: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Evaluates rules against resources.
        Returns a list of findings.
        """
        findings = []
        for rule in rules:
            target_service = rule.get("service")
            
            for resource in resources:
                # Match provider and service
                if resource.get("provider") != rule.get("provider"):
                    continue
                if resource.get("service") != target_service:
                    continue

                if self._check_condition(rule.get("detection_logic"), resource):
                     findings.append({
                        "id": getattr(resource, "id", "unknown"), # Handle dict or object
                        "resource_id": resource.get("id", "unknown"),
                        "resource_name": resource.get("name", "unknown"),
                        "service": resource.get("service", "unknown"),
                        "rule_id": rule.get("rule_id"),
                        "rule_name": rule.get("name"),
                        "severity": rule.get("severity"),
                        "description": rule.get("description"),
                        "remediation": rule.get("remediation", {}).get("manual_steps", "")
                    })
        return findings

    def _check_condition(self, logic: Dict[str, Any], resource: Dict[str, Any]) -> bool:
        """
        recursively matches logic against resource.
        logic example: {'condition': 'any', 'checks': [...]}
        """
        if not logic:
            return False
            
        condition_type = logic.get("condition", "all")
        checks = logic.get("checks", [])
        
        results = []
        for check in checks:
            # Nested logic (recursive)
            if "condition" in check:
                results.append(self._check_condition(check, resource))
                continue
            
            # Field check
            field_path = check.get("field")
            op_name = check.get("operator")
            value = check.get("value")
            
            resource_val = self._get_field_value(resource, field_path)
            
            op_func = self.ops.get(op_name)
            if op_func:
                try:
                    if op_name in ["exists", "not_exists"]:
                        res = op_func(resource_val, None)
                    else:
                        res = op_func(resource_val, value)
                    results.append(res)
                except Exception:
                    results.append(False)
            else:
                results.append(False)

        if condition_type == "any":
            return any(results)
        else: # all
            return all(results)

    def _get_field_value(self, resource: Dict[str, Any], path: str) -> Any:
        """
        Retrieves nested value using dot notation.
        e.g. "public_access_block.BlockPublicAcls"
        """
        if not path:
            return None
        
        current = resource
        for part in path.split("."):
            if isinstance(current, dict):
                current = current.get(part)
            else:
                return None
        return current
