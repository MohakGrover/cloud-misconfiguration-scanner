"""
Rule evaluator - evaluates rules against collected resources
"""

from typing import List, Dict, Any
import logging
import re

logger = logging.getLogger(__name__)


class RuleEvaluator:
    """Evaluates security rules against AWS resources"""
    
    def __init__(self):
        self.operators = {
            'equals': lambda a, b: a == b,
            'not_equals': lambda a, b: a != b,
            'greater_than': lambda a, b: a > b,
            'less_than': lambda a, b: a < b,
            'contains': lambda a, b: b in a if isinstance(a, (list, str)) else False,
            'matches': lambda a, b: bool(re.match(b, str(a))),
            'exists': lambda a, b: a is not None,
            'not_exists': lambda a, b: a is None
        }
    
    def evaluate_rule(self, rule: Dict[str, Any], resource: Dict[str, Any]) -> bool:
        """
        Evaluate a single rule against a resource
        
        Args:
            rule: Rule dictionary
            resource: Resource configuration
            
        Returns:
            True if rule matches (finding detected), False otherwise
        """
        detection_logic = rule.get('detection_logic', {})
        resource_type = detection_logic.get('resource_type')
        
        # Check if rule applies to this resource type
        if resource_type and resource.get('type') != resource_type:
            return False
        
        conditions = detection_logic.get('conditions', {})
        
        # Evaluate conditions
        if 'all' in conditions:
            return self._evaluate_all_conditions(conditions['all'], resource)
        elif 'any' in conditions:
            return self._evaluate_any_conditions(conditions['any'], resource)
        
        return False
    
    def _evaluate_all_conditions(self, conditions: List[Dict], resource: Dict[str, Any]) -> bool:
        """All conditions must match (AND logic)"""
        for condition in conditions:
            if not self._evaluate_condition(condition, resource):
                return False
        return True
    
    def _evaluate_any_conditions(self, conditions: List[Dict], resource: Dict[str, Any]) -> bool:
        """Any condition must match (OR logic)"""
        for condition in conditions:
            if self._evaluate_condition(condition, resource):
                return True
        return False
    
    def _evaluate_condition(self, condition: Dict, resource: Dict[str, Any]) -> bool:
        """
        Evaluate a single condition
        
        Args:
            condition: Condition dictionary with field, operator, value
            resource: Resource configuration
            
        Returns:
            True if condition matches, False otherwise
        """
        field = condition.get('field')
        operator = condition.get('operator')
        expected_value = condition.get('value')
        
        # Get actual value from resource using dot notation
        actual_value = self._get_nested_value(resource, field)
        
        # Apply operator
        operator_func = self.operators.get(operator)
        if not operator_func:
            logger.warning(f"Unknown operator: {operator}")
            return False
        
        try:
            return operator_func(actual_value, expected_value)
        except Exception as e:
            logger.debug(f"Error evaluating condition: {str(e)}")
            return False
    
    def _get_nested_value(self, resource: Dict[str, Any], field_path: str) -> Any:
        """
        Get nested value from resource using dot notation
        
        Args:
            resource: Resource dictionary
            field_path: Field path (e.g., 'public_access_block.block_public_acls')
            
        Returns:
            Field value or None if not found
        """
        if not field_path:
            return None
            
        parts = field_path.split('.')
        value = resource
        
        for part in parts:
            if isinstance(value, dict):
                value = value.get(part)
            else:
                return None
            
            if value is None:
                return None
        
        return value
