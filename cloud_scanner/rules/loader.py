"""
Rule loader - loads YAML rule definitions
"""

import yaml
import os
from typing import List, Dict, Any
import logging

logger = logging.getLogger(__name__)


class RuleLoader:
    """Loads security rules from YAML files"""
    
    def __init__(self, rules_directory: str):
        """
        Initialize rule loader
        
        Args:
            rules_directory: Path to directory containing YAML rule files
        """
        self.rules_directory = rules_directory
        self.rules = []
    
    def load_all_rules(self) -> List[Dict[str, Any]]:
        """
        Load all rule files from the rules directory
        
        Returns:
            List of rule dictionaries
        """
        self.rules = []
        
        if not os.path.exists(self.rules_directory):
            logger.error(f"Rules directory not found: {self.rules_directory}")
            return []
        
        # Load all YAML files
        for filename in os.listdir(self.rules_directory):
            if filename.endswith('.yaml') or filename.endswith('.yml'):
                filepath = os.path.join(self.rules_directory, filename)
                self._load_rule_file(filepath)
        
        logger.info(f"Loaded {len(self.rules)} rules")
        return self.rules
    
    def _load_rule_file(self, filepath: str):
        """Load rules from a single YAML file"""
        try:
            with open(filepath, 'r') as f:
                content = yaml.safe_load(f)
                
                if isinstance(content, list):
                    for rule in content:
                        if self._validate_rule(rule):
                            self.rules.append(rule)
                elif isinstance(content, dict):
                    if self._validate_rule(content):
                        self.rules.append(content)
                
                logger.info(f"Loaded rules from {filepath}")
        except Exception as e:
            logger.error(f"Failed to load rule file {filepath}: {str(e)}")
    
    def _validate_rule(self, rule: Dict[str, Any]) -> bool:
        """
        Validate rule has required fields
        
        Args:
            rule: Rule dictionary
            
        Returns:
            True if valid, False otherwise
        """
        required_fields = ['rule_id', 'name', 'severity', 'description', 'detection_logic']
        
        for field in required_fields:
            if field not in rule:
                logger.warning(f"Rule missing required field '{field}': {rule.get('rule_id', 'unknown')}")
                return False
        
        return True
    
    def get_rules_by_service(self, service: str) -> List[Dict[str, Any]]:
        """
        Get all rules for a specific service
        
        Args:
            service: Service name (e.g., 's3', 'ec2')
            
        Returns:
            List of rules for the service
        """
        return [rule for rule in self.rules if rule.get('service') == service]
    
    def get_rule_by_id(self, rule_id: str) -> Dict[str, Any]:
        """
        Get a specific rule by ID
        
        Args:
            rule_id: Rule identifier
            
        Returns:
            Rule dictionary or None if not found
        """
        for rule in self.rules:
            if rule.get('rule_id') == rule_id:
                return rule
        return None
