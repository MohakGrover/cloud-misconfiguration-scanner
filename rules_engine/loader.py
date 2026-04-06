import yaml
import os
from typing import List, Dict, Any

class RuleLoader:
    def __init__(self, rules_path: str = "rules"):
        self.rules_path = rules_path

    def load_rules(self, provider: str = None) -> List[Dict[str, Any]]:
        """
        Recursively loads YAML rules from the rules directory.
        Optionally filters by provider.
        """
        rules = []
        for root, _, files in os.walk(self.rules_path):
            for file in files:
                if file.endswith(".yaml") or file.endswith(".yml"):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, "r") as f:
                            rule = yaml.safe_load(f)
                            if rule:
                                if provider and rule.get("provider") != provider:
                                    continue
                                rules.append(rule)
                    except Exception as e:
                        print(f"Failed to load rule {file_path}: {e}")
        return rules
