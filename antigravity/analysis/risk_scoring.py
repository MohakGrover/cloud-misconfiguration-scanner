"""
Risk scoring logic
"""

from typing import Dict, Any

class RiskScorer:
    """Calculates risk scores for findings"""
    
    def __init__(self):
        self.severity_weights = {
            'CRITICAL': 100,
            'HIGH': 75,
            'MEDIUM': 50,
            'LOW': 25
        }
    
    def calculate_risk_score(self, rule: Dict[str, Any], resource: Dict[str, Any]) -> int:
        """
        Calculate risk score (0-100)
        
        Args:
            rule: Rule dictionary
            resource: Resource configuration
            
        Returns:
            Risk score integer
        """
        # Base score from severity
        base_score = self.severity_weights.get(rule.get('severity', 'LOW'), 25)
        
        # Adjust based on rule-defined risk factors if present
        factors = rule.get('risk_factors', {})
        if factors:
            exploitability = factors.get('exploitability', 50)
            blast_radius = factors.get('blast_radius', 50)
            business_impact = factors.get('business_impact', 50)
            
            # Weighted average
            # 40% Severity, 20% Exploitability, 20% Blast Radius, 20% Business Impact
            weighted_score = (
                (base_score * 0.4) +
                (exploitability * 0.2) +
                (blast_radius * 0.2) +
                (business_impact * 0.2)
            )
            return int(weighted_score)
            
        return base_score
