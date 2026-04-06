"""
Finding data model
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Dict, Any, Optional

@dataclass
class Finding:
    """Represents a security finding"""
    
    rule_id: str
    rule_name: str
    severity: str
    resource_id: str
    provider: str
    service: str
    region: str
    description: str
    remediation: Dict[str, str]
    risk_score: int
    cis_mapping: Optional[Dict[str, str]] = None
    resource_details: Optional[Dict[str, Any]] = None
    timestamp: datetime = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()
            
    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary"""
        return {
            'rule_id': self.rule_id,
            'rule_name': self.rule_name,
            'severity': self.severity,
            'resource_id': self.resource_id,
            'provider': self.provider,
            'service': self.service,
            'region': self.region,
            'description': self.description,
            'remediation': self.remediation,
            'risk_score': self.risk_score,
            'cis_mapping': self.cis_mapping,
            'resource_details': self.resource_details,
            'timestamp': self.timestamp.isoformat()
        }
