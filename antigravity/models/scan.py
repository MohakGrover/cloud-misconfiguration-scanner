"""
Scan data model
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Any
from .finding import Finding

@dataclass
class Scan:
    """Represents a security scan result"""
    
    scan_id: str
    timestamp: datetime
    region: str
    findings: List[Finding]
    resources_scanned: int
    duration_seconds: float
    
    @property
    def compliance_score(self) -> float:
        """Calculate compliance score (0-100)"""
        # Placeholder logic: Score starts at 100, drops for findings
        # 100 - (Critical * 10) - (High * 5) - (Medium * 2) - (Low * 1)
        base_score = 100.0
        deductions = 0
        
        for finding in self.findings:
            if finding.severity == 'CRITICAL':
                deductions += 10
            elif finding.severity == 'HIGH':
                deductions += 5
            elif finding.severity == 'MEDIUM':
                deductions += 2
            elif finding.severity == 'LOW':
                deductions += 1
                
        # Normalize to 0-100 and resource count? 
        # For now, simple deduction capped at 0.
        score = max(0.0, base_score - deductions)
        return score
    
    def get_findings_by_severity(self, severity: str) -> int:
        """Get count of findings by severity"""
        return sum(1 for f in self.findings if f.severity == severity)
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert scan to dictionary"""
        return {
            'scan_id': self.scan_id,
            'timestamp': self.timestamp.isoformat(),
            'region': self.region,
            'findings': [f.to_dict() for f in self.findings],
            'resources_scanned': self.resources_scanned,
            'duration_seconds': self.duration_seconds,
            'compliance_score': self.compliance_score
        }
