"""
Compliance analysis module
"""

from typing import List, Dict, Any
from collections import defaultdict

class ComplianceAnalyzer:
    """Analyzes scan findings against compliance frameworks (CIS)"""
    
    def __init__(self, findings: List[Any]):
        self.findings = findings
        
    def get_cis_report(self) -> Dict[str, Any]:
        """
        Generate CIS compliance report
        
        Returns:
            Dictionary containing compliance status
        """
        report = {
            'framework': 'CIS AWS Foundations Benchmark',
            'version': '1.2.0',
            'controls': {},
            'summary': {
                'total_controls': 0,
                'failed_controls': 0,
                'passed_controls': 0 # Note: We only know failed ones from findings.
            }
        }
        
        failed_controls = set()
        
        for finding in self.findings:
            if finding.cis_mapping:
                control_id = finding.cis_mapping.get('control')
                if control_id:
                    if control_id not in report['controls']:
                        report['controls'][control_id] = {
                            'status': 'FAIL',
                            'findings': []
                        }
                    
                    report['controls'][control_id]['findings'].append(finding.to_dict())
                    failed_controls.add(control_id)
        
        report['summary']['failed_controls'] = len(failed_controls)
        
        return report
