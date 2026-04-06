"""
Security Group collector - checks for overly permissive rules
"""

from .base import BaseCollector
from typing import List, Dict, Any
import logging

logger = logging.getLogger(__name__)


class SecurityGroupCollector(BaseCollector):
    """Collects EC2 Security Group configurations"""
    
    def __init__(self, session, region='us-east-1'):
        super().__init__(session, region)
        self.client = session.client('ec2', region_name=region)
    
    def get_service_name(self) -> str:
        return 'security_groups'
    
    def collect(self) -> List[Dict[str, Any]]:
        """
        Collect all security groups and analyze rules
        
        Returns:
            List of security group configurations
        """
        security_groups = []
        
        response = self._call_aws_api(self.client.describe_security_groups)
        
        if not response:
            logger.warning("Failed to list security groups")
            return []
        
        for sg in response.get('SecurityGroups', []):
            sg_id = sg['GroupId']
            logger.info(f"Scanning Security Group: {sg_id}")
            
            # Analyze ingress rules for risky configurations
            risky_rules = self._analyze_ingress_rules(sg.get('IpPermissions', []))
            
            # Check for specific risks for simplified boolean rules
            has_public_ssh = any(r['risk'] == 'HIGH' and 'SSH' in r['reason'] for r in risky_rules)
            has_public_rdp = any(r['risk'] == 'HIGH' and 'RDP' in r['reason'] for r in risky_rules)
            
            sg_config = {
                'type': 'security_group',
                'group_id': sg_id,
                'group_name': sg.get('GroupName'),
                'description': sg.get('Description'),
                'vpc_id': sg.get('VpcId'),
                'ingress_rules': sg.get('IpPermissions', []),
                'egress_rules': sg.get('IpPermissionsEgress', []),
                'risky_rules': risky_rules,
                'has_public_ssh': has_public_ssh,
                'has_public_rdp': has_public_rdp,
                'tags': {tag['Key']: tag['Value'] for tag in sg.get('Tags', [])}
            }
            
            security_groups.append(sg_config)
        
        logger.info(f"Collected {len(security_groups)} security groups")
        return security_groups
    
    def _analyze_ingress_rules(self, ip_permissions: List[Dict]) -> List[Dict[str, Any]]:
        """
        Analyze ingress rules for security risks
        
        Args:
            ip_permissions: List of ingress rules
            
        Returns:
            List of risky rule configurations
        """
        risky_rules = []
        sensitive_ports = {
            22: 'SSH',
            3389: 'RDP',
            3306: 'MySQL',
            5432: 'PostgreSQL',
            1433: 'MS SQL Server',
            27017: 'MongoDB',
            6379: 'Redis',
            5984: 'CouchDB',
            9200: 'Elasticsearch',
            8080: 'HTTP Proxy'
        }
        
        for rule in ip_permissions:
            # Check for 0.0.0.0/0 access
            has_public_access = any(
                ip_range.get('CidrIp') == '0.0.0.0/0'
                for ip_range in rule.get('IpRanges', [])
            )
            
            if has_public_access:
                from_port = rule.get('FromPort')
                to_port = rule.get('ToPort')
                protocol = rule.get('IpProtocol', 'all')
                
                # Check if sensitive port is exposed
                if protocol == '-1':  # All traffic
                    risky_rules.append({
                        'risk': 'CRITICAL',
                        'reason': 'All traffic allowed from 0.0.0.0/0',
                        'from_port': 'all',
                        'to_port': 'all',
                        'protocol': 'all'
                    })
                elif from_port in sensitive_ports or to_port in sensitive_ports:
                    port = from_port or to_port
                    service = sensitive_ports.get(port, 'Unknown')
                    risky_rules.append({
                        'risk': 'HIGH',
                        'reason': f'{service} port {port} exposed to 0.0.0.0/0',
                        'from_port': from_port,
                        'to_port': to_port,
                        'protocol': protocol
                    })
        
        return risky_rules
