"""
EC2 instance collector
"""

from .base import BaseCollector
from typing import List, Dict, Any
import logging

logger = logging.getLogger(__name__)


class EC2Collector(BaseCollector):
    """Collects EC2 instance configurations"""
    
    def __init__(self, session, region='us-east-1'):
        super().__init__(session, region)
        self.client = session.client('ec2', region_name=region)
    
    def get_service_name(self) -> str:
        return 'ec2'
    
    def collect(self) -> List[Dict[str, Any]]:
        """
        Collect EC2 instances
        
        Returns:
            List of EC2 instance configurations
        """
        instances = []
        
        response = self._call_aws_api(self.client.describe_instances)
        
        if not response:
            logger.warning("Failed to list EC2 instances")
            return []
        
        for reservation in response.get('Reservations', []):
            for instance in reservation.get('Instances', []):
                instance_id = instance['InstanceId']
                logger.info(f"Scanning EC2 instance: {instance_id}")
                
                # Check for public IP
                public_ip = instance.get('PublicIpAddress')
                
                # Get security groups
                security_groups = [
                    sg['GroupId'] for sg in instance.get('SecurityGroups', [])
                ]
                
                instance_config = {
                    'type': 'ec2_instance',
                    'instance_id': instance_id,
                    'image_id': instance.get('ImageId'),
                    'instance_type': instance.get('InstanceType'),
                    'launch_time': instance['LaunchTime'].isoformat(),
                    'state': instance.get('State', {}).get('Name'),
                    'public_ip': public_ip,
                    'private_ip': instance.get('PrivateIpAddress'),
                    'vpc_id': instance.get('VpcId'),
                    'subnet_id': instance.get('SubnetId'),
                    'security_groups': security_groups,
                    'tags': {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])},
                    'iam_instance_profile': instance.get('IamInstanceProfile', {}).get('Arn')
                }
                
                instances.append(instance_config)
        
        logger.info(f"Collected {len(instances)} EC2 instances")
        return instances
