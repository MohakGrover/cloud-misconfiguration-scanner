"""
RDS collector - checks for database security misconfigurations
"""

from .base import BaseCollector
from typing import List, Dict, Any
import logging

logger = logging.getLogger(__name__)


class RDSCollector(BaseCollector):
    """Collects RDS database configurations"""
    
    def __init__(self, session, region='us-east-1'):
        super().__init__(session, region)
        self.client = session.client('rds', region_name=region)
    
    def get_service_name(self) -> str:
        return 'rds'
    
    def collect(self) -> List[Dict[str, Any]]:
        """
        Collect all RDS instances and check security settings
        
        Returns:
            List of RDS instance configurations
        """
        instances = []
        
        response = self._call_aws_api(self.client.describe_db_instances)
        
        if not response:
            logger.warning("Failed to list RDS instances")
            return []
        
        for db in response.get('DBInstances', []):
            db_id = db['DBInstanceIdentifier']
            logger.info(f"Scanning RDS instance: {db_id}")
            
            db_config = {
                'type': 'rds_instance',
                'db_instance_identifier': db_id,
                'engine': db.get('Engine'),
                'engine_version': db.get('EngineVersion'),
                'db_instance_class': db.get('DBInstanceClass'),
                'publicly_accessible': db.get('PubliclyAccessible', False),
                'encrypted': db.get('StorageEncrypted', False),
                'kms_key_id': db.get('KmsKeyId'),
                'vpc_security_groups': [
                    sg['VpcSecurityGroupId'] 
                    for sg in db.get('VpcSecurityGroups', [])
                ],
                'backup_retention_period': db.get('BackupRetentionPeriod', 0),
                'multi_az': db.get('MultiAZ', False),
                'auto_minor_version_upgrade': db.get('AutoMinorVersionUpgrade', False),
                'deletion_protection': db.get('DeletionProtection', False),
                'tags': {tag['Key']: tag['Value'] for tag in db.get('TagList', [])}
            }
            
            instances.append(db_config)
        
        logger.info(f"Collected {len(instances)} RDS instances")
        return instances
