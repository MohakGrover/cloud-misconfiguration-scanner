"""
S3 bucket collector - checks for public access and encryption
"""

from .base import BaseCollector
from typing import List, Dict, Any
import logging

logger = logging.getLogger(__name__)


class S3Collector(BaseCollector):
    """Collects S3 bucket configurations"""
    
    def __init__(self, session, region='us-east-1'):
        super().__init__(session, region)
        self.client = session.client('s3', region_name=region)
    
    def get_service_name(self) -> str:
        return 's3'
    
    def collect(self) -> List[Dict[str, Any]]:
        """
        Collect all S3 buckets and their security configurations
        
        Returns:
            List of bucket configurations
        """
        buckets = []
        
        # List all buckets (S3 is global service)
        response = self._call_aws_api(self.client.list_buckets)
        
        if not response:
            logger.warning("Failed to list S3 buckets")
            return []
        
        for bucket in response.get('Buckets', []):
            bucket_name = bucket['Name']
            logger.info(f"Scanning S3 bucket: {bucket_name}")
            
            bucket_config = {
                'type': 's3_bucket',
                'bucket_name': bucket_name,
                'creation_date': bucket['CreationDate'].isoformat(),
                'region': self._get_bucket_region(bucket_name),
                'public_access_block': self._get_public_access_block(bucket_name),
                'bucket_policy': self._get_bucket_policy(bucket_name),
                'encryption': self._get_bucket_encryption(bucket_name),
                'versioning': self._get_bucket_versioning(bucket_name),
                'acl': self._get_bucket_acl(bucket_name)
            }
            
            buckets.append(bucket_config)
        
        logger.info(f"Collected {len(buckets)} S3 buckets")
        return buckets
    
    def _get_bucket_region(self, bucket_name: str) -> str:
        """Get bucket region"""
        try:
            response = self._call_aws_api(
                self.client.get_bucket_location,
                Bucket=bucket_name
            )
            location = response.get('LocationConstraint')
            return location if location else 'us-east-1'
        except Exception as e:
            logger.warning(f"Failed to get region for {bucket_name}: {str(e)}")
            return 'unknown'
    
    def _get_public_access_block(self, bucket_name: str) -> Dict[str, bool]:
        """Check if public access block is enabled"""
        try:
            response = self._call_aws_api(
                self.client.get_public_access_block,
                Bucket=bucket_name
            )
            if response:
                config = response.get('PublicAccessBlockConfiguration', {})
                return {
                    'block_public_acls': config.get('BlockPublicAcls', False),
                    'ignore_public_acls': config.get('IgnorePublicAcls', False),
                    'block_public_policy': config.get('BlockPublicPolicy', False),
                    'restrict_public_buckets': config.get('RestrictPublicBuckets', False)
                }
        except Exception as e:
            logger.warning(f"No public access block for {bucket_name}")
        
        return {
            'block_public_acls': False,
            'ignore_public_acls': False,
            'block_public_policy': False,
            'restrict_public_buckets': False
        }
    
    def _get_bucket_policy(self, bucket_name: str) -> Dict[str, Any]:
        """Get bucket policy"""
        try:
            response = self._call_aws_api(
                self.client.get_bucket_policy,
                Bucket=bucket_name
            )
            if response:
                import json
                return json.loads(response['Policy'])
        except Exception as e:
            logger.debug(f"No bucket policy for {bucket_name}")
        
        return None
    
    def _get_bucket_encryption(self, bucket_name: str) -> Dict[str, Any]:
        """Check if bucket encryption is enabled"""
        try:
            response = self._call_aws_api(
                self.client.get_bucket_encryption,
                Bucket=bucket_name
            )
            if response:
                rules = response.get('ServerSideEncryptionConfiguration', {}).get('Rules', [])
                if rules:
                    return {
                        'enabled': True,
                        'algorithm': rules[0].get('ApplyServerSideEncryptionByDefault', {}).get('SSEAlgorithm')
                    }
        except Exception as e:
            logger.debug(f"No encryption for {bucket_name}")
        
        return {'enabled': False, 'algorithm': None}
    
    def _get_bucket_versioning(self, bucket_name: str) -> Dict[str, str]:
        """Check if versioning is enabled"""
        try:
            response = self._call_aws_api(
                self.client.get_bucket_versioning,
                Bucket=bucket_name
            )
            if response:
                return {
                    'status': response.get('Status', 'Disabled'),
                    'mfa_delete': response.get('MFADelete', 'Disabled')
                }
        except Exception as e:
            logger.warning(f"Failed to get versioning for {bucket_name}")
        
        return {'status': 'Disabled', 'mfa_delete': 'Disabled'}
    
    def _get_bucket_acl(self, bucket_name: str) -> Dict[str, Any]:
        """Get bucket ACL"""
        try:
            response = self._call_aws_api(
                self.client.get_bucket_acl,
                Bucket=bucket_name
            )
            if response:
                grants = response.get('Grants', [])
                # Check for public access in ACL
                public_read = any(
                    grant.get('Grantee', {}).get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers'
                    for grant in grants
                )
                return {
                    'public_read': public_read,
                    'grants_count': len(grants)
                }
        except Exception as e:
            logger.warning(f"Failed to get ACL for {bucket_name}")
        
        return {'public_read': False, 'grants_count': 0}
