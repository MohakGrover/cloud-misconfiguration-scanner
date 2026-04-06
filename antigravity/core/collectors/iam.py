"""
IAM collector - checks for insecure IAM configurations
"""

from .base import BaseCollector
from typing import List, Dict, Any
from datetime import datetime, timezone
import logging

logger = logging.getLogger(__name__)


class IAMCollector(BaseCollector):
    """Collects IAM configurations"""
    
    def __init__(self, session, region='us-east-1'):
        super().__init__(session, region)
        self.client = session.client('iam', region_name=region)
    
    def get_service_name(self) -> str:
        return 'iam'
    
    def collect(self) -> List[Dict[str, Any]]:
        """
        Collect IAM users, roles, and policies
        
        Returns:
            List of IAM configurations
        """
        iam_data = []
        
        # Collect users
        users = self._collect_users()
        iam_data.extend(users)
        
        # Collect roles
        roles = self._collect_roles()
        iam_data.extend(roles)
        
        # Collect account summary
        account_summary = self._collect_account_summary()
        if account_summary:
            iam_data.append(account_summary)
        
        logger.info(f"Collected {len(iam_data)} IAM entities")
        return iam_data
    
    def _collect_users(self) -> List[Dict[str, Any]]:
        """Collect all IAM users and their access keys"""
        users = []
        
        response = self._call_aws_api(self.client.list_users)
        if not response:
            return []
        
        for user in response.get('Users', []):
            username = user['UserName']
            logger.info(f"Scanning IAM user: {username}")
            
            # Get access keys
            access_keys = self._get_user_access_keys(username)
            
            # Get attached policies
            policies = self._get_user_policies(username)
            
            user_config = {
                'type': 'user',
                'username': username,
                'user_id': user['UserId'],
                'arn': user['Arn'],
                'created_date': user['CreateDate'].isoformat(),
                'password_last_used': user.get('PasswordLastUsed', datetime.now(timezone.utc)).isoformat() if user.get('PasswordLastUsed') else None,
                'access_keys': access_keys,
                'policies': policies,
                'mfa_enabled': self._check_mfa(username)
            }
            
            users.append(user_config)
        
        return users
    
    def _get_user_access_keys(self, username: str) -> List[Dict[str, Any]]:
        """Get access keys for a user"""
        try:
            response = self._call_aws_api(
                self.client.list_access_keys,
                UserName=username
            )
            if response:
                keys = []
                for key in response.get('AccessKeyMetadata', []):
                    # Calculate key age
                    created_date = key['CreateDate']
                    age_days = (datetime.now(timezone.utc) - created_date).days
                    
                    keys.append({
                        'access_key_id': key['AccessKeyId'],
                        'status': key['Status'],
                        'created_date': created_date.isoformat(),
                        'age_days': age_days
                    })
                return keys
        except Exception as e:
            logger.warning(f"Failed to get access keys for {username}: {str(e)}")
        
        return []
    
    def _get_user_policies(self, username: str) -> List[Dict[str, Any]]:
        """Get attached policies for a user"""
        policies = []
        
        try:
            # Get attached managed policies
            response = self._call_aws_api(
                self.client.list_attached_user_policies,
                UserName=username
            )
            if response:
                for policy in response.get('AttachedPolicies', []):
                    policies.append({
                        'policy_name': policy['PolicyName'],
                        'policy_arn': policy['PolicyArn'],
                        'type': 'managed'
                    })
            
            # Get inline policies
            response = self._call_aws_api(
                self.client.list_user_policies,
                UserName=username
            )
            if response:
                for policy_name in response.get('PolicyNames', []):
                    # Get policy document
                    policy_doc = self._call_aws_api(
                        self.client.get_user_policy,
                        UserName=username,
                        PolicyName=policy_name
                    )
                    if policy_doc:
                        policies.append({
                            'policy_name': policy_name,
                            'document': policy_doc.get('PolicyDocument'),
                            'type': 'inline'
                        })
        except Exception as e:
            logger.warning(f"Failed to get policies for {username}: {str(e)}")
        
        return policies
    
    def _check_mfa(self, username: str) -> bool:
        """Check if MFA is enabled for user"""
        try:
            response = self._call_aws_api(
                self.client.list_mfa_devices,
                UserName=username
            )
            if response:
                return len(response.get('MFADevices', [])) > 0
        except Exception as e:
            logger.warning(f"Failed to check MFA for {username}")
        
        return False
    
    def _collect_roles(self) -> List[Dict[str, Any]]:
        """Collect all IAM roles"""
        roles = []
        
        response = self._call_aws_api(self.client.list_roles)
        if not response:
            return []
        
        for role in response.get('Roles', []):
            role_name = role['RoleName']
            logger.info(f"Scanning IAM role: {role_name}")
            
            # Get attached policies
            policies = self._get_role_policies(role_name)
            
            role_config = {
                'type': 'role',
                'role_name': role_name,
                'role_id': role['RoleId'],
                'arn': role['Arn'],
                'created_date': role['CreateDate'].isoformat(),
                'assume_role_policy': role.get('AssumeRolePolicyDocument'),
                'policies': policies
            }
            
            roles.append(role_config)
        
        return roles
    
    def _get_role_policies(self, role_name: str) -> List[Dict[str, Any]]:
        """Get attached policies for a role"""
        policies = []
        
        try:
            # Get attached managed policies
            response = self._call_aws_api(
                self.client.list_attached_role_policies,
                RoleName=role_name
            )
            if response:
                for policy in response.get('AttachedPolicies', []):
                    policies.append({
                        'policy_name': policy['PolicyName'],
                        'policy_arn': policy['PolicyArn'],
                        'type': 'managed'
                    })
        except Exception as e:
            logger.warning(f"Failed to get policies for role {role_name}: {str(e)}")
        
        return policies
    
    def _collect_account_summary(self) -> Dict[str, Any]:
        """Get account summary"""
        try:
            response = self._call_aws_api(self.client.get_account_summary)
            if response:
                summary = response.get('SummaryMap', {})
                return {
                    'type': 'account_summary',
                    'users': summary.get('Users', 0),
                    'groups': summary.get('Groups', 0),
                    'roles': summary.get('Roles', 0),
                    'policies': summary.get('Policies', 0),
                    'mfa_devices': summary.get('AccountMFAEnabled', 0)
                }
        except Exception as e:
            logger.warning(f"Failed to get account summary: {str(e)}")
        
        return None
