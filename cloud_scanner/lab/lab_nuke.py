"""
Validation Lab Nuke Script
Cleans up resources created by lab_deploy.py
"""

import boto3
import logging
from botocore.exceptions import ClientError

# Configure logging
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

class LabNuke:
    def __init__(self, region='us-east-1'):
        self.session = boto3.Session(region_name=region)
        self.s3 = self.session.client('s3')
        self.ec2 = self.session.client('ec2')
        self.iam = self.session.client('iam')
        self.sts = self.session.client('sts')
        
        self.tag_key = "ScannerLab"
        
    def nuke(self):
        """Delete all lab resources"""
        logger.info("Nuking Validation Lab resources...")
        
        self._nuke_s3()
        self._nuke_security_groups()
        self._nuke_iam()
        
        logger.info("Cleanup Complete!")

    def _nuke_s3(self):
        """Delete lab buckets"""
        try:
            response = self.s3.list_buckets()
            for bucket in response.get('Buckets', []):
                name = bucket['Name']
                
                # Check tags
                try:
                    tags = self.s3.get_bucket_tagging(Bucket=name).get('TagSet', [])
                    if any(t['Key'] == self.tag_key for t in tags):
                        logger.info(f"Deleting bucket: {name}")
                        
                        # Empty bucket first
                        objects = self.s3.list_objects_v2(Bucket=name)
                        if 'Contents' in objects:
                            for obj in objects['Contents']:
                                self.s3.delete_object(Bucket=name, Key=obj['Key'])
                        
                        self.s3.delete_bucket(Bucket=name)
                except ClientError:
                    continue
                    
        except Exception as e:
            logger.error(f"S3 cleanup failed: {e}")

    def _nuke_security_groups(self):
        """Delete lab security groups"""
        try:
            response = self.ec2.describe_security_groups(
                Filters=[{'Name': f'tag:{self.tag_key}', 'Values': ['*']}]
            )
            for sg in response.get('SecurityGroups', []):
                sg_id = sg['GroupId']
                logger.info(f"Deleting SG: {sg_id}")
                try:
                    self.ec2.delete_security_group(GroupId=sg_id)
                except ClientError as e:
                    logger.warning(f"Could not delete SG {sg_id}: {e}")
        except Exception as e:
            logger.error(f"SG cleanup failed: {e}")

    def _nuke_iam(self):
        """Delete lab IAM resources"""
        # Users
        try:
            response = self.iam.list_users()
            for user in response.get('Users', []):
                name = user['UserName']
                
                # Check tags (IAM ListUsers doesn't return tags by default, need to list tags or just match name pattern if tags not avail)
                # For safety, let's just check name pattern for this prototype
                if 'cloud_scanner-lab-' in name:
                     logger.info(f"Deleting User: {name}")
                     # Detach policies
                     policies = self.iam.list_attached_user_policies(UserName=name)
                     for p in policies.get('AttachedPolicies', []):
                         self.iam.detach_user_policy(UserName=name, PolicyArn=p['PolicyArn'])
                     
                     self.iam.delete_user(UserName=name)
        except Exception as e:
            logger.error(f"IAM User cleanup failed: {e}")

        # Roles
        try:
            response = self.iam.list_roles()
            for role in response.get('Roles', []):
                name = role['RoleName']
                if 'cloud_scanner-lab-' in name:
                    logger.info(f"Deleting Role: {name}")
                    
                    # Delete inline policies
                    policies = self.iam.list_role_policies(RoleName=name)
                    for p in policies.get('PolicyNames', []):
                        self.iam.delete_role_policy(RoleName=name, PolicyName=p)
                        
                    self.iam.delete_role(RoleName=name)
        except Exception as e:
            logger.error(f"IAM Role cleanup failed: {e}")

if __name__ == "__main__":
    nuke = LabNuke()
    nuke.nuke()
