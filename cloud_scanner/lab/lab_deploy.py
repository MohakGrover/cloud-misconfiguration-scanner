"""
Validation Lab Deployer
Creates intentionally misconfigured AWS resources to test Cloud Scanner scanner.
WARNING: This creates vulnerable resources. Use only in a sandbox account.
"""

import boto3
import logging
import time
import json
import random
import string
from botocore.exceptions import ClientError

# Configure logging
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

class LabDeployer:
    def __init__(self, region='us-east-1'):
        self.region = region
        self.session = boto3.Session(region_name=region)
        self.s3 = self.session.client('s3')
        self.ec2 = self.session.client('ec2')
        self.iam = self.session.client('iam')
        self.sts = self.session.client('sts')
        
        self.tag_key = "ScannerLab"
        self.tag_value = str(int(time.time()))
        
    def deploy(self):
        """Deploy all lab resources"""
        logger.info(f"Deploying Validation Lab in {self.region}...")
        logger.info(f"Run ID: {self.tag_value}")
        
        try:
            self._deploy_s3()
            self._deploy_security_group()
            self._deploy_iam()
            # self._deploy_rds() # Skipping RDS for speed/cost
            
            logger.info("\nDeployment Complete!")
            logger.info("Run 'python run.py scan' to see findings.")
            logger.info("Run 'python -m cloud_scanner.lab.nuke' to cleanup.")
            
        except Exception as e:
            logger.error(f"Deployment failed: {str(e)}")

    def _deploy_s3(self):
        """Create public S3 bucket"""
        bucket_name = f"cloud_scanner-lab-public-{self.tag_value}"
        logger.info(f"Creating public S3 bucket: {bucket_name}")
        
        try:
            if self.region == 'us-east-1':
                self.s3.create_bucket(Bucket=bucket_name)
            else:
                self.s3.create_bucket(
                    Bucket=bucket_name,
                    CreateBucketConfiguration={'LocationConstraint': self.region}
                )
            
            # Remove public access block (to allow public policies)
            self.s3.delete_public_access_block(Bucket=bucket_name)
            
            # Disable encryption (default is now often enabled by AWS, so we explicitly try to disable if possible or just ignore as it's hard to force disable now)
            # AWS enforces SSE-S3 by default now on new buckets. We might not be able to fully disable it easily.
            
            # Add tags
            self.s3.put_bucket_tagging(
                Bucket=bucket_name,
                Tagging={'TagSet': [{'Key': self.tag_key, 'Value': self.tag_value}]}
            )
            
            # Make public (Policy)
            public_policy = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "PublicReadGetObject",
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": "s3:GetObject",
                        "Resource": f"arn:aws:s3:::{bucket_name}/*"
                    }
                ]
            }
            self.s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(public_policy))
            logger.info("  -> Bucket configured as public")
            
        except ClientError as e:
            logger.error(f"  -> Failed to create bucket: {e}")

    def _deploy_security_group(self):
        """Create insecure security group"""
        sg_name = f"cloud_scanner-lab-sg-{self.tag_value}"
        logger.info(f"Creating insecure Security Group: {sg_name}")
        
        try:
            # Get default VPC
            vpcs = self.ec2.describe_vpcs(Filters=[{'Name': 'isDefault', 'Values': ['true']}])
            vpc_id = vpcs['Vpcs'][0]['VpcId']
            
            sg = self.ec2.create_security_group(
                GroupName=sg_name,
                Description="Cloud Scanner Lab - Insecure SG",
                VpcId=vpc_id,
                TagSpecifications=[{
                    'ResourceType': 'security-group',
                    'Tags': [{'Key': self.tag_key, 'Value': self.tag_value}]
                }]
            )
            sg_id = sg['GroupId']
            
            # Add ingress 0.0.0.0/0 on port 22
            self.ec2.authorize_security_group_ingress(
                GroupId=sg_id,
                IpPermissions=[
                    {
                        'IpProtocol': 'tcp',
                        'FromPort': 22,
                        'ToPort': 22,
                        'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                    },
                    {
                        'IpProtocol': 'tcp',
                        'FromPort': 3389,
                        'ToPort': 3389,
                        'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                    }
                ]
            )
            logger.info(f"  -> SG created {sg_id} with open ports 22, 3389")
            
        except ClientError as e:
            logger.error(f"  -> Failed to create SG: {e}")

    def _deploy_iam(self):
        """Create insecure IAM user and role"""
        user_name = f"cloud_scanner-lab-admin-{self.tag_value}"
        role_name = f"cloud_scanner-lab-role-{self.tag_value}"
        
        logger.info(f"Creating permissive IAM User: {user_name}")
        try:
            self.iam.create_user(
                UserName=user_name,
                Tags=[{'Key': self.tag_key, 'Value': self.tag_value}]
            )
            
            # Attach Admin Access
            self.iam.attach_user_policy(
                UserName=user_name,
                PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess'
            )
            logger.info("  -> Attached AdministratorAccess")
            
            # Create Access Key
            # self.iam.create_access_key(UserName=user_name)
            # logger.info("  -> Created Access Key")
            
        except ClientError as e:
            logger.error(f"  -> Failed to create user: {e}")
            
        logger.info(f"Creating permissive IAM Role: {role_name}")
        try:
            assume_policy = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": f"arn:aws:iam::{self.sts.get_caller_identity()['Account']}:root"},
                        "Action": "sts:AssumeRole"
                    }
                ]
            }
            
            self.iam.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=json.dumps(assume_policy),
                Tags=[{'Key': self.tag_key, 'Value': self.tag_value}]
            )
            
            # Inline policy allowing *:*
            policy_doc = {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
            }
            self.iam.put_role_policy(
                RoleName=role_name,
                PolicyName="SuperPermissive",
                PolicyDocument=json.dumps(policy_doc)
            )
            logger.info("  -> Attached inline *:* policy")
            
        except ClientError as e:
            logger.error(f"  -> Failed to create role: {e}")

if __name__ == "__main__":
    deployer = LabDeployer()
    deployer.deploy()
