import boto3
import socket
from typing import List, Dict, Any
from .base_scanner import BaseScanner
from botocore.exceptions import NoCredentialsError, ClientError

class AWSScanner(BaseScanner):
    def __init__(self, region: str = None, 
                 aws_access_key_id: str = None, 
                 aws_secret_access_key: str = None, 
                 aws_session_token: str = None,
                 profile_name: str = None):
        super().__init__("aws")
        self.region = region
        self.session = boto3.Session(
            region_name=region,
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            aws_session_token=aws_session_token,
            profile_name=profile_name
        )
        
        # Validate credentials immediately
        try:
            sts = self.session.client("sts")
            identity = sts.get_caller_identity()
            self.account_id = identity["Account"]
            self.user_arn = identity["Arn"]
            print(f"[INFO] Scanning as identity: {self.user_arn}")
        except (NoCredentialsError, ClientError) as e:
            raise ValueError(f"Could not validate credentials: {e}")

    def scan_s3(self) -> List[Dict[str, Any]]:
        """
        Scans all S3 buckets (S3 is global, but we use the session).
        Returns list of bucket dicts with 'Name', 'PublicAccessBlock', 'Policy'.
        """
        s3 = self.session.client("s3")
        buckets = []
        try:
            response = s3.list_buckets()
            for bucket in response.get("Buckets", []):
                b_name = bucket["Name"]
                bucket_data = {
                    "id": b_name,
                    "name": b_name,
                    "provider": "aws",
                    "service": "s3",
                    "public_access_block": None,
                    "policy": None
                }

                # Check Public Access Block
                try:
                    pab = s3.get_public_access_block(Bucket=b_name)
                    bucket_data["public_access_block"] = pab.get("PublicAccessBlockConfiguration")
                except Exception:
                    pass # No PAB config found

                buckets.append(bucket_data)
        except Exception as e:
            print(f"Error scanning S3: {e}")
        
        return buckets

    def scan_security_groups(self) -> List[Dict[str, Any]]:
        """
        Scans EC2 Security Groups in the current region.
        (Kept for legacy/generic rules, but EC2 SSH exposure is now handled by scan_ec2_exposure)
        """
        ec2 = self.session.client("ec2")
        sgs = []
        try:
            response = ec2.describe_security_groups()
            for sg in response.get("SecurityGroups", []):
                sg_data = {
                    "id": sg["GroupId"],
                    "name": sg["GroupName"],
                    "provider": "aws",
                    "service": "ec2",
                    "ip_permissions": sg.get("IpPermissions", [])
                }
                sgs.append(sg_data)
        except Exception as e:
            print(f"Error scanning Security Groups: {e}")
        return sgs

    def scan_ec2_exposure(self) -> List[Dict[str, Any]]:
        """
        Implements Authoritative EC2 SSH Exposure Detection:
        Network Exposure -> Resource Attribution -> Configuration Validation
        Returns a list of FINDING dicts (not raw resources).
        """
        ec2 = self.session.client("ec2")
        findings = []
        
        # 1. Discovery: Get Public IPs of RUNNING instances
        # We start by listing instances to get the 'Target IPs' (Network Scan Targets)
        # Note: In a real black-box test, we'd scan a range. Here we simulate scanning our known footprint.
        active_instances = {} # IP -> Instance Dict
        
        try:
            # Filter for running instances only
            response = ec2.describe_instances(Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])
            
            for reservation in response.get("Reservations", []):
                for inst in reservation.get("Instances", []):
                    # Get Public IP
                    pub_ip = inst.get("PublicIpAddress")
                    if pub_ip:
                        active_instances[pub_ip] = inst
            
            # If no instances, return early (False Positive Prevention)
            if not active_instances:
                return []

            # 2. Network Layout Simulation (Scanning)
            # We iterate over the IPs we found.
            for ip, instance in active_instances.items():
                
                # Check Port 22
                is_ssh_open = False
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1.0) # Fast timeout
                    result = sock.connect_ex((ip, 22))
                    if result == 0:
                        is_ssh_open = True
                    sock.close()
                except Exception:
                    pass

                if is_ssh_open:
                    # Step 1: Attribute (Already done via active_instances map)
                    inst_id = instance["InstanceId"]
                    
                    # Step 2: Validate state (Already filtered for 'running')
                    
                    # Step 3: Collect & Analyze Security Groups
                    sg_allows_global = False
                    relevant_sg_id = None
                    
                    # Get SGs attached to this instance
                    group_ids = [g['GroupId'] for g in instance.get("SecurityGroups", [])]
                    
                    if group_ids:
                        # Describe these specific SGs to get permissions
                        # Optimization: We could cache these, but for now we fetch per instance or batch
                        try:
                            sg_resp = ec2.describe_security_groups(GroupIds=group_ids)
                            for sg in sg_resp.get("SecurityGroups", []):
                                for perm in sg.get("IpPermissions", []):
                                    # Check for TCP/22 or All Traffic
                                    # Protocol: 'tcp' or '-1'
                                    proto = perm.get("IpProtocol")
                                    from_p = perm.get("FromPort")
                                    to_p = perm.get("ToPort")
                                    
                                    # Check Protocol & Port
                                    is_port_match = False
                                    if proto == "-1":
                                        is_port_match = True
                                    elif proto == "tcp" and from_p is not None and to_p is not None:
                                        if from_p <= 22 <= to_p:
                                            is_port_match = True
                                    
                                    if is_port_match:
                                        # Check Ranges
                                        for ip_range in perm.get("IpRanges", []):
                                            if ip_range.get("CidrIp") == "0.0.0.0/0":
                                                sg_allows_global = True
                                                relevant_sg_id = sg["GroupId"]
                                                break
                                if sg_allows_global:
                                    break
                        except Exception as e:
                            print(f"Error inspecting SGs for {inst_id}: {e}")

                    # Severity Logic
                    severity = "LOW"
                    title = "SSH Service Exposed"
                    desc = f"SSH exposed on {ip} (Instance {inst_id})."
                    
                    if sg_allows_global:
                        severity = "HIGH"
                        title = "EC2 Security Group allows unrestricted SSH access"
                        desc = f"Security group {relevant_sg_id} allows ingress on port 22 from 0.0.0.0/0 to instance {inst_id}."
                    else:
                        severity = "MEDIUM"
                        title = "SSH Detected on Public IP"
                        desc = f"SSH is open on {ip} (Instance {inst_id}) but not globally open in SG (likely restricted IP range)."

                    # Construct Finding
                    # We match the structure scan.py expects for the table
                    finding = {
                        "id": inst_id,
                        "resource_id": inst_id,
                        "resource_name": f"Instance {inst_id}",
                        "service": "ec2",
                        "rule_id": "EC2_SSH_EXPOSURE_NET",
                        "rule_name": title,
                        "severity": severity,
                        "description": desc,
                        "remediation": "Restrict Security Group rules to known IPs."
                    }
                    findings.append(finding)

        except Exception as e:
            print(f"Error in scan_ec2_exposure: {e}")
            
        return findings

    def scan_iam(self) -> List[Dict[str, Any]]:
        """
        Scans IAM Users (Global).
        """
        iam = self.session.client("iam")
        users_data = []
        try:
            paginator = iam.get_paginator('list_users')
            for page in paginator.paginate():
                for user in page['Users']:
                    u_data = {
                        "id": user["UserId"],
                        "name": user["UserName"],
                        "provider": "aws",
                        "service": "iam",
                        "mfa_active": False 
                    }
                    
                    # Check MFA
                    try:
                        mfa = iam.list_mfa_devices(UserName=user["UserName"])
                        if mfa.get("MFADevices"):
                            u_data["mfa_active"] = True
                    except Exception:
                        pass

                    users_data.append(u_data)
        except Exception as e:
            print(f"Error scanning IAM: {e}")
        return users_data

    def scan_rds(self) -> List[Dict[str, Any]]:
        """
        Scans RDS Instances (Regional).
        """
        rds = self.session.client("rds")
        instances_data = []
        try:
            paginator = rds.get_paginator('describe_db_instances')
            for page in paginator.paginate():
                for db in page['DBInstances']:
                    db_data = {
                        "id": db["DBInstanceIdentifier"],
                        "name": db["DBInstanceIdentifier"],
                        "provider": "aws",
                        "service": "rds",
                        "storage_encrypted": db.get("StorageEncrypted", False),
                        "publicly_accessible": db.get("PubliclyAccessible", False),
                        "backup_retention_period": db.get("BackupRetentionPeriod", 0)
                    }
                    instances_data.append(db_data)
        except Exception as e:
            print(f"Error scanning RDS: {e}")
        return instances_data

