"""
Main scanner orchestrator - coordinates collectors, rules, and analysis
"""

import boto3
import os
from typing import List, Dict, Any
import logging
from datetime import datetime
from botocore.exceptions import NoCredentialsError, ClientError

from cloud_scanner.core.collectors.s3 import S3Collector
from cloud_scanner.core.collectors.security_groups import SecurityGroupCollector
from cloud_scanner.core.collectors.iam import IAMCollector
from cloud_scanner.core.collectors.rds import RDSCollector
from cloud_scanner.core.collectors.ec2 import EC2Collector
from cloud_scanner.rules.loader import RuleLoader
from cloud_scanner.rules.evaluator import RuleEvaluator
from cloud_scanner.models.finding import Finding
from cloud_scanner.models.scan import Scan
from cloud_scanner.analysis.risk_scoring import RiskScorer
from cloud_scanner.analysis.compliance import ComplianceAnalyzer
from cloud_scanner.core.config import Config

logger = logging.getLogger(__name__)


class CloudScanner:
    """Main cloud security scanner"""
    
    def __init__(self, aws_profile: str = None, region: str = 'us-east-1', interactive_creds: Dict = None):
        """
        Initialize scanner
        
        Args:
            aws_profile: AWS profile name (optional)
            region: AWS region to scan
            interactive_creds: Dictionary containing explicit credentials (optional)
        """
        self.region = region
        
        # Initialize session
        if interactive_creds:
            self.session = boto3.Session(
                aws_access_key_id=interactive_creds.get('aws_access_key_id'),
                aws_secret_access_key=interactive_creds.get('aws_secret_access_key'),
                aws_session_token=interactive_creds.get('aws_session_token'),
                region_name=region
            )
        else:
            self.session = boto3.Session(profile_name=aws_profile, region_name=region)
            
        # Validate credentials
        try:
            sts = self.session.client("sts")
            identity = sts.get_caller_identity()
            self.account_id = identity["Account"]
            self.user_arn = identity["Arn"]
            logger.info(f"Scanning as identity: {self.user_arn}")
        except (NoCredentialsError, ClientError) as e:
            raise ValueError(f"Could not validate credentials: {e}")
        
        # Initialize collectors
        self.collectors = {
            's3': S3Collector(self.session, region),
            'security_groups': SecurityGroupCollector(self.session, region),
            'iam': IAMCollector(self.session, region),
            'rds': RDSCollector(self.session, region),
            'ec2': EC2Collector(self.session, region)
        }
        
        # Initialize rules engine
        self.rule_loader = RuleLoader(Config.RULES_DIR)
        self.rules = self.rule_loader.load_all_rules()
        self.rule_evaluator = RuleEvaluator()
        
        # Initialize analysis modules
        self.risk_scorer = RiskScorer()
    
    def scan(self) -> Scan:
        """
        Perform complete security scan
        
        Returns:
            Scan object with findings
        """
        logger.info("=" * 60)
        logger.info("Starting Cloud Scanner Cloud Security Scan")
        logger.info("=" * 60)
        logger.info(f"Region: {self.region}")
        logger.info(f"Rules loaded: {len(self.rules)}")
        
        start_time = datetime.now()
        
        # Collect resources from all services
        collected_resources = {}
        for service_name, collector in self.collectors.items():
            logger.info(f"\nCollecting {service_name} resources...")
            try:
                resources = collector.collect()
                collected_resources[service_name] = resources
                logger.info(f"Collected {len(resources)} {service_name} resources")
            except Exception as e:
                logger.error(f"Failed to collect {service_name}: {str(e)}")
                collected_resources[service_name] = []
        
        # Evaluate rules against collected resources
        findings = []
        logger.info("\nEvaluating security rules...")
        
        for service_name, resources in collected_resources.items():
            service_rules = self.rule_loader.get_rules_by_service(service_name)
            logger.info(f"Evaluating {len(service_rules)} rules for {service_name}")
            
            for resource in resources:
                for rule in service_rules:
                    if self.rule_evaluator.evaluate_rule(rule, resource):
                        # Create finding
                        finding = self._create_finding(rule, resource, service_name)
                        findings.append(finding)
                        logger.warning(f"FINDING: {finding.rule_name} - {finding.resource_id}")
        
        # Calculate scan metrics
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        # Create scan summary
        scan = Scan(
            scan_id=f"scan-{start_time.strftime('%Y%m%d-%H%M%S')}",
            timestamp=start_time,
            region=self.region,
            findings=findings,
            resources_scanned=sum(len(r) for r in collected_resources.values()),
            duration_seconds=duration
        )
        
        # Generate Compliance Report
        compliance_analyzer = ComplianceAnalyzer(findings)
        compliance_report = compliance_analyzer.get_cis_report()
        
        # Print summary
        logger.info("\n" + "=" * 60)
        logger.info("Scan Complete!")
        logger.info("=" * 60)
        logger.info(f"Duration: {duration:.2f} seconds")
        logger.info(f"Resources scanned: {scan.resources_scanned}")
        logger.info(f"Total findings: {len(findings)}")
        logger.info(f"  CRITICAL: {scan.get_findings_by_severity('CRITICAL')}")
        logger.info(f"  HIGH: {scan.get_findings_by_severity('HIGH')}")
        logger.info(f"  MEDIUM: {scan.get_findings_by_severity('MEDIUM')}")
        logger.info(f"  LOW: {scan.get_findings_by_severity('LOW')}")
        logger.info(f"Compliance Score: {scan.compliance_score:.1f}%")
        logger.info(f"CIS Failed Controls: {compliance_report['summary']['failed_controls']}")
        logger.info("=" * 60)
        
        return scan
    
    def _create_finding(self, rule: Dict[str, Any], resource: Dict[str, Any], service: str) -> Finding:
        """
        Create Finding object from rule and resource
        
        Args:
            rule: Rule dictionary
            resource: Resource configuration
            service: Service name
            
        Returns:
            Finding object
        """
        # Extract resource identifier
        resource_id = self._extract_resource_id(resource, service)
        
        # Calculate risk score
        risk_score = self.risk_scorer.calculate_risk_score(rule, resource)
        
        # Format remediation with resource-specific values
        remediation = self._format_remediation(rule.get('remediation', {}), resource_id)
        
        finding = Finding(
            rule_id=rule['rule_id'],
            rule_name=rule['name'],
            severity=rule['severity'],
            resource_id=resource_id,
            provider='aws',
            service=service,
            region=self.region,
            description=rule['description'],
            remediation=remediation,
            risk_score=risk_score,
            cis_mapping=rule.get('cis_mapping'),
            resource_details=resource
        )
        
        return finding
    
    def _extract_resource_id(self, resource: Dict[str, Any], service: str) -> str:
        """Extract resource identifier based on service type"""
        id_fields = {
            's3': 'bucket_name',
            'security_groups': 'group_id',
            'iam': 'username',
            'rds': 'db_instance_identifier',
            'ec2': 'instance_id'
        }
        
        if service == 'iam' and resource.get('type') == 'role':
            return resource.get('role_name')
        elif service == 'iam' and resource.get('type') == 'account_summary':
            return 'AWS Account'
            
        field = id_fields.get(service, 'id')
        return resource.get(field, 'unknown')
    
    def _format_remediation(self, remediation: Dict[str, str], resource_id: str) -> Dict[str, str]:
        """Format remediation strings with resource-specific values"""
        formatted = {}
        
        for key, value in remediation.items():
            if isinstance(value, str):
                # Replace common placeholders using the resource_id as a best guess for all
                formatted_val = value
                replacements = {
                    '{bucket_name}': resource_id,
                    '{group_id}': resource_id,
                    '{db_instance_identifier}': resource_id,
                    '{resource_id}': resource_id,
                    '{username}': resource_id,
                    '{role_name}': resource_id,
                    '{instance_id}': resource_id
                }
                for placeholder, replacement in replacements.items():
                    if replacement:
                        formatted_val = formatted_val.replace(placeholder, str(replacement))
                
                formatted[key] = formatted_val
            else:
                formatted[key] = value
        
        return formatted
