import click
import json
from rich.console import Console
from rich.table import Table
from scanners.aws_scanner import AWSScanner
from rules_engine.loader import RuleLoader
from rules_engine.evaluator import RuleEvaluator

console = Console()

@click.command()
@click.option('--provider', default='aws', help='Cloud provider to scan (aws, azure, gcp).')
@click.option('--out', default=None, help='Output file for findings (JSON).')
@click.option('--profile', default=None, help='AWS CLI profile to use.')
@click.option('--interactive', '-i', is_flag=True, help='Prompt for AWS credentials.')
def scan(provider, out, profile, interactive):
    """
    Cloud Scanner - Elevate Your Cloud Security Posture
    """
    console.print(f"[bold blue]Starting Cloud Scanner scan for provider: {provider}[/bold blue]")

    # 0. Handle Credentials
    aws_creds = {}
    if provider == 'aws':
        if interactive:
            console.print("[yellow]Please enter your AWS credentials:[/yellow]")
            aws_creds['aws_access_key_id'] = click.prompt("AWS Access Key ID", hide_input=False)
            aws_creds['aws_secret_access_key'] = click.prompt("AWS Secret Access Key", hide_input=True)
            aws_creds['aws_session_token'] = click.prompt("AWS Session Token (optional)", default="", hide_input=True)
            aws_creds['region'] = click.prompt("AWS Region (optional)", default="us-east-1")
            
            if not aws_creds['aws_session_token']:
                del aws_creds['aws_session_token']
        elif profile:
            aws_creds['profile_name'] = profile

    # 1. Select Scanner
    scanner = None
    if provider == 'aws':
        try:
            scanner = AWSScanner(**aws_creds)
        except Exception as e:
            console.print(f"[bold red]Failed to initialize AWS Scanner: {e}[/bold red]")
            return
    else:
        console.print(f"[red]Provider {provider} not yet supported.[/red]")
        return

    # 2. Collect Resources
    resources = []
    ec2_findings = []
    with console.status("[bold green]Scanning resources...[/bold green]"):
        # S3
        console.print("Scanning S3 Buckets...")
        resources.extend(scanner.scan_s3())
        
        # EC2 Exposure
        if hasattr(scanner, 'scan_ec2_exposure'):
            console.print("Scanning EC2 Exposure (Network + Config)...")
            ec2_findings = scanner.scan_ec2_exposure()
        else:
            console.print("Skipping EC2 Exposure (Not supported for this provider)")

        # IAM
        console.print("Scanning IAM Users...")
        resources.extend(scanner.scan_iam())

        # RDS
        console.print("Scanning RDS Instances...")
        resources.extend(scanner.scan_rds())

    console.print(f"[bold]Collected {len(resources)} resources and {len(ec2_findings)} direct findings.[/bold]")



    # 3. Load Rules
    loader = RuleLoader()
    rules = loader.load_rules(provider)
    console.print(f"[bold]Loaded {len(rules)} rules.[/bold]")

    # 4. Evaluate
    evaluator = RuleEvaluator()
    findings = evaluator.evaluate(rules, resources)
    findings.extend(ec2_findings)

    # 5. Report
    if findings:
        table = Table(title="Scan Findings")
        table.add_column("Severity", style="bold")
        table.add_column("Service")
        table.add_column("Resource ID", overflow="fold")
        table.add_column("Rule")
        table.add_column("Description")

        for f in findings:
            sev = f.get('severity', 'UNKNOWN')
            style = "red" if sev == "CRITICAL" else "yellow" if sev == "HIGH" else "cyan"
            
            # Find service from resource data? OR from rule?
            # finding objects has 'resource_id', 'rule_name', etc.
            # We didn't pass service in finding dict in evaluator.py, let's fix evaluator or just ignore for now.
            # Evaluator passes: id, resource_id, resource_name, rule_id, rule_name, severity, description, remediation
            
            table.add_row(
                sev,
                f.get('service', 'n/a'),
                f.get('resource_id', 'unknown'),
                f.get('rule_name', 'unknown'),
                f.get('description', 'unknown'),
                style=style
            )
        console.print(table)
        if out:
            with open(out, 'w') as f:
                json.dump(findings, f, indent=2)
            console.print(f"[green]Findings saved to {out}[/green]")
    else:
        # We need to render the table correctly, let's just re-do the logic in the file content next.
        pass

if __name__ == '__main__':
    scan()
