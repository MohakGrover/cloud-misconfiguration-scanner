"""
CLI commands for AntiGravity
"""

import click
import logging
import json
from antigravity.core.scanner import CloudScanner
from antigravity.core.config import Config

# Configure logging
logging.basicConfig(
    level=getattr(logging, Config.LOG_LEVEL),
    format='[%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)

@click.group()
def cli():
    """AntiGravity - Cloud Security Scanner"""
    pass

@cli.command()
@click.option('--region', default='us-east-1', help='AWS region to scan')
@click.option('--profile', default=None, help='AWS CLI profile to use')
@click.option('--interactive', '-i', is_flag=True, help='Prompt for AWS credentials')
@click.option('--output', '-o', default=None, help='Output file for JSON results')
def scan(region, profile, interactive, output):
    """Run a security scan on AWS account"""
    
    creds = {}
    if interactive:
        click.secho("Please enter your AWS credentials:", fg="yellow")
        creds['aws_access_key_id'] = click.prompt("AWS Access Key ID", hide_input=False)
        creds['aws_secret_access_key'] = click.prompt("AWS Secret Access Key", hide_input=True)
        creds['aws_session_token'] = click.prompt("AWS Session Token (optional)", default="", hide_input=True)
        region = click.prompt("AWS Region", default=region)
        
        if not creds['aws_session_token']:
            del creds['aws_session_token']
            
    try:
        scanner = CloudScanner(aws_profile=profile, region=region, interactive_creds=creds if interactive else None)
        scan_result = scanner.scan()
        
        if output:
            with open(output, 'w') as f:
                json.dump(scan_result.to_dict(), f, indent=2)
            click.echo(f"Results saved to {output}")
            
    except Exception as e:
        click.secho(f"Scan failed: {str(e)}", fg="red")
        exit(1)

if __name__ == '__main__':
    cli()
