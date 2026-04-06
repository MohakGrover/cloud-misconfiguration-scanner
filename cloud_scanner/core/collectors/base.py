"""
Base collector class for AWS resource scanning.
All collectors inherit from this to ensure consistent interface.
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any
import boto3
import logging
from botocore.exceptions import ClientError
import time

logger = logging.getLogger(__name__)


class BaseCollector(ABC):
    """Abstract base class for AWS resource collectors"""
    
    def __init__(self, session: boto3.Session, region: str = 'us-east-1'):
        """
        Initialize collector with AWS session
        
        Args:
            session: boto3 Session object with credentials
            region: AWS region to scan (default: us-east-1)
        """
        self.session = session
        self.region = region
        self.client = None
        
    @abstractmethod
    def collect(self) -> List[Dict[str, Any]]:
        """
        Collect resources from AWS
        
        Returns:
            List of resource dictionaries
        """
        pass
    
    def _call_aws_api(self, func, **kwargs):
        """
        Call AWS API with exponential backoff for throttling
        
        Args:
            func: boto3 client method to call
            **kwargs: Arguments to pass to the method
            
        Returns:
            API response
        """
        max_retries = 5
        base_delay = 1
        
        for attempt in range(max_retries):
            try:
                return func(**kwargs)
            except ClientError as e:
                error_code = e.response['Error']['Code']
                
                # Handle throttling
                if error_code in ['Throttling', 'TooManyRequestsException', 'RequestLimitExceeded']:
                    if attempt < max_retries - 1:
                        delay = base_delay * (2 ** attempt)
                        logger.warning(f"Throttled by AWS API, retrying in {delay}s...")
                        time.sleep(delay)
                        continue
                    else:
                        logger.error(f"Max retries exceeded for throttling")
                        raise
                
                # Handle access denied
                elif error_code == 'AccessDenied':
                    logger.error(f"Access denied for API call: {func.__name__}")
                    return None
                
                # Other errors
                else:
                    logger.error(f"AWS API error: {error_code} - {str(e)}")
                    raise
        
        return None
    
    @abstractmethod
    def get_service_name(self) -> str:
        """Return the AWS service name (e.g., 's3', 'ec2')"""
        pass
