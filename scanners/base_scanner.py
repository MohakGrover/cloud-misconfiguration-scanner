from abc import ABC, abstractmethod
from typing import List, Dict, Any

class BaseScanner(ABC):
    """
    Abstract base class for cloud resource scanners.
    """

    def __init__(self, provider: str):
        self.provider = provider

    @abstractmethod
    def scan_s3(self) -> List[Dict[str, Any]]:
        """Scans S3-like storage buckets."""
        pass

    @abstractmethod
    def scan_security_groups(self) -> List[Dict[str, Any]]:
        """Scans network security groups."""
        pass

    @abstractmethod
    def scan_iam(self) -> List[Dict[str, Any]]:
        """Scans IAM roles/users."""
        pass

    @abstractmethod
    def scan_ec2_exposure(self) -> List[Dict[str, Any]]:
        """
        Scans for EC2 instances with authorized exposure.
        Returns a list of findings (not raw resources).
        """
        pass
