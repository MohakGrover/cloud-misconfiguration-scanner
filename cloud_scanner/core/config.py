"""
Configuration settings for Cloud Scanner
"""

import os
from dataclasses import dataclass

@dataclass
class Config:
    """Application configuration"""
    APP_NAME = "Cloud Scanner"
    VERSION = "1.0.0"
    
    # Paths
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    RULES_DIR = os.path.join(BASE_DIR, 'rules', 'definitions')
    DB_PATH = os.path.join(os.path.dirname(BASE_DIR), 'cloud_scanner.duckdb')
    
    # Scanning
    DEFAULT_REGION = "us-east-1"
    MAX_RETRIES = 5
    
    # Risk Scoring
    RISK_WEIGHTS = {
        'CRITICAL': 100,
        'HIGH': 75,
        'MEDIUM': 50,
        'LOW': 25
    }
    
    # Logging
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    
    @classmethod
    def get_db_path(cls):
        return os.getenv('Cloud Scanner_DB_PATH', cls.DB_PATH)
