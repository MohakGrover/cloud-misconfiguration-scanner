"""
API Routes for Cloud Scanner Dashboard
"""

from flask import jsonify, request, current_app
from . import api_bp
from cloud_scanner.core.scanner import CloudScanner
from cloud_scanner.core.config import Config
import logging
import threading
import json
import os
from datetime import datetime
import traceback

# Configure logging to file
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("backend_debug.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Global variable to store latest scan (simple in-memory storage for prototype)
# In production, this should be a database.
LATEST_SCAN_RESULT = None
SCAN_HISTORY = []

@api_bp.route('/scan', methods=['POST'])
def trigger_scan():
    """Trigger a new security scan"""
    data = request.get_json() or {}
    region = data.get('region', Config.DEFAULT_REGION)
    profile = data.get('profile', None)
    
    # Run scan in a separate thread (simplified for prototype)
    # In production, use Celery or RQ
    thread = threading.Thread(target=run_scan_background, args=(region, profile))
    thread.start()
    
    return jsonify({'message': 'Scan started', 'status': 'running'}), 202

def run_scan_background(region, profile):
    global LATEST_SCAN_RESULT
    try:
        logger.info(f"Starting background scan for region {region}")
        scanner = CloudScanner(aws_profile=profile, region=region)
        scan_result = scanner.scan()
        
        # Determine paths
        # Assuming run from project root or installed package
        # We'll save to a 'scans' directory in the usage directory (e.g. where the app is run)
        # or the artifacts directory if possible. For now, project root 'scans' dir.
        output_dir = os.path.join(os.getcwd(), 'scans')
        os.makedirs(output_dir, exist_ok=True)
        
        filename = f"scan_{scan_result.scan_id}.json"
        filepath = os.path.join(output_dir, filename)
        
        scan_dict = scan_result.to_dict()
        with open(filepath, 'w') as f:
            json.dump(scan_dict, f, indent=2)
            
        LATEST_SCAN_RESULT = scan_dict
        SCAN_HISTORY.append({
            'scan_id': scan_result.scan_id,
            'timestamp': scan_result.timestamp.isoformat(),
            'findings_count': len(scan_result.findings),
            'compliance_score': scan_result.compliance_score,
            'filepath': filepath
        })
        
        logger.info(f"Background scan complete. Saved to {filepath}")
        
    except Exception as e:
        logger.error(f"Background scan failed: {str(e)}")
        logger.error(traceback.format_exc())

@api_bp.route('/results/latest', methods=['GET'])
def get_latest_results():
    """Get results of the latest scan"""
    if LATEST_SCAN_RESULT:
        return jsonify(LATEST_SCAN_RESULT)
    else:
        return jsonify({'message': 'No scan results available'}), 404

@api_bp.route('/history', methods=['GET'])
def get_scan_history():
    """Get list of past scans"""
    return jsonify(SCAN_HISTORY)

@api_bp.route('/stats', methods=['GET'])
def get_dashboard_stats():
    """Get aggregate statistics for the dashboard"""
    if not LATEST_SCAN_RESULT:
        return jsonify({
            'total_findings': 0,
            'critical_findings': 0,
            'high_findings': 0,
            'compliance_score': 0,
            'resources_scanned': 0
        })
    
    findings = LATEST_SCAN_RESULT.get('findings', [])
    scan_meta = LATEST_SCAN_RESULT
    
    critical = sum(1 for f in findings if f['severity'] == 'CRITICAL')
    high = sum(1 for f in findings if f['severity'] == 'HIGH')
    
    return jsonify({
        'total_findings': len(findings),
        'critical_findings': critical,
        'high_findings': high,
        'compliance_score': scan_meta.get('compliance_score', 0),
        'resources_scanned': scan_meta.get('resources_scanned', 0),
        'timestamp': scan_meta.get('timestamp')
    })
