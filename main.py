import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from prometheus_client import Gauge, generate_latest, REGISTRY
from datetime import datetime
import time
import logging
from threading import Thread

from dotenv import load_dotenv

# Setting up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class TrivyMetricsCollector:
    def __init__(self, scan_dir):
        self.scan_dir = scan_dir
        self.last_scan_time = 0
        
        # Initializing metrics
        self.image_vulnerabilities = Gauge(
            'trivy_image_vulnerabilities',
            'Number of image vulnerabilities by severity',
            ['severity', 'image_repository', 'image_tag', 'namespace']
        )
        
        self.image_exposedsecrets = Gauge(
            'trivy_image_exposedsecrets',
            'Number of exposed secrets in image',
            ['image_repository', 'image_tag', 'namespace']
        )
        
        self.resource_configaudits = Gauge(
            'trivy_resource_configaudits',
            'Number of misconfigurations by severity',
            ['severity', 'namespace']
        )
        
        self.role_rbacassessments = Gauge(
            'trivy_role_rbacassessments',
            'Number of RBAC assessment issues by severity',
            ['severity', 'namespace']
        )
        
        self.clusterrole_clusterrbacassessments = Gauge(
            'trivy_clusterrole_clusterrbacassessments',
            'Number of cluster RBAC assessment issues',
            ['severity']
        )

    def collect_metrics(self):
        """Collecting and updating metrics from scan"""
        try:
            # Cleaning up old metrics
            self.clear_metrics()
            
            if not os.path.exists(self.scan_dir):
                logger.error(f"Scan directory {self.scan_dir} does not exist")
                return
            
            # Scan the directory for new files
            for filename in os.listdir(self.scan_dir):
                if filename.endswith('.json'):
                    filepath = os.path.join(self.scan_dir, filename)
                    try:
                        file_mtime = os.path.getmtime(filepath)
                        
                        if file_mtime > self.last_scan_time:
                            self.process_scan_file(filepath)
                    except OSError as e:
                        logger.error(f"Error processing file {filename}: {str(e)}")
            
            self.last_scan_time = time.time()
            logger.info(f"Metrics updated at {datetime.now()}")
            
        except Exception as e:
            logger.error(f"Error collecting metrics: {str(e)}")

    def clear_metrics(self):
        """Clearing all metrics before updating"""
        for metric in [
            self.image_vulnerabilities,
            self.image_exposedsecrets,
            self.resource_configaudits,
            self.role_rbacassessments,
            self.clusterrole_clusterrbacassessments
        ]:
            metric.clear()

    def process_scan_file(self, filepath):
        """Processing a single file with scan results"""
        try:
            with open(filepath, 'r') as f:
                scan_data = json.load(f)
            
            # We determine the type of scan by the file structure
            if 'ArtifactName' in scan_data and 'Results' in scan_data:
                 # Image scanning
                self.process_image_scan(scan_data)
            elif 'ClusterName' in scan_data:
                # Cluster scan
                self.process_cluster_scan(scan_data)
            
            logger.debug(f"Processed scan file: {filepath}")

            # Deleting the read reports
            if ".json" in filepath:
                os.remove(filepath)

        except json.JSONDecodeError:
            logger.error(f"JSON decode error in file {filepath}")
        except Exception as e:
            logger.error(f"Error reading file {filepath}: {str(e)}")

    def process_image_scan(self, scan_data):
        """Image scan results processing"""
        artifact_name = scan_data.get('ArtifactName', 'unknown')
        namespace = scan_data.get('Metadata', {}).get('OS', {}).get('Family', None)
        namespace = namespace.split(':')[0] if namespace else 'unknown'
        
        # Parsing information about the image
        if '@' in artifact_name:
            image_repository = artifact_name.split('@')[0]
            image_tag = 'sha256:' + artifact_name.split('@')[1].split(':')[-1]
        else:
            image_repository = artifact_name.split(':')[0] if ':' in artifact_name else artifact_name
            image_tag = artifact_name.split(':')[1] if ':' in artifact_name else 'latest'

        # Handling vulnerabilities
        severity_counts = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0,
            'UNKNOWN': 0
        }
        
        for result in scan_data.get('Results', []):
            for vuln in result.get('Vulnerabilities', []):
                severity = vuln.get('Severity', 'Unknown')
                severity_counts[severity] += 1
        logger.info(f"Scanned image: {artifact_name} - {severity_counts}")
        
        # Processing exposed secrets
        for severity, count in severity_counts.items():
            self.image_vulnerabilities.labels(
                severity=severity,
                image_repository=image_repository,
                image_tag=image_tag,
                namespace=namespace
            ).set(count)
        
        # Processing exposed secrets
        secrets_count = 0
        for result in scan_data.get('Results', []):
            secrets_count += len(result.get('Secrets', []))

        if secrets_count > 0:
            self.image_exposedsecrets.labels(
                image_repository=image_repository,
                image_tag=image_tag,
                namespace=namespace
            ).set(secrets_count)

    def process_cluster_scan(self, scan_data):
        """Processing cluster scan results"""
        for result in scan_data.get('Results', []):
            namespace = result.get('Namespace', 'cluster')
            
            # Handling misconfigurations
            if 'Misconfigurations' in result:
                severity_counts = {
                    'CRITICAL': 0,
                    'HIGH': 0,
                    'MEDIUM': 0,
                    'LOW': 0,
                    'UNKNOWN': 0
                }
                
                for misconfig in result.get('Misconfigurations', []):
                    severity = misconfig.get('Severity', 'Unknown')
                    severity_counts[severity] += 1
                
                # Defining the type of metrics by Target
                target = result.get('Target', '')
                if 'Role' in target:
                    for severity, count in severity_counts.items():
                        self.role_rbacassessments.labels(
                            severity=severity,
                            namespace=namespace
                        ).set(count)
                elif 'ClusterRole' in target:
                    for severity, count in severity_counts.items():
                        self.clusterrole_clusterrbacassessments.labels(
                            severity=severity
                        ).set(count)
                else:
                    for severity, count in severity_counts.items():
                        self.resource_configaudits.labels(
                            severity=severity,
                            namespace=namespace
                        ).set(count)

class MetricsHandler(BaseHTTPRequestHandler):
    def __init__(self, collector, *args, **kwargs):
        self.collector = collector
        super().__init__(*args, **kwargs)
    
    def do_GET(self):
        if self.path == '/metrics':
            # We update the metrics before each request
            self.collector.collect_metrics()
            
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(generate_latest(REGISTRY))
        elif self.path == '/health':
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'OK')
        else:
            self.send_response(404)
            self.end_headers()

def run_server(collector, host='0.0.0.0', port=8000):
    """Launching an HTTP server to collect metrics"""
    def handler(*args, **kwargs):
        return MetricsHandler(collector, *args, **kwargs)
    
    server_address = (host, port)
    server = HTTPServer(server_address, handler)
    logger.info(f"Starting HTTP server on {host}:{port}")
    server.serve_forever()

def get_env_var(name, default=None, required=False):
    """Getting an environment variable with error handling"""
    value = os.getenv(name, default)
    if required and value is None:
        logger.error(f"Environment variable {name} is required but not set")
        raise ValueError(f"Environment variable {name} is required")
    return value

def main():
    try:
        load_dotenv()
        # Getting parameters from environment variables
        scan_dir = get_env_var('TRIVY_SCAN_DIR', '/scans', required=True)
        port = int(get_env_var('EXPORTER_PORT', '8000'))
        host = get_env_var('EXPORTER_HOST', '0.0.0.0')
        log_level = get_env_var('LOG_LEVEL', 'INFO')
        
        # Setting the logging level
        logger.setLevel(log_level)
        
        logger.info(f"Starting Trivy Exporter with scan_dir={scan_dir}, port={port}")
        
        # Initializing the metric collector
        collector = TrivyMetricsCollector(scan_dir)
        
        # Initial filling of metrics
        collector.collect_metrics()
        
        # Launching the HTTP server
        run_server(collector, host, port)
        
    except Exception as e:
        logger.error(f"Failed to start exporter: {str(e)}")
        raise

if __name__ == '__main__':
    main()
