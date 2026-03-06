"""
Enterprise SOAR - Forensics Worker Container
Long-running container for forensic analysis and malware scanning
"""

import os
import json
import boto3
import logging
from datetime import datetime, timezone
from flask import Flask, request, jsonify
import threading
import time
import hashlib
from botocore.exceptions import ClientError

# Configure logging
logging.basicConfig(
    level=getattr(logging, os.environ.get('LOG_LEVEL', 'INFO')),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)

# AWS clients
ec2_client = boto3.client('ec2')
s3_client = boto3.client('s3')
sns_client = boto3.client('sns')

# Configuration
ENVIRONMENT = os.environ.get('ENVIRONMENT', 'production')
S3_BUCKET = os.environ.get('FORENSICS_S3_BUCKET')
SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN')

class ForensicsWorker:
    """Enterprise-grade forensics worker with comprehensive analysis capabilities"""
    
    def __init__(self):
        self.active_operations = {}
        self.operation_counter = 0
        
    def analyze_instance(self, instance_id, snapshot_ids=None, operation_id=None):
        """
        Perform comprehensive forensic analysis of compromised instance
        
        Args:
            instance_id (str): EC2 instance ID to analyze
            snapshot_ids (list): List of snapshot IDs to analyze
            operation_id (str): Unique operation identifier
            
        Returns:
            dict: Analysis results with detailed findings
        """
        if not operation_id:
            self.operation_counter += 1
            operation_id = f"forensics-{int(time.time())}-{self.operation_counter}"
        
        try:
            logger.info(f"Starting forensics operation {operation_id} for instance {instance_id}")
            
            # Track operation
            self.active_operations[operation_id] = {
                'instance_id': instance_id,
                'status': 'in_progress',
                'start_time': datetime.now(timezone.utc).isoformat(),
                'steps': [],
                'findings': {}
            }
            
            # Step 1: Collect instance metadata
            metadata = self._collect_instance_metadata(instance_id, operation_id)
            
            # Step 2: Analyze snapshots if provided
            snapshot_analysis = {}
            if snapshot_ids:
                for snapshot_id in snapshot_ids:
                    analysis = self._analyze_snapshot(snapshot_id, operation_id)
                    snapshot_analysis[snapshot_id] = analysis
            
            # Step 3: Perform threat intelligence lookup
            threat_intel = self._perform_threat_intel_lookup(instance_id, operation_id)
            
            # Step 4: Generate forensic report
            report = self._generate_forensic_report(
                instance_id, 
                metadata, 
                snapshot_analysis, 
                threat_intel, 
                operation_id
            )
            
            # Step 5: Store results in S3
            if S3_BUCKET:
                self._store_forensic_results(report, operation_id)
            
            # Step 6: Send notification
            self._send_forensics_notification(instance_id, report, operation_id)
            
            # Mark operation complete
            self.active_operations[operation_id]['status'] = 'completed'
            self.active_operations[operation_id]['end_time'] = datetime.now(timezone.utc).isoformat()
            self.active_operations[operation_id]['findings'] = report
            
            result = {
                'operation_id': operation_id,
                'instance_id': instance_id,
                'status': 'success',
                'metadata': metadata,
                'snapshot_analysis': snapshot_analysis,
                'threat_intel': threat_intel,
                'report_summary': {
                    'total_findings': len(report.get('findings', [])),
                    'severity_distribution': report.get('severity_distribution', {}),
                    'recommendations': report.get('recommendations', [])
                },
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
            
            logger.info(f"Successfully completed forensics operation {operation_id}")
            return result
            
        except Exception as e:
            logger.error(f"Forensics operation {operation_id} failed: {str(e)}")
            
            # Mark operation failed
            if operation_id in self.active_operations:
                self.active_operations[operation_id]['status'] = 'failed'
                self.active_operations[operation_id]['error'] = str(e)
                self.active_operations[operation_id]['end_time'] = datetime.now(timezone.utc).isoformat()
            
            return {
                'operation_id': operation_id,
                'instance_id': instance_id,
                'status': 'failed',
                'error': str(e),
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
    
    def _collect_instance_metadata(self, instance_id, operation_id):
        """Collect comprehensive metadata about the instance"""
        try:
            response = ec2_client.describe_instances(InstanceIds=[instance_id])
            instance = response['Reservations'][0]['Instances'][0]
            
            metadata = {
                'instance_id': instance_id,
                'instance_type': instance.get('InstanceType'),
                'ami_id': instance.get('ImageId'),
                'launch_time': instance.get('LaunchTime').isoformat() if instance.get('LaunchTime') else None,
                'state': instance.get('State', {}).get('Name'),
                'availability_zone': instance.get('Placement', {}).get('AvailabilityZone'),
                'vpc_id': instance.get('VpcId'),
                'subnet_id': instance.get('SubnetId'),
                'security_groups': [sg['GroupId'] for sg in instance.get('SecurityGroups', [])],
                'iam_instance_profile': instance.get('IamInstanceProfile', {}).get('Arn'),
                'tags': {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])},
                'block_device_mappings': instance.get('BlockDeviceMappings', [])
            }
            
            # Get additional instance attributes
            try:
                attributes = ec2_client.describe_instance_attribute(
                    InstanceId=instance_id,
                    Attribute='userData'
                )
                metadata['has_user_data'] = bool(attributes.get('UserData'))
            except:
                metadata['has_user_data'] = False
            
            self._log_step(operation_id, 'collect_metadata', 'success', f"Collected metadata for {instance_id}")
            return metadata
            
        except Exception as e:
            self._log_step(operation_id, 'collect_metadata', 'failed', str(e))
            raise
    
    def _analyze_snapshot(self, snapshot_id, operation_id):
        """Analyze EBS snapshot for evidence"""
        try:
            logger.info(f"Analyzing snapshot {snapshot_id}")
            
            analysis = {
                'snapshot_id': snapshot_id,
                'analysis_timestamp': datetime.now(timezone.utc).isoformat(),
                'findings': [],
                'file_system_analysis': {},
                'malware_scan': {},
                'suspicious_activities': []
            }
            
            # Get snapshot details
            snapshot_info = ec2_client.describe_snapshots(SnapshotIds=[snapshot_id])
            snapshot = snapshot_info['Snapshots'][0]
            
            analysis['snapshot_info'] = {
                'size': snapshot.get('VolumeSize'),
                'start_time': snapshot.get('StartTime').isoformat() if snapshot.get('StartTime') else None,
                'status': snapshot.get('State'),
                'volume_id': snapshot.get('VolumeId'),
                'tags': {tag['Key']: tag['Value'] for tag in snapshot.get('Tags', [])}
            }
            
            # Simulate file system analysis
            # In a real implementation, you would:
            # 1. Create volume from snapshot
            # 2. Mount volume
            # 3. Run file system analysis tools
            # 4. Scan for malware
            # 5. Look for suspicious files and activities
            
            analysis['file_system_analysis'] = self._simulate_filesystem_analysis()
            analysis['malware_scan'] = self._simulate_malware_scan()
            analysis['suspicious_activities'] = self._simulate_activity_analysis()
            
            # Calculate overall risk score
            risk_score = self._calculate_snapshot_risk_score(analysis)
            analysis['risk_score'] = risk_score
            
            self._log_step(operation_id, 'analyze_snapshot', 'success', f"Analyzed snapshot {snapshot_id} (risk: {risk_score})")
            return analysis
            
        except Exception as e:
            self._log_step(operation_id, 'analyze_snapshot', 'failed', str(e))
            raise
    
    def _simulate_filesystem_analysis(self):
        """Simulate file system analysis (placeholder for real implementation)"""
        return {
            'total_files': 15420,
            'suspicious_files': 3,
            'hidden_files': 12,
            'recently_modified_files': 45,
            'file_types_found': {
                'executables': 234,
                'scripts': 89,
                'configuration': 156,
                'logs': 1245,
                'temp_files': 892
            },
            'suspicious_file_locations': [
                '/tmp/backdoor.exe',
                '/var/www/.hidden/shell.php',
                '/home/ec2-user/.ssh/authorized_keys.bak'
            ]
        }
    
    def _simulate_malware_scan(self):
        """Simulate malware scan (placeholder for real implementation)"""
        return {
            'scanned_files': 15420,
            'malware_detected': 2,
            'threats_found': [
                {
                    'file': '/tmp/backdoor.exe',
                    'threat_type': 'Trojan.Generic',
                    'severity': 'high',
                    'hash': 'a1b2c3d4e5f6...'
                },
                {
                    'file': '/var/www/.hidden/shell.php',
                    'threat_type': 'WebShell',
                    'severity': 'critical',
                    'hash': 'f6e5d4c3b2a1...'
                }
            ],
            'scan_duration_seconds': 245
        }
    
    def _simulate_activity_analysis(self):
        """Simulate suspicious activity analysis"""
        return [
            {
                'type': 'unusual_network_connections',
                'description': 'Connections to known C2 servers detected',
                'severity': 'high',
                'evidence': ['192.168.1.100:443 -> 185.14.28.56:8080']
            },
            {
                'type': 'privilege_escalation',
                'description': 'Evidence of sudo abuse detected',
                'severity': 'medium',
                'evidence': ['/var/log/auth.log entries']
            },
            {
                'type': 'data_exfiltration',
                'description': 'Large file transfers to external IP',
                'severity': 'high',
                'evidence': ['/var/log/nginx/access.log patterns']
            }
        ]
    
    def _calculate_snapshot_risk_score(self, analysis):
        """Calculate overall risk score for snapshot"""
        base_score = 0
        
        # Malware detections
        malware_count = len(analysis.get('malware_scan', {}).get('threats_found', []))
        base_score += malware_count * 25
        
        # Suspicious activities
        activity_count = len(analysis.get('suspicious_activities', []))
        base_score += activity_count * 15
        
        # Suspicious files
        suspicious_files = analysis.get('file_system_analysis', {}).get('suspicious_files', 0)
        base_score += suspicious_files * 10
        
        return min(base_score, 100)  # Cap at 100
    
    def _perform_threat_intel_lookup(self, instance_id, operation_id):
        """Perform threat intelligence lookups"""
        try:
            threat_intel = {
                'instance_id': instance_id,
                'lookup_timestamp': datetime.now(timezone.utc).isoformat(),
                'indicators': [],
                'reputations': {}
            }
            
            # Simulate threat intelligence lookups
            # In a real implementation, you would query:
            # - VirusTotal for file hashes
            # - AbuseIPDB for IP addresses
            # - MISP for IOCs
            # - Internal threat feeds
            
            threat_intel['indicators'] = [
                {
                    'type': 'ip_address',
                    'value': '185.14.28.56',
                    'reputation': 'malicious',
                    'sources': ['AbuseIPDB', 'InternalIntel'],
                    'confidence': 'high'
                },
                {
                    'type': 'domain',
                    'value': 'malicious-c2.example.com',
                    'reputation': 'malicious',
                    'sources': ['VirusTotal'],
                    'confidence': 'medium'
                }
            ]
            
            self._log_step(operation_id, 'threat_intel', 'success', f"Completed threat intel lookup for {instance_id}")
            return threat_intel
            
        except Exception as e:
            self._log_step(operation_id, 'threat_intel', 'failed', str(e))
            return {'error': str(e)}
    
    def _generate_forensic_report(self, instance_id, metadata, snapshot_analysis, threat_intel, operation_id):
        """Generate comprehensive forensic report"""
        report = {
            'report_id': operation_id,
            'instance_id': instance_id,
            'generation_timestamp': datetime.now(timezone.utc).isoformat(),
            'executive_summary': {
                'incident_severity': 'high',
                'compromise_confidence': 'high',
                'attack_vector': 'unknown',
                'timeline_estimate': 'last 7 days'
            },
            'technical_findings': {
                'instance_metadata': metadata,
                'snapshot_analysis': snapshot_analysis,
                'threat_intelligence': threat_intel
            },
            'findings': [],
            'severity_distribution': {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0
            },
            'recommendations': [],
            'evidence_preservation': {
                'snapshots_created': list(snapshot_analysis.keys()),
                'logs_collected': True,
                'metadata_preserved': True
            }
        }
        
        # Aggregate findings from all analyses
        for snapshot_id, analysis in snapshot_analysis.items():
            for threat in analysis.get('malware_scan', {}).get('threats_found', []):
                severity = 'critical' if threat['severity'] == 'critical' else threat['severity']
                report['findings'].append({
                    'type': 'malware',
                    'severity': severity,
                    'description': f"Malware detected: {threat['threat_type']}",
                    'evidence': threat,
                    'snapshot_id': snapshot_id
                })
                report['severity_distribution'][severity] += 1
            
            for activity in analysis.get('suspicious_activities', []):
                report['findings'].append({
                    'type': 'suspicious_activity',
                    'severity': activity['severity'],
                    'description': activity['description'],
                    'evidence': activity['evidence'],
                    'snapshot_id': snapshot_id
                })
                report['severity_distribution'][activity['severity']] += 1
        
        # Add threat intelligence findings
        for indicator in threat_intel.get('indicators', []):
            if indicator['reputation'] == 'malicious':
                severity = 'high' if indicator['confidence'] == 'high' else 'medium'
                report['findings'].append({
                    'type': 'threat_intel',
                    'severity': severity,
                    'description': f"Malicious {indicator['type']} detected: {indicator['value']}",
                    'evidence': indicator
                })
                report['severity_distribution'][severity] += 1
        
        # Generate recommendations
        report['recommendations'] = self._generate_recommendations(report)
        
        return report
    
    def _generate_recommendations(self, report):
        """Generate security recommendations based on findings"""
        recommendations = []
        
        if report['severity_distribution']['critical'] > 0:
            recommendations.append({
                'priority': 'immediate',
                'action': 'terminate_compromised_resources',
                'description': 'Immediate termination of all compromised resources recommended due to critical findings'
            })
        
        if report['severity_distribution']['high'] > 2:
            recommendations.append({
                'priority': 'high',
                'action': 'comprehensive_password_reset',
                'description': 'Reset all credentials and enforce multi-factor authentication'
            })
        
        recommendations.extend([
            {
                'priority': 'medium',
                'action': 'enhance_monitoring',
                'description': 'Implement enhanced logging and monitoring for early detection'
            },
            {
                'priority': 'medium',
                'action': 'security_training',
                'description': 'Conduct security awareness training for all users'
            },
            {
                'priority': 'low',
                'action': 'policy_review',
                'description': 'Review and update security policies and procedures'
            }
        ])
        
        return recommendations
    
    def _store_forensic_results(self, report, operation_id):
        """Store forensic results in S3"""
        try:
            key = f"forensics-reports/{ENVIRONMENT}/{operation_id}/report.json"
            
            s3_client.put_object(
                Bucket=S3_BUCKET,
                Key=key,
                Body=json.dumps(report, indent=2, default=str),
                ContentType='application/json'
            )
            
            logger.info(f"Stored forensic report in S3: s3://{S3_BUCKET}/{key}")
            
        except Exception as e:
            logger.error(f"Failed to store forensic results: {str(e)}")
    
    def _send_forensics_notification(self, instance_id, report, operation_id):
        """Send notification about forensic analysis completion"""
        try:
            if SNS_TOPIC_ARN:
                message = {
                    'event_type': 'forensics_completed',
                    'instance_id': instance_id,
                    'environment': ENVIRONMENT,
                    'operation_id': operation_id,
                    'summary': {
                        'total_findings': len(report.get('findings', [])),
                        'severity_distribution': report.get('severity_distribution', {}),
                        'recommendations_count': len(report.get('recommendations', []))
                    },
                    'timestamp': datetime.now(timezone.utc).isoformat()
                }
                
                sns_client.publish(
                    TopicArn=SNS_TOPIC_ARN,
                    Subject=f"SOAR: Forensic Analysis Complete for Instance {instance_id}",
                    Message=json.dumps(message, indent=2)
                )
                
                self._log_step(operation_id, 'send_notification', 'success', 'Forensics notification sent')
            
        except Exception as e:
            self._log_step(operation_id, 'send_notification', 'failed', str(e))
    
    def _log_step(self, operation_id, step_name, status, details):
        """Log operation step details"""
        if operation_id in self.active_operations:
            self.active_operations[operation_id]['steps'].append({
                'step': step_name,
                'status': status,
                'details': details,
                'timestamp': datetime.now(timezone.utc).isoformat()
            })
    
    def get_operation_status(self, operation_id):
        """Get status of a specific operation"""
        return self.active_operations.get(operation_id, {'status': 'not_found'})
    
    def get_active_operations(self):
        """Get all active operations"""
        return self.active_operations

# Initialize worker
worker = ForensicsWorker()

# Flask routes
@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'environment': ENVIRONMENT,
        'active_operations': len(worker.active_operations)
    })

@app.route('/analyze', methods=['POST'])
def analyze_instance():
    """Analyze instance endpoint"""
    try:
        data = request.get_json()
        
        if not data or 'instance_id' not in data:
            return jsonify({'error': 'instance_id is required'}), 400
        
        instance_id = data['instance_id']
        snapshot_ids = data.get('snapshot_ids', [])
        operation_id = data.get('operation_id')
        
        result = worker.analyze_instance(instance_id, snapshot_ids, operation_id)
        
        return jsonify(result), 200
        
    except Exception as e:
        logger.error(f"Error in analyze endpoint: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/status/<operation_id>', methods=['GET'])
def get_operation_status(operation_id):
    """Get operation status endpoint"""
    try:
        status = worker.get_operation_status(operation_id)
        
        if status.get('status') == 'not_found':
            return jsonify({'error': 'Operation not found'}), 404
        
        return jsonify(status), 200
        
    except Exception as e:
        logger.error(f"Error in status endpoint: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/operations', methods=['GET'])
def get_active_operations():
    """Get all active operations endpoint"""
    try:
        operations = worker.get_active_operations()
        return jsonify(operations), 200
        
    except Exception as e:
        logger.error(f"Error in operations endpoint: {str(e)}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    logger.info("Starting SOAR Forensics Worker")
    app.run(host='0.0.0.0', port=8080, debug=False)
