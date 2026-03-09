import json
import os
import logging
import requests  # type: ignore
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

class ThreatIntelService:
    """Service to aggregate threat intelligence from multiple sources."""
    
    def __init__(self):
        self.vt_api_key = os.environ.get('VIRUSTOTAL_API_KEY')
        self.abuse_api_key = os.environ.get('ABUSEIPDB_API_KEY')
        
    def get_ip_report(self, ip_address: str) -> Dict[str, Any]:
        """Get combined report for an IP address."""
        report = {
            "ip": ip_address,
            "virustotal": self._query_virustotal(ip_address),
            "abuseipdb": self._query_abuseipdb(ip_address)
        }
        return report

    def _query_virustotal(self, ip_address: str) -> Dict[str, Any]:
        """Query VirusTotal V3 API for IP reputation."""
        if not self.vt_api_key:
            logger.warning("VIRUSTOTAL_API_KEY not set")
            return {"error": "API key missing"}

        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
        headers = {"x-apikey": self.vt_api_key}
        
        try:
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            data = response.json()
            stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            return {
                    "malicious": stats.get('malicious', 0),
                    "suspicious": stats.get('suspicious', 0),
                    "harmless": stats.get('harmless', 0),
                    "undetected": stats.get('undetected', 0)
                }
        except Exception as e:
            logger.error(f"VirusTotal query failed: {str(e)}")
            return {"error": str(e)}

    def _query_abuseipdb(self, ip_address: str) -> Dict[str, Any]:
        """Query AbuseIPDB V2 API for IP reputation."""
        if not self.abuse_api_key:
            logger.warning("ABUSEIPDB_API_KEY not set")
            return {"error": "API key missing"}

        url = "https://api.abuseipdb.com/api/v2/check"
        params = {
            'ipAddress': ip_address,
            'maxAgeInDays': '90'
        }
        
        headers = {
            'Accept': 'application/json',
            'Key': self.abuse_api_key
        }
        
        try:
            response = requests.get(url, headers=headers, params=params, timeout=10)
            response.raise_for_status()
            data = response.json()
            attributes = data.get('data', {})
            return {
                    "abuseConfidenceScore": attributes.get('abuseConfidenceScore', 0),
                    "totalReports": attributes.get('totalReports', 0),
                    "lastReportedAt": attributes.get('lastReportedAt')
                }
        except Exception as e:
            logger.error(f"AbuseIPDB query failed: {str(e)}")
            return {"error": str(e)}
