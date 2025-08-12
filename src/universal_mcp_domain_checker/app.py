from universal_mcp.applications import APIApplication
from universal_mcp.integrations import Integration
import json
import logging
import sys
import dns.resolver
import requests
import time
from typing import Optional, List, Dict, Any

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stderr)
    ]
)

logger = logging.getLogger("domain_checker")

# Constants
RDAP_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
USER_AGENT = "DomainCheckerBot/1.0"

# Top TLDs to check
TOP_TLDS = [
    "com", "net", "org", "io", "co", "app", "dev", "ai", 
    "me", "info", "xyz", "online", "site", "tech"
]

class DomainCheckerApp(APIApplication):
    """
    Base class for Universal MCP Applications.
    """
    def __init__(self, integration: Integration = None, **kwargs) -> None:
        super().__init__(name="domain-checker", integration=integration, **kwargs)

    async def get_rdap_data(self, domain: str) -> Optional[Dict[str, Any]]:
        """Get RDAP data for a domain"""
        try:
            # Special case for .ch and .li domains
            tld = domain.split('.')[-1].lower()
            if tld in ['ch', 'li']:
                rdap_url = f"https://rdap.nic.{tld}/domain/{domain}"
            else:
                # Use common RDAP servers for known TLDs
                if tld in ["com", "net"]:
                    rdap_url = f"https://rdap.verisign.com/{tld}/v1/domain/{domain}"
                elif tld == "org":
                    rdap_url = f"https://rdap.publicinterestregistry.org/rdap/domain/{domain}"
                else:
                    rdap_url = f"https://rdap.org/domain/{domain}"
            
            headers = {
                "Accept": "application/rdap+json",
                "User-Agent": USER_AGENT
            }
            
            response = requests.get(rdap_url, headers=headers, timeout=5)
            if response.status_code == 200:
                return response.json()
            return None
        except Exception as e:
            logger.error(f"RDAP error for {domain}: {e}")
            return None

    async def check_dns(self, domain: str) -> bool:
        """Check if a domain has DNS records"""
        try:
            answers = dns.resolver.resolve(domain, 'A')
            return True
        except:
            try:
                answers = dns.resolver.resolve(domain, 'NS')
                return True
            except:
                return False

    async def check_domain_tool(self, domain: str) -> str:
        """Check if a domain is available for registration"""
        logger.info(f"Checking domain: {domain}")
        
        # First check DNS
        has_dns = await self.check_dns(domain)
        
        if has_dns:
            # Domain exists, get RDAP data if possible
            rdap_data = await self.get_rdap_data(domain)
            
            if rdap_data:
                # Extract data from RDAP
                registrar = "Unknown"
                reg_date = "Unknown"
                exp_date = "Unknown"
                
                # Extract registrar
                entities = rdap_data.get("entities", [])
                for entity in entities:
                    if "registrar" in entity.get("roles", []):
                        vcard = entity.get("vcardArray", [])
                        if len(vcard) > 1 and isinstance(vcard[1], list):
                            for entry in vcard[1]:
                                if entry[0] in ["fn", "org"] and len(entry) > 3:
                                    registrar = entry[3]
                                    break
                
                # Extract dates
                events = rdap_data.get("events", [])
                for event in events:
                    if event.get("eventAction") == "registration":
                        reg_date = event.get("eventDate", "Unknown")
                    elif event.get("eventAction") == "expiration":
                        exp_date = event.get("eventDate", "Unknown")
                
                return f"""
Domain: {domain}
Status: Registered
Registrar: {registrar}
Registration Date: {reg_date}
Expiration Date: {exp_date}
"""
            else:
                return f"""
Domain: {domain}
Status: Registered
Note: Domain has DNS records but RDAP data couldn't be retrieved
"""
        
        # Try RDAP one more time even if DNS not found
        rdap_data = await self.get_rdap_data(domain)
        if rdap_data:
            return f"""
Domain: {domain}
Status: Registered
Note: Domain found in RDAP registry
"""
        
        # If we get here, the domain is likely available
        return f"""
Domain: {domain}
Status: Available
Note: No DNS records or RDAP data found
"""

    async def check_tlds_tool(self, keyword: str) -> str:
        """Check a keyword across top TLDs"""
        logger.info(f"Checking keyword: {keyword} across TLDs")
        
        results = []
        available = []
        
        # Check each TLD in sequence
        for tld in TOP_TLDS:
            domain = f"{keyword}.{tld}"
            has_dns = await self.check_dns(domain)
            
            if not has_dns:
                # Double-check with RDAP if no DNS
                rdap_data = await self.get_rdap_data(domain)
                if not rdap_data:
                    available.append(domain)
        
        # Format the response
        response = f"Keyword: {keyword}\n"
        response += f"TLDs checked: {len(TOP_TLDS)}\n"
        response += f"Available domains: {len(available)}\n\n"
        
        if available:
            response += "Available domains:\n"
            for domain in available:
                response += f"- {domain}\n"
        else:
            response += "No available domains found for this keyword.\n"
        
        return response

    

    def list_tools(self):
        """
        Lists the available tools (methods) for this application.
        """
        return [
            self.check_domain_tool,
            self.check_tlds_tool
        ]
