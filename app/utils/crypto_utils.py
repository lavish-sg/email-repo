import base64
import hashlib
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from typing import Tuple, Dict, Any
import secrets
import string
from datetime import datetime, timezone
import ssl
import socket


class DKIMKeyGenerator:
    """DKIM key pair generator."""
    
    @staticmethod
    def generate_rsa_key_pair(key_size: int = 2048) -> Tuple[str, str]:
        """
        Generate RSA key pair for DKIM.
        
        Args:
            key_size: RSA key size in bits (1024, 2048, 4096)
            
        Returns:
            Tuple of (private_key_pem, public_key_dns)
        """
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        
        # Get public key
        public_key = private_key.public_key()
        
        # Serialize private key to PEM format
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        
        # Serialize public key to DNS format
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Encode to base64 for DNS
        public_key_dns = base64.b64encode(public_key_bytes).decode('utf-8')
        
        return private_key_pem, public_key_dns
    
    @staticmethod
    def generate_selector() -> str:
        """Generate a random DKIM selector."""
        # Generate a random selector with letters and numbers
        chars = string.ascii_lowercase + string.digits
        return ''.join(secrets.choice(chars) for _ in range(16))
    
    @staticmethod
    def create_dkim_dns_record(selector: str, public_key: str, algorithm: str = "rsa-sha256") -> str:
        """
        Create DKIM DNS TXT record.
        
        Args:
            selector: DKIM selector
            public_key: Base64 encoded public key
            algorithm: Signing algorithm
            
        Returns:
            DKIM DNS TXT record
        """
        return f'v=DKIM1; k=rsa; p={public_key}'
    
    @staticmethod
    def validate_public_key(public_key: str) -> Dict[str, Any]:
        """
        Validate DKIM public key.
        
        Args:
            public_key: Base64 encoded public key
            
        Returns:
            Validation result
        """
        result = {
            'valid': False,
            'key_size': None,
            'algorithm': None,
            'error': None
        }
        
        try:
            # Decode base64
            key_bytes = base64.b64decode(public_key)
            
            # Load public key
            public_key_obj = serialization.load_der_public_key(
                key_bytes,
                backend=default_backend()
            )
            
            # Get key size
            if hasattr(public_key_obj, 'key_size'):
                result['key_size'] = public_key_obj.key_size
            
            # Determine algorithm
            result['algorithm'] = 'rsa-sha256'
            result['valid'] = True
            
        except Exception as e:
            result['error'] = str(e)
        
        return result


class SPFGenerator:
    """SPF record generator."""
    
    # Common email provider SPF includes
    PROVIDER_INCLUDES = {
        'google': '_spf.google.com',
        'outlook': '_spf.protection.outlook.com',
        'office365': '_spf.protection.outlook.com',
        'sendgrid': '_spf.sendgrid.net',
        'mailgun': '_spf.mailgun.org',
        'amazonses': '_spf.amazonaws.com',
        'mailchimp': '_spf.mailchimp.com',
        'constant_contact': '_spf.constantcontact.com',
        'hubspot': '_spf.hubspot.com',
        'salesforce': '_spf.salesforce.com',
        'zendesk': '_spf.zendesk.com',
        'intercom': '_spf.intercom.io',
        'klaviyo': '_spf.klaviyo.com',
        'convertkit': '_spf.convertkit.com',
        'activecampaign': '_spf.activecampaign.com',
        'drip': '_spf.drip.com',
        'getresponse': '_spf.getresponse.com',
        'aweber': '_spf.aweber.com',
        'infusionsoft': '_spf.infusionsoft.com',
        'ontraport': '_spf.ontraport.com'
    }
    
    @staticmethod
    def generate_spf_record(
        providers: list = None,
        include_all: bool = False,
        custom_mechanisms: list = None
    ) -> str:
        """
        Generate SPF record.
        
        Args:
            providers: List of email providers to include
            include_all: Include all common providers
            custom_mechanisms: Custom SPF mechanisms
            
        Returns:
            Generated SPF record
        """
        mechanisms = ['v=spf1']
        
        # Add provider includes
        if include_all:
            for provider, include in SPFGenerator.PROVIDER_INCLUDES.items():
                mechanisms.append(f'include:{include}')
        elif providers:
            for provider in providers:
                if provider.lower() in SPFGenerator.PROVIDER_INCLUDES:
                    mechanisms.append(f'include:{SPFGenerator.PROVIDER_INCLUDES[provider.lower()]}')
        
        # Add custom mechanisms
        if custom_mechanisms:
            mechanisms.extend(custom_mechanisms)
        
        return ' '.join(mechanisms)
    
    @staticmethod
    def get_available_providers() -> Dict[str, str]:
        """Get list of available email providers."""
        return SPFGenerator.PROVIDER_INCLUDES.copy()


class DMARCGenerator:
    """DMARC record generator."""
    
    @staticmethod
    def generate_dmarc_record(
        policy: str = "none",
        subdomain_policy: str = "none",
        percentage: int = 100,
        report_uri: str = None,
        forensic_uri: str = None,
        adkim: str = "r",
        aspf: str = "r"
    ) -> str:
        """
        Generate DMARC record.
        
        Args:
            policy: DMARC policy (none, quarantine, reject)
            subdomain_policy: Subdomain policy
            percentage: Percentage of messages to filter
            report_uri: URI for aggregate reports
            forensic_uri: URI for forensic reports
            adkim: DKIM alignment mode
            aspf: SPF alignment mode
            
        Returns:
            Generated DMARC record
        """
        parts = ['v=DMARC1']
        
        # Add policy
        parts.append(f'p={policy}')
        
        # Add subdomain policy
        parts.append(f'sp={subdomain_policy}')
        
        # Add percentage
        if percentage != 100:
            parts.append(f'pct={percentage}')
        
        # Add alignment modes
        parts.append(f'adkim={adkim}')
        parts.append(f'aspf={aspf}')
        
        # Add report URIs
        if report_uri:
            rua_value = report_uri if report_uri.startswith('mailto:') else f'mailto:{report_uri}'
            parts.append(f'rua={rua_value}')
        
        if forensic_uri:
            ruf_value = forensic_uri if forensic_uri.startswith('mailto:') else f'mailto:{forensic_uri}'
            parts.append(f'ruf={ruf_value}')
        
        return '; '.join(parts)
    
    @staticmethod
    def get_policy_recommendations() -> Dict[str, Dict[str, str]]:
        """Get DMARC policy recommendations."""
        return {
            'none': {
                'description': 'Monitor only - no action taken',
                'recommendation': 'Use for initial setup and testing',
                'risk': 'low'
            },
            'quarantine': {
                'description': 'Quarantine suspicious emails',
                'recommendation': 'Use after monitoring phase',
                'risk': 'medium'
            },
            'reject': {
                'description': 'Reject suspicious emails',
                'recommendation': 'Use only after thorough testing',
                'risk': 'high'
            }
        }


class MTASTSGenerator:
    """MTA-STS record and policy generator."""
    
    @staticmethod
    def generate_mtasts_record(domain: str) -> str:
        """
        Generate MTA-STS DNS TXT record.
        
        Args:
            domain: Domain name
            
        Returns:
            MTA-STS DNS TXT record
        """
        # Use a dynamic policy id so updates propagate quickly across caches
        id_value = str(int(datetime.now(timezone.utc).timestamp()))
        return f'v=STSv1; id={id_value}'
    
    @staticmethod
    def generate_mtasts_policy(
        mode: str = "testing",
        max_age: int = 86400,
        mx_records: list = None,
        include_subdomains: bool = False
    ) -> str:
        """
        Generate MTA-STS policy file content.
        
        Args:
            mode: MTA-STS mode (testing, enforce, none)
            max_age: Policy max age in seconds
            mx_records: List of MX records
            include_subdomains: Include subdomains
            
        Returns:
            MTA-STS policy content
        """
        if mx_records is None:
            mx_records = []
        
        # Normalize and clamp inputs
        valid_modes = ['testing', 'enforce', 'none']
        normalized_mode = mode if mode in valid_modes else 'testing'
        clamped_max_age = max(300, min(int(max_age), 31536000))

        policy_lines = [
            'version: STSv1',
            f'mode: {normalized_mode}',
            f'max_age: {clamped_max_age}'
        ]
        
        if mx_records:
            # Deduplicate and normalize MX entries
            seen = set()
            normalized_mx = []
            for mx in mx_records:
                entry = str(mx).strip()
                if entry and entry not in seen:
                    seen.add(entry)
                    normalized_mx.append(entry)
            if normalized_mx:
                policy_lines.append('mx:')
                for mx in normalized_mx:
                    policy_lines.append(f'  - {mx}')
        
        if include_subdomains:
            policy_lines.append('subdomains: true')
        
        return '\n'.join(policy_lines)
    
    @staticmethod
    def validate_mtasts_policy(policy_content: str) -> Dict[str, Any]:
        """
        Validate MTA-STS policy content.
        
        Args:
            policy_content: MTA-STS policy content
            
        Returns:
            Validation result
        """
        result = {
            'valid': False,
            'version': None,
            'mode': None,
            'max_age': None,
            'mx_records': [],
            'include_subdomains': False,
            'errors': [],
            'warnings': []
        }
        
        try:
            lines = policy_content.strip().split('\n')
            
            for line in lines:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                if ':' in line:
                    key, value = line.split(':', 1)
                    key = key.strip()
                    value = value.strip()
                    
                    if key == 'version':
                        result['version'] = value
                        if value != 'STSv1':
                            result['errors'].append('Invalid version - must be STSv1')
                    elif key == 'mode':
                        result['mode'] = value
                        if value not in ['testing', 'enforce', 'none']:
                            result['errors'].append('Invalid mode - must be testing, enforce, or none')
                    elif key == 'max_age':
                        try:
                            result['max_age'] = int(value)
                            if result['max_age'] < 300 or result['max_age'] > 31536000:
                                result['warnings'].append('Max age should be between 300 and 31536000 seconds')
                        except ValueError:
                            result['errors'].append('Invalid max_age - must be a number')
                    elif key == 'mx':
                        # MX records are handled separately
                        continue
                    elif key == 'subdomains':
                        result['include_subdomains'] = value.lower() == 'true'
            
            # Validate required fields
            if not result['version']:
                result['errors'].append('Missing version field')
            if not result['mode']:
                result['errors'].append('Missing mode field')
            if not result['max_age']:
                result['errors'].append('Missing max_age field')
            
            # Check if valid
            result['valid'] = len(result['errors']) == 0
            
        except Exception as e:
            result['errors'].append(f'Error parsing policy: {str(e)}')
        
        return result


class TLSRPTGenerator:
    """TLS-RPT record generator."""
    
    @staticmethod
    def generate_tlsrpt_record(
        domain: str,
        report_uri: str = "mailto:tls-reports@example.com",
        include_subdomains: bool = False
    ) -> str:
        """
        Generate TLS-RPT DNS TXT record.
        
        Args:
            domain: Domain name
            report_uri: URI for TLS reports
            include_subdomains: Include subdomains
            
        Returns:
            TLS-RPT DNS TXT record
        """
        # Support multiple URIs via comma-separated list and normalize prefixes
        uri_candidates = [u.strip() for u in report_uri.split(',')] if report_uri else []
        normalized_uris = []
        seen = set()
        for uri in uri_candidates:
            if not uri:
                continue
            if uri.startswith('mailto:') or uri.startswith('https:'):
                normalized = uri
            else:
                # If it looks like an email, prefix with mailto:
                normalized = f'mailto:{uri}'
            if normalized not in seen:
                seen.add(normalized)
                normalized_uris.append(normalized)
        # Fallback to default if none provided after normalization
        if not normalized_uris:
            normalized_uris = [report_uri if report_uri else 'mailto:tls-reports@example.com']
        record = f"v=TLSRPTv1; rua={','.join(normalized_uris)}"
        
        if include_subdomains:
            record += '; subdomains=true'
        
        return record
    
    @staticmethod
    def validate_tlsrpt_record(record: str) -> Dict[str, Any]:
        """
        Validate TLS-RPT record.
        
        Args:
            record: TLS-RPT record
            
        Returns:
            Validation result
        """
        result = {
            'valid': False,
            'version': None,
            'rua': None,
            'include_subdomains': False,
            'errors': [],
            'warnings': []
        }
        
        try:
            parts = record.split(';')
            for part in parts:
                part = part.strip()
                if '=' in part:
                    key, value = part.split('=', 1)
                    key = key.strip()
                    value = value.strip()
                    
                    if key == 'v':
                        result['version'] = value
                        if value != 'TLSRPTv1':
                            result['errors'].append('Invalid version - must be TLSRPTv1')
                    elif key == 'rua':
                        result['rua'] = value
                        if not value.startswith('mailto:'):
                            result['warnings'].append('Report URI should start with mailto:')
                    elif key == 'subdomains':
                        result['include_subdomains'] = value.lower() == 'true'
            
            # Validate required fields
            if not result['version']:
                result['errors'].append('Missing version field')
            if not result['rua']:
                result['errors'].append('Missing rua field')
            
            # Check if valid
            result['valid'] = len(result['errors']) == 0
            
        except Exception as e:
            result['errors'].append(f'Error parsing record: {str(e)}')
        
        return result 


def validate_certificate(cert: Dict[str, Any]) -> bool:
    """
    Validate SSL certificate.
    
    Args:
        cert: Certificate dictionary from ssl.getpeercert()
        
    Returns:
        True if certificate is valid, False otherwise
    """
    try:
        # Check if certificate has required fields
        if not cert or 'notBefore' not in cert or 'notAfter' not in cert:
            return False
        
        # Parse dates
        not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
        not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
        
        # Get current time
        now = datetime.now(timezone.utc)
        
        # Check if certificate is currently valid
        if now < not_before or now > not_after:
            return False
        
        # Check if certificate has subject and issuer
        if 'subject' not in cert or 'issuer' not in cert:
            return False
        
        return True
        
    except Exception:
        return False


def check_certificate_expiry(cert: Dict[str, Any]) -> int:
    """
    Calculate days until certificate expiry.
    
    Args:
        cert: Certificate dictionary from ssl.getpeercert()
        
    Returns:
        Days until expiry (negative if expired)
    """
    try:
        if not cert or 'notAfter' not in cert:
            return -1
        
        # Parse expiry date
        not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
        
        # Get current time
        now = datetime.now(timezone.utc)
        
        # Calculate difference
        delta = not_after - now
        return delta.days
        
    except Exception:
        return -1


def get_certificate_info(hostname: str, port: int = 443) -> Dict[str, Any]:
    """
    Get detailed certificate information for a host.
    
    Args:
        hostname: Hostname to check
        port: Port to connect to
        
    Returns:
        Certificate information dictionary
    """
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                
                return {
                    'subject': dict(x[0] for x in cert['subject']),
                    'issuer': dict(x[0] for x in cert['issuer']),
                    'not_before': cert['notBefore'],
                    'not_after': cert['notAfter'],
                    'serial_number': cert['serialNumber'],
                    'version': cert['version'],
                    'san': cert.get('subjectAltName', []),
                    'is_valid': validate_certificate(cert),
                    'days_until_expiry': check_certificate_expiry(cert),
                    'tls_version': ssock.version(),
                    'cipher': ssock.cipher()
                }
                
    except Exception as e:
        return {
            'error': str(e),
            'is_valid': False,
            'days_until_expiry': -1
        } 