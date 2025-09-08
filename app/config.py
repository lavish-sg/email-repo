import os
from typing import Optional
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    """Application settings."""
    
    # API Configuration
    api_title: str = "Domain Security API"
    api_version: str = "1.0.0"
    debug: bool = False
    
    # Server Configuration
    host: str = "0.0.0.0"
    port: int = 8000
    
    # External API Keys
    ipinfo_token: Optional[str] = None
    virustotal_api_key: Optional[str] = None
    spamhaus_api_key: Optional[str] = None
    
    # Rate Limiting
    rate_limit_per_minute: int = 60
    
    # DNS Configuration
    dns_timeout: int = 20
    dns_retries: int = 3
    
    # Performance Configuration
    default_dkim_selectors: str = "default,google,selector1,selector2,k1,mandrill,s1,s2"  # Restored all 8 selectors for comprehensive checking
    
    class Config:
        env_file = ".env"
        case_sensitive = False


# Global settings instance
settings = Settings() 