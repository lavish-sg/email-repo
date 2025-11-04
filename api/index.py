"""
Vercel serverless function handler for FastAPI application.
"""
import sys
import os

# Add the project root to Python path for imports
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Import the FastAPI app
# Vercel's @vercel/python runtime automatically detects FastAPI/ASGI apps
from app.main import app

