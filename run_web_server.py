#!/usr/bin/env python3
"""
Simple script to start the Linux Driver Evaluation Framework web server.
"""

import sys
import os
from pathlib import Path

# Add src directory to Python path
src_path = Path(__file__).parent / "src"
sys.path.insert(0, str(src_path))

if __name__ == "__main__":
    import uvicorn
    
    print("Starting Linux Driver Evaluation Framework Web Server...")
    print("Server will be available at http://127.0.0.1:8000")
    print("Press Ctrl+C to stop the server")
    
    try:
        uvicorn.run(
            "api.web_app:app",
            host="127.0.0.1",
            port=8000,
            reload=True
        )
    except KeyboardInterrupt:
        print("\nServer stopped.")