"""
NexusController main entry point

Allows running the application as a module: python -m nexuscontroller
"""

import sys
import argparse
from pathlib import Path

def main():
    """Main entry point for NexusController"""
    parser = argparse.ArgumentParser(description="NexusController v2.0 - Enterprise Infrastructure Management")
    parser.add_argument("--mode", choices=["api", "controller", "websocket"], default="api",
                      help="Run mode: api (REST API server), controller (main controller), websocket (WebSocket server)")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8000, help="Port to bind to (default: 8000)")
    parser.add_argument("--config", type=Path, help="Path to configuration file")

    args = parser.parse_args()

    if args.mode == "api":
        # Run API server
        from nexuscontroller.api.server import main as api_main
        sys.exit(api_main())
    elif args.mode == "websocket":
        # Run WebSocket server
        from nexuscontroller.api.websocket import main as ws_main
        sys.exit(ws_main())
    elif args.mode == "controller":
        # Run main controller
        from nexuscontroller.core.controller import main as controller_main
        sys.exit(controller_main())
    else:
        parser.print_help()
        return 1

if __name__ == "__main__":
    sys.exit(main())
