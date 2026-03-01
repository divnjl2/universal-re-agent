"""
Frida MCP Server — root launcher.

Usage:
    python frida_mcp_server.py [port]

Default port: 8766 (matches FridaMCPClient and config.yaml mcp.frida.port).

The server implements JSON-RPC 2.0 over HTTP on POST /rpc.
See src/mcp/frida_mcp_server.py for full implementation details.
"""
import sys
from pathlib import Path

# Ensure src/ is importable when running from the project root
sys.path.insert(0, str(Path(__file__).parent))

from src.mcp.frida_mcp_server import run  # noqa: E402

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8766
    run(port=port)
