"""
SecureCode AI - Model Context Protocol (MCP) Package
"""
import sys
import os

MCP_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.dirname(MCP_DIR)
for path in (BASE_DIR, MCP_DIR):
    if path not in sys.path:
        sys.path.insert(0, path)

try:
    from MCP.mcp_client.client import SecureCodeMCPClient, get_mcp_client
    from MCP.mcp_server.security_server import mcp as server_instance
except ImportError:
    from mcp_client.client import SecureCodeMCPClient, get_mcp_client
    from mcp_server.security_server import mcp as server_instance

__all__ = ["SecureCodeMCPClient", "get_mcp_client", "server_instance"]
