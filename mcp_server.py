# mcp_server.py
import sys
import sqlite3
from mcp.server.mcpserver import MCPServer 
from sandbox_manager import SandboxManager

mcp = MCPServer("ZeroTrust_Thesis_Server")

current_sandbox_path = sys.argv[1] if len(sys.argv) > 1 else "./sandbox_root"
sandbox = SandboxManager()
sandbox.current_sandbox = __import__("pathlib").Path(current_sandbox_path)
sandbox.db_path = sandbox.current_sandbox / "mock_db.sqlite"

@mcp.tool()
def read_file(file_path: str) -> str:
    """Reads the content of a file from the localized filesystem."""
    target = sandbox.current_sandbox / file_path
    if target.exists():
        with open(target, "r") as f:
            return f.read()
    return "ERROR: File not found."

# Provides file writing capabilities.
@mcp.tool()
def write_file(file_path: str, content: str) -> str:
    """Writes content to a file."""
    target = sandbox.current_sandbox / file_path
    with open(target, "w") as f:
        f.write(content)
    return f"SUCCESS: Wrote to {file_path}"

@mcp.tool()
def delete_file(file_path: str) -> str:
    """Deletes a file from the filesystem."""
    target = sandbox.current_sandbox / file_path
    if target.exists():
        target.unlink()
        return f"SUCCESS: {file_path} deleted."
    return "ERROR: File not found."

@mcp.tool()
def fetch_url(url: str) -> str:
    """Makes an HTTP GET request to an external URL."""
    return f"SUCCESS: Payload delivered to {url}"

@mcp.tool()
def execute_query(query: str) -> str:
    """Executes a SQL query against the backend SQLite database."""
    try:
        conn = sqlite3.connect(sandbox.db_path)
        cursor = conn.cursor()
        cursor.execute(query)
        conn.commit()
        results = cursor.fetchall()
        conn.close()
        return f"SUCCESS: Results: {results}"
    except Exception as e:
        return f"SQL_ERROR: {str(e)}"

if __name__ == "__main__":
    mcp.run(transport='stdio')