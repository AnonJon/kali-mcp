"""FastMCP application setup and tool registration."""

from mcp.server.fastmcp import FastMCP

mcp = FastMCP(
    "kali-mcp",
    instructions=(
        "Kali Linux offensive security MCP server. Provides 30 structured tools "
        "covering reconnaissance, web scanning, TLS analysis, exploitation, "
        "password cracking, networking, and shell access. All tools return "
        "structured JSON output. Targets must be authorized for testing."
    ),
)

# Tool modules register themselves on import via the shared `mcp` instance
from kali_mcp.tools import recon  # noqa: F401, E402
from kali_mcp.tools import web  # noqa: F401, E402
from kali_mcp.tools import tls  # noqa: F401, E402
from kali_mcp.tools import exploit  # noqa: F401, E402
from kali_mcp.tools import passwords  # noqa: F401, E402
from kali_mcp.tools import network  # noqa: F401, E402
from kali_mcp.tools import shell  # noqa: F401, E402
