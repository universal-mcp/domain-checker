
from universal_mcp.servers import SingleMCPServer

from universal_mcp_domain_checker.app import DomainCheckerApp

app_instance = DomainCheckerApp()

mcp = SingleMCPServer(
    app_instance=app_instance
)

if __name__ == "__main__":
    print(f"Starting {mcp.name}...")
    mcp.run()


