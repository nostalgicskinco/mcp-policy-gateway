"""MCP Policy Gateway CLI."""
import click
from rich.console import Console

console = Console()

@click.group()
def cli():
    """MCP Policy Gateway — firewall for agent tool access."""
    pass

@cli.command()
def status():
    """Show gateway status."""
    import httpx
    try:
        resp = httpx.get("http://localhost:8400/v1/stats")
        stats = resp.json()
        console.print(f"Total: {stats['total_requests']} | Allowed: {stats['allowed']} | Denied: {stats['denied']} | Escalated: {stats['escalated']}")
    except Exception:
        console.print("[red]Gateway not reachable[/red]")

if __name__ == "__main__":
    cli()
