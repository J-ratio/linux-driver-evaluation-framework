"""Command-line interface for Linux Driver Evaluation Framework."""

import click
import uvicorn
from pathlib import Path


@click.group()
def main():
    """Linux Driver Evaluation Framework CLI."""
    pass


@main.command()
@click.option('--host', default='127.0.0.1', help='Host to bind to')
@click.option('--port', default=8000, help='Port to bind to')
@click.option('--reload', is_flag=True, help='Enable auto-reload for development')
def serve(host, port, reload):
    """Start the web server."""
    click.echo(f"Starting Linux Driver Evaluation Framework web server...")
    click.echo(f"Server will be available at http://{host}:{port}")
    
    uvicorn.run(
        "src.api.web_app:app",
        host=host,
        port=port,
        reload=reload
    )


@main.command()
def version():
    """Show version information."""
    click.echo("Linux Driver Evaluation Framework v1.0.0")


if __name__ == '__main__':
    main()