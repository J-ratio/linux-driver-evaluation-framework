"""Command-line interface for Linux Driver Evaluation Framework."""

import click
import uvicorn
import subprocess
import sys
from pathlib import Path
from src.config.manager import DefaultConfigurationManager


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


@main.group()
def kernel():
    """Kernel version management commands."""
    pass


@kernel.command('list')
def list_kernels():
    """List available kernel versions."""
    config_manager = DefaultConfigurationManager()
    available_versions = config_manager.get_available_kernel_versions()
    compilation_config = config_manager.load_config().get("compilation", {})
    current_version = compilation_config.get("kernel_version", "5.15")
    version_configs = compilation_config.get("kernel_version_configs", {})
    
    click.echo("Available kernel versions:")
    click.echo("=" * 50)
    
    for version in available_versions:
        config = version_configs.get(version, {})
        description = config.get("description", f"Kernel {version}")
        marker = " (current)" if version == current_version else ""
        click.echo(f"  {version}: {description}{marker}")
    
    click.echo(f"\nCurrent default: {current_version}")


@kernel.command('set')
@click.argument('version')
def set_kernel(version):
    """Set the default kernel version."""
    config_manager = DefaultConfigurationManager()
    available_versions = config_manager.get_available_kernel_versions()
    
    if version not in available_versions:
        click.echo(f"Error: Kernel version '{version}' is not supported.", err=True)
        click.echo(f"Available versions: {', '.join(available_versions)}")
        sys.exit(1)
    
    # Load current config
    config = config_manager.load_config()
    config["compilation"]["kernel_version"] = version
    
    # Save updated config
    if config_manager.save_config(config):
        click.echo(f"Successfully set default kernel version to {version}")
        
        # Get version info
        kernel_config = config_manager.get_kernel_version_config(version)
        click.echo(f"Description: {kernel_config['description']}")
        click.echo(f"Docker image: {kernel_config['docker_image']}")
        click.echo(f"Headers package: {kernel_config['headers_package']}")
    else:
        click.echo("Error: Failed to save configuration", err=True)
        sys.exit(1)


@kernel.command('setup')
@click.argument('version', required=False)
@click.option('--force', is_flag=True, help='Force rebuild even if image exists')
def setup_kernel(version, force):
    """Set up Docker environment for a kernel version."""
    config_manager = DefaultConfigurationManager()
    
    if not version:
        # Use current default version
        version = config_manager.load_config().get("compilation", {}).get("kernel_version", "5.15")
    
    available_versions = config_manager.get_available_kernel_versions()
    if version not in available_versions:
        click.echo(f"Error: Kernel version '{version}' is not supported.", err=True)
        click.echo(f"Available versions: {', '.join(available_versions)}")
        sys.exit(1)
    
    click.echo(f"Setting up Docker environment for kernel {version}...")
    
    # Run the setup script
    try:
        cmd = [sys.executable, "scripts/setup_docker_env.py", version]
        if force:
            # Add force flag if the script supports it
            pass
        
        result = subprocess.run(cmd, check=True)
        click.echo(f"Successfully set up kernel {version} environment")
        
    except subprocess.CalledProcessError as e:
        click.echo(f"Error: Failed to set up kernel {version} environment", err=True)
        sys.exit(1)
    except FileNotFoundError:
        click.echo("Error: Setup script not found. Please run from project root.", err=True)
        sys.exit(1)


@kernel.command('info')
@click.argument('version', required=False)
def kernel_info(version):
    """Show information about a kernel version."""
    config_manager = DefaultConfigurationManager()
    
    if not version:
        # Use current default version
        version = config_manager.load_config().get("compilation", {}).get("kernel_version", "5.15")
    
    available_versions = config_manager.get_available_kernel_versions()
    if version not in available_versions:
        click.echo(f"Error: Kernel version '{version}' is not supported.", err=True)
        click.echo(f"Available versions: {', '.join(available_versions)}")
        sys.exit(1)
    
    kernel_config = config_manager.get_kernel_version_config(version)
    
    click.echo(f"Kernel Version: {version}")
    click.echo("=" * 30)
    click.echo(f"Description: {kernel_config['description']}")
    click.echo(f"Docker base image: {kernel_config['docker_image']}")
    click.echo(f"Headers package: {kernel_config['headers_package']}")
    
    # Check if Docker image exists
    try:
        image_name = f"linux-driver-eval:kernel-{version}"
        result = subprocess.run(['docker', 'images', '-q', image_name], 
                              capture_output=True, text=True, timeout=10)
        if result.stdout.strip():
            click.echo(f"Docker image: {image_name} (available)")
        else:
            click.echo(f"Docker image: {image_name} (not built)")
            click.echo(f"Run 'driver-eval kernel setup {version}' to build it")
    except Exception:
        click.echo("Docker image: Status unknown (Docker not available)")


if __name__ == '__main__':
    main()