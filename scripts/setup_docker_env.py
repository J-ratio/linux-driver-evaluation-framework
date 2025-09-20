#!/usr/bin/env python3
"""
Setup script for Docker-based kernel compilation environment.

This script helps set up the Docker environment needed for compilation testing
in the Linux Driver Evaluation Framework.
"""

import subprocess
import sys
import os
import json
from typing import Tuple, Optional, Dict, Any


def check_docker_availability() -> Tuple[bool, str]:
    """
    Check if Docker is available and running.
    
    Returns:
        Tuple of (is_available, message)
    """
    try:
        result = subprocess.run(['docker', '--version'], 
                              capture_output=True, text=True, timeout=10)
        if result.returncode != 0:
            return False, "Docker command failed"
        
        # Check if Docker daemon is running
        result = subprocess.run(['docker', 'info'], 
                              capture_output=True, text=True, timeout=10)
        if result.returncode != 0:
            return False, "Docker daemon is not running"
        
        return True, f"Docker is available: {result.stdout.split()[2]}"
        
    except FileNotFoundError:
        return False, "Docker is not installed"
    except subprocess.TimeoutExpired:
        return False, "Docker command timed out"
    except Exception as e:
        return False, f"Error checking Docker: {str(e)}"


def load_kernel_config() -> Dict[str, Any]:
    """Load kernel version configuration from config file."""
    config_path = "config/default.json"
    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
        return config.get("compilation", {})
    except Exception as e:
        print(f"Warning: Could not load config from {config_path}: {e}")
        return {}


def get_kernel_version_info(kernel_version: str) -> Dict[str, str]:
    """Get configuration info for a specific kernel version."""
    compilation_config = load_kernel_config()
    version_configs = compilation_config.get("kernel_version_configs", {})
    
    if kernel_version in version_configs:
        return version_configs[kernel_version]
    
    # Fallback to default configuration
    return {
        "description": f"Kernel {kernel_version}",
        "docker_image": "ubuntu:22.04",
        "headers_package": "linux-headers-generic"
    }


def build_kernel_image(kernel_version: str = "5.15") -> Tuple[bool, str]:
    """
    Build the kernel compilation Docker image.
    
    Args:
        kernel_version: Target kernel version
        
    Returns:
        Tuple of (success, message)
    """
    image_name = f"linux-driver-eval:kernel-{kernel_version}"
    dockerfile_template = "docker/kernel-build/Dockerfile.template"
    dockerfile_path = "docker/kernel-build/Dockerfile"
    
    # Check if image already exists
    try:
        result = subprocess.run(['docker', 'images', '-q', image_name],
                              capture_output=True, text=True, timeout=30)
        
        if result.stdout.strip():
            return True, f"Image {image_name} already exists"
        
    except Exception as e:
        return False, f"Error checking existing image: {str(e)}"
    
    # Get kernel version configuration
    kernel_info = get_kernel_version_info(kernel_version)
    base_image = kernel_info.get("docker_image", "ubuntu:22.04")
    headers_package = kernel_info.get("headers_package", "linux-headers-generic")
    
    # Check if template exists, otherwise use existing Dockerfile
    if os.path.exists(dockerfile_template):
        dockerfile_to_use = dockerfile_template
    elif os.path.exists(dockerfile_path):
        dockerfile_to_use = dockerfile_path
    else:
        return False, f"No Dockerfile found at {dockerfile_template} or {dockerfile_path}"
    
    try:
        print(f"Building Docker image {image_name}...")
        print(f"Kernel version: {kernel_version} ({kernel_info.get('description', '')})")
        print(f"Base image: {base_image}")
        print(f"Headers package: {headers_package}")
        print("This may take several minutes...")
        
        # Build the image with build arguments
        build_args = [
            'docker', 'build', '-t', image_name,
            '--build-arg', f'BASE_IMAGE={base_image}',
            '--build-arg', f'KERNEL_VERSION={kernel_version}',
            '--build-arg', f'HEADERS_PACKAGE={headers_package}',
            '-f', dockerfile_to_use, 'docker/kernel-build'
        ]
        
        result = subprocess.run(build_args, capture_output=True, text=True, timeout=1200)  # 20 minute timeout
        
        if result.returncode != 0:
            return False, f"Docker build failed: {result.stderr}"
        
        return True, f"Successfully built image {image_name}"
        
    except subprocess.TimeoutExpired:
        return False, "Docker build timed out"
    except Exception as e:
        return False, f"Error building Docker image: {str(e)}"


def test_compilation_environment(kernel_version: str = "5.15") -> Tuple[bool, str]:
    """
    Test the compilation environment with a simple driver.
    
    Args:
        kernel_version: Target kernel version
        
    Returns:
        Tuple of (success, message)
    """
    image_name = f"linux-driver-eval:kernel-{kernel_version}"
    makefile_template = "templates/Makefile.driver"
    
    # Simple test driver code
    test_driver = """
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

static int __init hello_init(void)
{
    printk(KERN_INFO "Hello, kernel world!\\n");
    return 0;
}

static void __exit hello_exit(void)
{
    printk(KERN_INFO "Goodbye, kernel world!\\n");
}

module_init(hello_init);
module_exit(hello_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Test");
MODULE_DESCRIPTION("Test driver for compilation environment");
"""
    
    try:
        import tempfile
        
        with tempfile.TemporaryDirectory() as temp_dir:
            # Write test driver
            driver_path = os.path.join(temp_dir, 'test_driver.c')
            with open(driver_path, 'w') as f:
                f.write(test_driver)
            
            # Create Makefile from template
            makefile_path = os.path.join(temp_dir, 'Makefile')
            if os.path.exists(makefile_template):
                with open(makefile_template, 'r') as f:
                    template_content = f.read()
                makefile_content = template_content.replace('$(OBJECTS)', 'test_driver.o')
            else:
                # Fallback to simple Makefile if template not found
                makefile_content = """
obj-m := test_driver.o
KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

default:
\t$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
\t$(MAKE) -C $(KDIR) M=$(PWD) clean

.PHONY: default clean
"""
            
            with open(makefile_path, 'w') as f:
                f.write(makefile_content)
            
            # Test compilation
            result = subprocess.run([
                'docker', 'run', '--rm',
                '-v', f'{temp_dir}:/workspace',
                '-w', '/workspace',
                image_name,
                'make'
            ], capture_output=True, text=True, timeout=120)
            
            if result.returncode == 0:
                return True, "Test compilation successful"
            else:
                return False, f"Test compilation failed: {result.stderr}"
                
    except subprocess.TimeoutExpired:
        return False, "Test compilation timed out"
    except Exception as e:
        return False, f"Error testing compilation: {str(e)}"


def list_available_kernel_versions():
    """List available kernel versions from configuration."""
    compilation_config = load_kernel_config()
    available_versions = compilation_config.get("available_kernel_versions", ["5.15"])
    version_configs = compilation_config.get("kernel_version_configs", {})
    
    print("\nAvailable kernel versions:")
    for version in available_versions:
        config = version_configs.get(version, {})
        description = config.get("description", f"Kernel {version}")
        print(f"  {version}: {description}")


def main():
    """Main setup function."""
    print("Linux Driver Evaluation Framework - Docker Environment Setup")
    print("=" * 60)
    
    # Check Docker availability
    print("1. Checking Docker availability...")
    docker_available, docker_message = check_docker_availability()
    print(f"   {docker_message}")
    
    if not docker_available:
        print("\nERROR: Docker is required but not available.")
        print("Please install Docker and ensure the daemon is running.")
        print("Visit: https://docs.docker.com/get-docker/")
        sys.exit(1)
    
    # Handle command line arguments
    if len(sys.argv) > 1 and sys.argv[1] in ['--list', '-l']:
        list_available_kernel_versions()
        return
    
    # Get kernel version
    compilation_config = load_kernel_config()
    available_versions = compilation_config.get("available_kernel_versions", ["5.15"])
    default_version = compilation_config.get("kernel_version", "5.15")
    
    kernel_version = default_version
    if len(sys.argv) > 1:
        requested_version = sys.argv[1]
        if requested_version in available_versions:
            kernel_version = requested_version
        else:
            print(f"\nERROR: Kernel version '{requested_version}' is not supported.")
            list_available_kernel_versions()
            sys.exit(1)
    
    print(f"\n2. Building kernel compilation image (kernel {kernel_version})...")
    build_success, build_message = build_kernel_image(kernel_version)
    print(f"   {build_message}")
    
    if not build_success:
        print("\nERROR: Failed to build Docker image.")
        sys.exit(1)
    
    # Test the environment
    print("\n3. Testing compilation environment...")
    test_success, test_message = test_compilation_environment(kernel_version)
    print(f"   {test_message}")
    
    if not test_success:
        print("\nWARNING: Test compilation failed.")
        print("The environment may still work, but there might be issues.")
    
    print("\n" + "=" * 60)
    print("Setup complete!")
    print(f"Docker image: linux-driver-eval:kernel-{kernel_version}")
    print("You can now use the compilation analyzer.")
    print(f"\nTo use this kernel version, set 'kernel_version': '{kernel_version}' in your config.")


if __name__ == "__main__":
    main()