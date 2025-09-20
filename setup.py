#!/usr/bin/env python3
"""
Setup script for Linux Driver Evaluation Framework.
This script handles initial setup including Docker image building.
"""

import sys
import subprocess
import os
import json
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from src.config.manager import DefaultConfigurationManager

def check_requirements():
    """Check system requirements."""
    print("🔍 Checking system requirements...")
    
    requirements = {
        "python": {"cmd": [sys.executable, "--version"], "min_version": "3.8"},
        "docker": {"cmd": ["docker", "--version"], "required": True},
        "docker_daemon": {"cmd": ["docker", "info"], "required": True}
    }
    
    failed = []
    
    for name, req in requirements.items():
        try:
            result = subprocess.run(req["cmd"], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                version_info = result.stdout.strip()
                print(f"✅ {name}: {version_info}")
            else:
                print(f"❌ {name}: Command failed")
                if req.get("required"):
                    failed.append(name)
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
            print(f"❌ {name}: Not available")
            if req.get("required"):
                failed.append(name)
    
    if failed:
        print(f"\n💥 Missing required dependencies: {', '.join(failed)}")
        print("Please install the missing dependencies and try again.")
        return False
    
    print("✅ All requirements satisfied!")
    return True

def install_python_dependencies():
    """Install Python dependencies."""
    print("\n📦 Installing Python dependencies...")
    
    requirements_file = Path("requirements.txt")
    if not requirements_file.exists():
        print("⚠️  requirements.txt not found, skipping Python dependencies")
        return True
    
    try:
        result = subprocess.run([
            sys.executable, "-m", "pip", "install", "-r", "requirements.txt"
        ], capture_output=True, text=True, timeout=300)
        
        if result.returncode == 0:
            print("✅ Python dependencies installed successfully")
            return True
        else:
            print(f"❌ Failed to install Python dependencies: {result.stderr}")
            return False
    except Exception as e:
        print(f"❌ Error installing Python dependencies: {e}")
        return False

def build_docker_images():
    """Build Docker images for all supported architectures."""
    print("\n🐳 Building Docker images for supported architectures...")
    print("💡 This may take 10-20 minutes depending on your internet connection")
    
    try:
        # Import and run the build script
        from build_docker_images import main as build_main
        result = build_main()
        
        if result == 0:
            print("✅ All Docker images built successfully!")
            return True
        else:
            print("⚠️  Some Docker images failed to build, but setup can continue")
            print("💡 You can retry building images later with: python build_docker_images.py")
            return True  # Don't fail setup for image build issues
    except Exception as e:
        print(f"❌ Error building Docker images: {e}")
        print("💡 You can build images manually later with: python build_docker_images.py")
        return True  # Don't fail setup for image build issues

def setup_configuration():
    """Set up initial configuration."""
    print("\n⚙️  Setting up configuration...")
    
    try:
        config_manager = DefaultConfigurationManager()
        config = config_manager.load_config()
        
        # Ensure config directory exists
        config_dir = Path("config")
        config_dir.mkdir(exist_ok=True)
        
        # Save default configuration
        if config_manager.save_config(config):
            print("✅ Configuration initialized successfully")
            
            # Display current settings
            compilation_config = config.get("compilation", {})
            print(f"   🏗️  Default architecture: {compilation_config.get('target_architecture', 'x86_64')}")
            print(f"   ⚙️  Default kernel version: {compilation_config.get('kernel_version', '5.15')}")
            print(f"   🏛️  Available architectures: {', '.join(compilation_config.get('available_architectures', []))}")
            
            return True
        else:
            print("❌ Failed to save configuration")
            return False
    except Exception as e:
        print(f"❌ Error setting up configuration: {e}")
        return False

def create_example_files():
    """Create example driver files if they don't exist."""
    print("\n📝 Setting up example files...")
    
    examples_dir = Path("examples")
    examples_dir.mkdir(exist_ok=True)
    
    # Simple hello driver example
    hello_driver = examples_dir / "simple_hello_driver.c"
    if not hello_driver.exists():
        hello_content = '''/*
 * Simple Hello World Linux Kernel Module
 * 
 * This is a minimal kernel module that demonstrates basic module
 * loading and unloading functionality.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

static int __init hello_init(void)
{
    printk(KERN_INFO "Hello from Linux Driver Evaluation Framework!\\n");
    printk(KERN_INFO "Module loaded successfully\\n");
    return 0;
}

static void __exit hello_exit(void)
{
    printk(KERN_INFO "Goodbye from Linux Driver Evaluation Framework!\\n");
    printk(KERN_INFO "Module unloaded successfully\\n");
}

module_init(hello_init);
module_exit(hello_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Linux Driver Evaluation Framework");
MODULE_DESCRIPTION("Simple hello world kernel module for testing");
MODULE_VERSION("1.0");
'''
        hello_driver.write_text(hello_content)
        print(f"✅ Created example: {hello_driver}")
    
    # Multi-architecture test driver
    multiarch_driver = examples_dir / "multiarch_test_driver.c"
    if not multiarch_driver.exists():
        multiarch_content = '''/*
 * Multi-Architecture Test Driver
 * 
 * This driver demonstrates cross-platform compatibility
 * and can be compiled for x86_64, ARM64, and RISC-V.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/platform_device.h>

static int __init multiarch_init(void)
{
    printk(KERN_INFO "Multi-Architecture Test Driver Loading...\\n");
    
    #ifdef CONFIG_X86_64
    printk(KERN_INFO "Running on x86_64 architecture\\n");
    #elif defined(CONFIG_ARM64)
    printk(KERN_INFO "Running on ARM64 architecture\\n");
    #elif defined(CONFIG_RISCV)
    printk(KERN_INFO "Running on RISC-V architecture\\n");
    #else
    printk(KERN_INFO "Running on unknown architecture\\n");
    #endif
    
    printk(KERN_INFO "Driver loaded successfully\\n");
    return 0;
}

static void __exit multiarch_exit(void)
{
    printk(KERN_INFO "Multi-Architecture Test Driver Unloading...\\n");
    printk(KERN_INFO "Driver unloaded successfully\\n");
}

module_init(multiarch_init);
module_exit(multiarch_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Linux Driver Evaluation Framework");
MODULE_DESCRIPTION("Multi-architecture test driver");
MODULE_VERSION("1.0");
'''
        multiarch_driver.write_text(multiarch_content)
        print(f"✅ Created example: {multiarch_driver}")
    
    print("✅ Example files ready")
    return True

def run_quick_test():
    """Run a quick test to verify the setup."""
    print("\n🧪 Running quick setup verification...")
    
    try:
        # Test configuration loading
        config_manager = DefaultConfigurationManager()
        config = config_manager.load_config()
        
        available_architectures = config.get("compilation", {}).get("available_architectures", [])
        print(f"✅ Configuration loaded: {len(available_architectures)} architectures available")
        
        # Test Docker images
        print("🐳 Checking Docker images...")
        for arch in available_architectures:
            image_name = f"linux-driver-eval:kernel-5.15-{arch}"
            result = subprocess.run(
                ["docker", "images", "-q", image_name],
                capture_output=True, text=True, timeout=30
            )
            
            if result.stdout.strip():
                print(f"✅ Docker image available: {image_name}")
            else:
                print(f"⚠️  Docker image missing: {image_name}")
        
        print("✅ Setup verification completed")
        return True
        
    except Exception as e:
        print(f"⚠️  Setup verification failed: {e}")
        return False

def main():
    """Main setup function."""
    print("🚀 Linux Driver Evaluation Framework Setup")
    print("=" * 60)
    
    steps = [
        ("System Requirements", check_requirements),
        ("Python Dependencies", install_python_dependencies),
        ("Configuration", setup_configuration),
        ("Example Files", create_example_files),
        ("Docker Images", build_docker_images),
        ("Verification", run_quick_test)
    ]
    
    failed_steps = []
    
    for step_name, step_func in steps:
        print(f"\n📋 Step: {step_name}")
        try:
            if not step_func():
                failed_steps.append(step_name)
                if step_name in ["System Requirements", "Python Dependencies"]:
                    print(f"💥 Critical step '{step_name}' failed. Setup cannot continue.")
                    return 1
        except KeyboardInterrupt:
            print(f"\n⚠️  Setup interrupted during '{step_name}'")
            return 1
        except Exception as e:
            print(f"❌ Unexpected error in '{step_name}': {e}")
            failed_steps.append(step_name)
    
    # Summary
    print(f"\n{'='*60}")
    print("📊 SETUP SUMMARY")
    print(f"{'='*60}")
    
    if not failed_steps:
        print("🎉 Setup completed successfully!")
        print("✅ All components are ready")
        print("\n🚀 Next steps:")
        print("   1. Start the web server: python run_web_server.py")
        print("   2. Open http://localhost:8000 in your browser")
        print("   3. Upload a driver file or try a sample driver")
        print("   4. Select your target architecture (x86_64 or riscv64)")
        return 0
    else:
        print("⚠️  Setup completed with some issues:")
        for step in failed_steps:
            print(f"   ❌ {step}")
        
        print("\n💡 You can:")
        print("   - Retry setup: python setup.py")
        print("   - Build images manually: python build_docker_images.py")
        print("   - Check documentation for troubleshooting")
        
        return 1

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n⚠️  Setup interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n💥 Setup failed with unexpected error: {e}")
        sys.exit(1)