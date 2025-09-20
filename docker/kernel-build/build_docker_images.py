#!/usr/bin/env python3
"""
Script to pre-build Docker images for all supported architectures.
This separates the build process from testing for faster iteration.
"""

import sys
import subprocess
import json
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from src.config.manager import DefaultConfigurationManager

def build_docker_image(architecture: str, kernel_version: str = "5.15"):
    """Build Docker image for a specific architecture."""
    print(f"\n{'='*80}")
    print(f"🐳 Building Docker image for {architecture.upper()}")
    print(f"{'='*80}")
    
    try:
        # Load configuration
        config_manager = DefaultConfigurationManager()
        kernel_config = config_manager.get_kernel_version_config(kernel_version)
        arch_config = config_manager.get_architecture_config(architecture)
        
        # Image details
        image_name = f"linux-driver-eval:kernel-{kernel_version}-{architecture}"
        dockerfile_path = "docker/kernel-build/Dockerfile.template"
        
        print(f"📋 Build Configuration:")
        print(f"   🏷️  Image name: {image_name}")
        print(f"   🏗️  Architecture: {architecture}")
        print(f"   ⚙️  Kernel version: {kernel_version}")
        print(f"   🐧 Base image: {kernel_config['docker_image']}")
        print(f"   📦 Headers package: {arch_config['headers_package']}")
        print(f"   🔧 Cross-compile prefix: {arch_config.get('cross_compile_prefix', 'None (native)')}")
        
        # Check if image already exists
        print(f"\n📋 Checking if image already exists...")
        result = subprocess.run(['docker', 'images', '-q', image_name],
                              capture_output=True, text=True, timeout=30)
        
        if result.stdout.strip():
            print(f"✅ Image {image_name} already exists")
            print(f"🔄 Rebuilding to ensure it's up to date...")
        else:
            print(f"🆕 Image {image_name} does not exist, building new...")
        
        # Build arguments
        build_args = [
            '--build-arg', f'KERNEL_VERSION={kernel_version}',
            '--build-arg', f'TARGET_ARCH={architecture}',
            '--build-arg', f'BASE_IMAGE={kernel_config["docker_image"]}',
            '--build-arg', f'HEADERS_PACKAGE={arch_config["headers_package"]}'
        ]
        
        # Build command
        build_cmd = [
            'docker', 'build', '-t', image_name
        ] + build_args + [
            '-f', dockerfile_path, 'docker/kernel-build'
        ]
        
        print(f"\n⏳ Starting Docker build...")
        print(f"💡 This may take 5-15 minutes depending on your internet connection")
        print(f"🔧 Build command: {' '.join(build_cmd)}")
        
        # Run build with real-time output
        process = subprocess.Popen(
            build_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )
        
        # Track build progress
        step_count = 0
        while True:
            output = process.stdout.readline()
            if output == '' and process.poll() is not None:
                break
            if output:
                line = output.strip()
                
                # Count build steps
                if line.startswith('#') and '[' in line and ']' in line:
                    if 'internal' not in line.lower():
                        step_count += 1
                        print(f"📦 Step {step_count}: {line}")
                    else:
                        print(f"🔧 {line}")
                
                # Show important messages
                elif any(keyword in line.lower() for keyword in [
                    'successfully built', 'successfully tagged', 'error', 'failed'
                ]):
                    print(f"📢 {line}")
                
                # Show package installation progress
                elif 'get:' in line.lower() or 'setting up' in line.lower():
                    if step_count > 0:  # Only show during package installation steps
                        print(f"   📥 {line}")
        
        return_code = process.poll()
        
        if return_code == 0:
            print(f"\n✅ Successfully built {image_name}")
            
            # Verify image was created
            result = subprocess.run(['docker', 'images', image_name, '--format', 'table {{.Repository}}:{{.Tag}}\t{{.Size}}\t{{.CreatedAt}}'],
                                  capture_output=True, text=True)
            if result.stdout:
                lines = result.stdout.strip().split('\n')
                if len(lines) > 1:  # Skip header
                    print(f"📊 Image details: {lines[1]}")
            
            return True
        else:
            print(f"\n❌ Failed to build {image_name} (exit code: {return_code})")
            return False
            
    except subprocess.TimeoutExpired:
        print(f"❌ Build timed out for {architecture}")
        return False
    except Exception as e:
        print(f"❌ Build failed for {architecture}: {e}")
        return False

def check_existing_images():
    """Check which Docker images already exist."""
    print("� PChecking existing Docker images...")
    
    try:
        config_manager = DefaultConfigurationManager()
        config = config_manager.load_config()
        available_architectures = config.get('compilation', {}).get('available_architectures', [])
        kernel_version = config.get('compilation', {}).get('kernel_version', '5.15')
        
        existing_images = {}
        for arch in available_architectures:
            image_name = f"linux-driver-eval:kernel-{kernel_version}-{arch}"
            result = subprocess.run(['docker', 'images', '-q', image_name],
                                  capture_output=True, text=True, timeout=30)
            existing_images[arch] = bool(result.stdout.strip())
            
            status = "✅ EXISTS" if existing_images[arch] else "❌ MISSING"
            print(f"   {arch:>10}: {status}")
        
        return existing_images
    except Exception as e:
        print(f"❌ Error checking existing images: {e}")
        return {}

def main():
    """Main function to build all architecture images."""
    print("🚀 Pre-building Docker images for all architectures")
    print("=" * 80)
    
    # Check Docker availability
    print("📋 Checking Docker availability...")
    try:
        result = subprocess.run(['docker', '--version'], capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            print(f"✅ Docker is available: {result.stdout.strip()}")
        else:
            print("❌ Docker is not available")
            return 1
    except Exception as e:
        print(f"❌ Docker check failed: {e}")
        return 1
    
    # Load configuration
    print("\n📋 Loading configuration...")
    try:
        config_manager = DefaultConfigurationManager()
        config = config_manager.load_config()
        available_architectures = config.get('compilation', {}).get('available_architectures', [])
        kernel_version = config.get('compilation', {}).get('kernel_version', '5.15')
        
        print(f"✅ Configuration loaded")
        print(f"🏗️  Architectures to build: {', '.join(available_architectures)}")
        print(f"⚙️  Kernel version: {kernel_version}")
    except Exception as e:
        print(f"❌ Failed to load configuration: {e}")
        return 1
    
    # Check existing images
    existing_images = check_existing_images()
    
    # Determine which images need building
    to_build = [arch for arch in available_architectures if not existing_images.get(arch, False)]
    
    if not to_build:
        print("\n🎉 All Docker images already exist!")
        print("💡 Use --force to rebuild existing images")
        return 0
    
    print(f"\n🏗️  Need to build {len(to_build)} images: {', '.join(to_build)}")
    
    # Build images for each architecture
    results = {}
    total_archs = len(to_build)
    
    for i, arch in enumerate(to_build, 1):
        print(f"\n🏗️  Building image {i}/{total_archs} for {arch}")
        try:
            results[arch] = build_docker_image(arch, kernel_version)
        except KeyboardInterrupt:
            print(f"\n⚠️  Build interrupted for {arch}")
            break
        except Exception as e:
            print(f"❌ Unexpected error building {arch}: {e}")
            results[arch] = False
    
    # Summary
    print(f"\n{'='*80}")
    print(f"📊 BUILD SUMMARY")
    print(f"{'='*80}")
    
    successful_builds = 0
    for arch in available_architectures:
        if arch in results:
            success = results[arch]
            status = "✅ SUCCESS" if success else "❌ FAILED"
        elif existing_images.get(arch, False):
            success = True
            status = "✅ EXISTS"
        else:
            success = False
            status = "❌ MISSING"
        
        print(f"{arch:>10}: {status}")
        if success:
            successful_builds += 1
    
    total_archs = len(available_architectures)
    print(f"\n📈 Overall: {successful_builds}/{total_archs} images available")
    
    if successful_builds == total_archs:
        print("🎉 All Docker images are ready!")
        print("✅ Multi-architecture evaluation is fully functional")
        return 0
    elif successful_builds > 0:
        print("⚠️  Some images are missing but others are available")
        print("💡 You can use the available architectures")
        return 1
    else:
        print("❌ No Docker images are available")
        print("💡 Check Docker setup and network connectivity")
        return 1

if __name__ == "__main__":
    sys.exit(main())