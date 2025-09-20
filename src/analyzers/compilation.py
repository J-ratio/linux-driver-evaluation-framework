"""
Compilation testing engine for the Linux Driver Evaluation Framework.

This module provides compilation testing capabilities using containerized environments
with Linux kernel headers and build tools. It parses compilation results and provides
detailed error and warning analysis.
"""

import os
import re
import subprocess
import tempfile
import shutil
import json
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from src.core.interfaces import BaseAnalyzer, AnalysisResult, AnalysisStatus, Finding, Severity


class CompilationStatus(Enum):
    """Compilation result status."""
    SUCCESS = "success"
    WARNINGS = "warnings"
    ERRORS = "errors"
    TIMEOUT = "timeout"
    ENVIRONMENT_ERROR = "environment_error"


@dataclass
class CompilationMessage:
    """Represents a single compilation message (error or warning)."""
    file: str
    line: int
    column: int
    message_type: str  # 'error', 'warning', 'note'
    message: str
    severity: Severity
    
    def to_finding(self) -> Finding:
        """Convert to a Finding object."""
        return Finding(
            type=f"compilation_{self.message_type}",
            severity=self.severity,
            file=self.file,
            line=self.line,
            column=self.column,
            message=self.message,
            recommendation=self._get_recommendation()
        )
    
    def _get_recommendation(self) -> str:
        """Generate recommendation based on the compilation message."""
        message_lower = self.message.lower()
        
        # Standard compilation recommendations
        if "undeclared" in message_lower:
            return "Check if the required header files are included or if the identifier is spelled correctly"
        elif "implicit declaration" in message_lower:
            return "Include the appropriate header file for this function"
        elif "unused variable" in message_lower:
            return "Remove the unused variable or mark it with __attribute__((unused))"
        elif "unused parameter" in message_lower:
            return "Remove the unused parameter or mark it with __attribute__((unused))"
        elif "format" in message_lower:
            return "Check format string and arguments match"
        elif "assignment" in message_lower and "condition" in message_lower:
            return "Use == for comparison or wrap assignment in extra parentheses if intentional"
        elif "comparison" in message_lower and "always" in message_lower:
            return "Review the comparison logic - it may always evaluate to the same result"
        else:
            return "Review the compilation message and fix the indicated issue"


class KernelEnvironment:
    """Manages containerized kernel compilation environment."""
    
    def __init__(self, kernel_version: str = "5.15"):
        """
        Initialize kernel environment.
        
        Args:
            kernel_version: Target kernel version for compilation
        """
        self.kernel_version = kernel_version
        self.container_name = f"kernel-build-{kernel_version}"
        self.image_name = f"linux-driver-eval:kernel-{kernel_version}"
        self.is_setup = False
    
    def setup_environment(self) -> bool:
        """
        Set up the containerized kernel build environment.
        
        Returns:
            True if setup successful, False otherwise
        """
        try:
            # Check if Docker is available - REQUIRED, no fallback
            result = subprocess.run(['docker', '--version'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                raise RuntimeError("Docker is not available. Docker is required for compilation analysis.")
            
            # Check if image already exists
            result = subprocess.run(['docker', 'images', '-q', self.image_name],
                                  capture_output=True, text=True, timeout=30)
            
            if not result.stdout.strip():
                # Build the image - MUST succeed
                if not self._build_docker_image():
                    raise RuntimeError("Failed to build Docker image. Compilation analysis cannot proceed.")
            
            self.is_setup = True
            return True
            
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, RuntimeError) as e:
            raise RuntimeError(f"Failed to setup kernel environment: {e}. Compilation analysis is mandatory and cannot proceed.")
    

    
    def _build_docker_image(self) -> bool:
        """Build Docker image with kernel headers and build tools."""
        dockerfile_path = "docker/kernel-build/Dockerfile"
        
        if not os.path.exists(dockerfile_path):
            raise RuntimeError(f"Dockerfile not found at {dockerfile_path}")
        
        try:
            print("Building Docker image for compilation analysis...")
            # Build the image using the main Dockerfile - MUST succeed
            result = subprocess.run([
                'docker', 'build', '-t', self.image_name, 
                '-f', dockerfile_path, 'docker/kernel-build'
            ], capture_output=True, text=True, timeout=1800)  # 30 minute timeout
            
            if result.returncode == 0:
                print("Docker build successful")
                return True
            else:
                raise RuntimeError(f"Docker build failed: {result.stderr}")
                
        except subprocess.TimeoutExpired:
            raise RuntimeError("Docker build timed out after 30 minutes")
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Docker build process failed: {e}")
    

    
    def compile_driver(self, source_files: List[str], temp_dir: str) -> Tuple[CompilationStatus, str, str]:
        """
        Compile driver source files in the containerized environment.
        
        Args:
            source_files: List of source file paths
            temp_dir: Temporary directory containing the source files
            
        Returns:
            Tuple of (status, stdout, stderr)
        """
        if not self.is_setup:
            if not self.setup_environment():
                raise RuntimeError("Failed to setup compilation environment. Compilation analysis is mandatory.")
        
        # Docker compilation only - no fallbacks
        return self._compile_with_docker(source_files, temp_dir)
    
    def _compile_with_docker(self, source_files: List[str], temp_dir: str) -> Tuple[CompilationStatus, str, str]:
        """Compile using Docker container - simplified version."""
        # Create Makefile for the driver
        makefile_path = os.path.join(temp_dir, 'Makefile')
        self._create_simple_makefile(source_files, makefile_path)
        
        # Check if Docker image exists - MUST exist
        result = subprocess.run(['docker', 'images', '-q', self.image_name],
                              capture_output=True, text=True, timeout=30)
        if not result.stdout.strip():
            raise RuntimeError(f"Docker image {self.image_name} not available. Run setup first.")
        
        try:
            # Run compilation in container
            docker_cmd = [
                'docker', 'run', '--rm',
                '-v', f'{temp_dir}:/workspace',
                '-w', '/workspace',
                self.image_name,
                'make'
            ]
            
            result = subprocess.run(
                docker_cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            # Determine status based on compilation result
            if result.returncode == 0:
                # Compilation succeeded
                if "warning" in result.stderr.lower() or "warning" in result.stdout.lower():
                    status = CompilationStatus.WARNINGS
                else:
                    status = CompilationStatus.SUCCESS
            else:
                # Compilation failed
                status = CompilationStatus.ERRORS
            
            return status, result.stdout, result.stderr
            
        except subprocess.TimeoutExpired:
            raise RuntimeError("Docker compilation timed out after 5 minutes")
        except Exception as e:
            raise RuntimeError(f"Docker compilation failed: {e}")
    

    
    def _create_simple_makefile(self, source_files: List[str], makefile_path: str) -> None:
        """Create a simple Makefile for driver compilation."""
        # Extract base names without extensions
        obj_files = []
        for source_file in source_files:
            base_name = os.path.splitext(os.path.basename(source_file))[0]
            obj_files.append(f"{base_name}.o")
        
        # Create simple Makefile content
        makefile_content = f"""# Simple kernel module Makefile
obj-m := {' '.join(obj_files)}

# Use kernel build directory in Docker
KDIR := /lib/modules/generic/build
PWD := $(shell pwd)

# Compilation flags
ccflags-y := -Wall -Wextra

default:
\t$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
\t$(MAKE) -C $(KDIR) M=$(PWD) clean

.PHONY: default clean
"""
        
        with open(makefile_path, 'w') as f:
            f.write(makefile_content)
    



class CompilationMessageParser:
    """Parses compilation output to extract structured error and warning information."""
    
    # GCC message patterns
    GCC_PATTERN = re.compile(
        r'(?P<file>[^:]+):(?P<line>\d+):(?P<column>\d+):\s*'
        r'(?P<type>error|warning|note):\s*(?P<message>.*)'
    )
    

    
    def __init__(self):
        """Initialize the parser."""
        self.messages = []
    
    def parse_compilation_output(self, stdout: str, stderr: str) -> List[CompilationMessage]:
        """
        Parse compilation output to extract messages.
        
        Args:
            stdout: Standard output from compilation
            stderr: Standard error from compilation
            
        Returns:
            List of CompilationMessage objects
        """
        self.messages = []
        
        # Parse both stdout and stderr
        combined_output = stdout + "\n" + stderr
        
        # Parse both stdout and stderr line by line
        lines = combined_output.split('\n')
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            # Try GCC pattern for compilation messages
            gcc_match = self.GCC_PATTERN.match(line)
            if gcc_match:
                message = self._create_message_from_match(gcc_match)
                if message:
                    self.messages.append(message)
        
        return self.messages
    

    
    def _create_message_from_match(self, match) -> Optional[CompilationMessage]:
        """Create CompilationMessage from regex match."""
        try:
            file_path = match.group('file')
            line = int(match.group('line'))
            column = int(match.group('column'))
            message_type = match.group('type')
            message = match.group('message').strip()
            
            # Map message type to severity
            severity_map = {
                'error': Severity.HIGH,
                'warning': Severity.MEDIUM,
                'note': Severity.INFO
            }
            
            severity = severity_map.get(message_type, Severity.INFO)
            
            return CompilationMessage(
                file=os.path.basename(file_path),
                line=line,
                column=column,
                message_type=message_type,
                message=message,
                severity=severity
            )
            
        except (ValueError, AttributeError):
            return None
    

    
    def get_statistics(self) -> Dict[str, int]:
        """Get compilation statistics."""
        stats = {
            'total_messages': len(self.messages),
            'errors': 0,
            'warnings': 0,
            'notes': 0
        }
        
        for message in self.messages:
            if message.message_type == 'error':
                stats['errors'] += 1
            elif message.message_type == 'warning':
                stats['warnings'] += 1
            elif message.message_type == 'note':
                stats['notes'] += 1
        
        return stats


class CompilationAnalyzer(BaseAnalyzer):
    """Main compilation analyzer that implements the BaseAnalyzer interface."""
    
    def __init__(self, kernel_version: str = "5.15"):
        """
        Initialize the compilation analyzer.
        
        Args:
            kernel_version: Target kernel version for compilation
        """
        self.kernel_version = kernel_version
        self.environment = KernelEnvironment(kernel_version)
        self.parser = CompilationMessageParser()
    
    @property
    def name(self) -> str:
        """Return the name of this analyzer."""
        return "compilation"
    
    @property
    def version(self) -> str:
        """Return the version of this analyzer."""
        return "1.0.0"
    
    def analyze(self, source_files: List[str], config: Dict[str, Any]) -> AnalysisResult:
        """
        Analyze source files by attempting compilation.
        
        Args:
            source_files: List of source file paths to compile
            config: Configuration parameters
            
        Returns:
            AnalysisResult with compilation findings and metrics
        """
        try:
            # Create temporary directory for compilation
            with tempfile.TemporaryDirectory() as temp_dir:
                # Copy source files to temp directory
                temp_source_files = []
                for source_file in source_files:
                    if os.path.exists(source_file):
                        dest_path = os.path.join(temp_dir, os.path.basename(source_file))
                        shutil.copy2(source_file, dest_path)
                        temp_source_files.append(dest_path)
                    else:
                        # Handle case where source_file is content, not path
                        # This would need to be handled based on the calling context
                        pass
                
                if not temp_source_files:
                    return AnalysisResult(
                        analyzer=self.name,
                        status=AnalysisStatus.FAILURE,
                        findings=[Finding(
                            type="compilation_error",
                            severity=Severity.CRITICAL,
                            file="",
                            line=0,
                            column=0,
                            message="No valid source files provided for compilation",
                            recommendation="Ensure source files exist and are accessible"
                        )],
                        metrics={"compilation_attempted": False},
                        score=0.0
                    )
                
                # Attempt compilation
                status, stdout, stderr = self.environment.compile_driver(temp_source_files, temp_dir)
                
                # Parse compilation messages
                messages = self.parser.parse_compilation_output(stdout, stderr)
                
                # Convert messages to findings
                findings = [msg.to_finding() for msg in messages]
                
                # Calculate metrics
                stats = self.parser.get_statistics()
                metrics = {
                    "compilation_status": status.value,
                    "compilation_attempted": True,
                    "kernel_version": self.kernel_version,
                    **stats
                }
                
                # Determine overall analysis status
                if status == CompilationStatus.SUCCESS:
                    analysis_status = AnalysisStatus.SUCCESS
                elif status == CompilationStatus.WARNINGS:
                    analysis_status = AnalysisStatus.WARNING
                else:
                    analysis_status = AnalysisStatus.FAILURE
                
                # Calculate score based on compilation success and findings
                score = self._calculate_compilation_score(status, findings)
                
                return AnalysisResult(
                    analyzer=self.name,
                    status=analysis_status,
                    findings=findings,
                    metrics=metrics,
                    score=score
                )
                
        except Exception as e:
            return AnalysisResult(
                analyzer=self.name,
                status=AnalysisStatus.FAILURE,
                findings=[Finding(
                    type="compilation_error",
                    severity=Severity.CRITICAL,
                    file="",
                    line=0,
                    column=0,
                    message=f"Compilation analysis failed: {str(e)}",
                    recommendation="Check system configuration and Docker availability"
                )],
                metrics={"compilation_attempted": False, "error": str(e)},
                score=0.0
            )
    
    def validate_config(self, config: Dict[str, Any]) -> bool:
        """
        Validate configuration for the compilation analyzer.
        
        Args:
            config: Configuration to validate
            
        Returns:
            True if configuration is valid
        """
        # Docker is REQUIRED - no exceptions
        try:
            result = subprocess.run(['docker', '--version'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                raise RuntimeError("Docker is required for compilation analysis but is not available")
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
            raise RuntimeError("Docker is required for compilation analysis but is not installed or accessible")
        
        # Check if Docker daemon is running
        try:
            result = subprocess.run(['docker', 'info'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                raise RuntimeError("Docker daemon is not running. Please start Docker service.")
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
            raise RuntimeError("Docker daemon is not accessible. Please ensure Docker is running and you have permissions.")
        
        # Validate kernel version if specified
        kernel_version = config.get('kernel_version', self.kernel_version)
        if not re.match(r'^\d+\.\d+$', kernel_version):
            raise ValueError(f"Invalid kernel version format: {kernel_version}. Expected format: X.Y")
        
        return True
    
    def _calculate_compilation_score(self, status: CompilationStatus, findings: List[Finding]) -> float:
        """
        Calculate compilation score based on status and findings.
        
        Args:
            status: Compilation status
            findings: List of findings from compilation
            
        Returns:
            Score from 0.0 to 100.0
        """
        if status == CompilationStatus.SUCCESS:
            base_score = 100.0
        elif status == CompilationStatus.WARNINGS:
            base_score = 80.0
        elif status == CompilationStatus.ERRORS:
            base_score = 20.0
        else:
            base_score = 0.0
        
        # Deduct points for findings (more reasonable for kernel code)
        deductions = 0.0
        for finding in findings:
            if finding.severity == Severity.CRITICAL:
                deductions += 10.0
            elif finding.severity == Severity.HIGH:
                deductions += 5.0
            elif finding.severity == Severity.MEDIUM:
                deductions += 2.0
            elif finding.severity == Severity.LOW:
                deductions += 0.5  # Kernel code has many low-severity warnings
        
        # Cap deductions to not exceed 50% of base score for warnings-only compilation
        if status == CompilationStatus.WARNINGS:
            max_deductions = base_score * 0.5
            deductions = min(deductions, max_deductions)
        
        final_score = max(0.0, base_score - deductions)
        return min(100.0, final_score)
    
    def setup(self) -> bool:
        """
        Set up the compilation environment.
        
        Returns:
            True if setup successful
        """
        return self.environment.setup_environment()