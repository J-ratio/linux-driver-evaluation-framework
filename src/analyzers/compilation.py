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
        
        # Sparse-specific recommendations
        if self.message_type.startswith('sparse_'):
            return self._get_sparse_recommendation(message_lower)
        
        # Standard compilation recommendations
        if "undeclared" in message_lower:
            return "Check if the required header files are included or if the identifier is spelled correctly"
        elif "implicit declaration" in message_lower:
            return "Include the appropriate header file for this function"
        elif "unused variable" in message_lower:
            return "Remove the unused variable or mark it with __attribute__((unused))"
        elif "format" in message_lower:
            return "Check format string and arguments match"
        elif "assignment" in message_lower and "condition" in message_lower:
            return "Use == for comparison or wrap assignment in extra parentheses if intentional"
        else:
            return "Review the compilation message and fix the indicated issue"
    
    def _get_sparse_recommendation(self, message_lower: str) -> str:
        """Generate sparse-specific recommendations."""
        if "address space" in message_lower:
            return "Use proper address space annotations (__user, __kernel, __iomem) and appropriate access functions"
        elif "endian" in message_lower:
            return "Use proper endianness conversion functions (cpu_to_le32, be32_to_cpu, etc.) for cross-platform compatibility"
        elif "context" in message_lower and ("lock" in message_lower or "unlock" in message_lower):
            return "Ensure proper lock/unlock pairing and use appropriate locking primitives for kernel context"
        elif "context imbalance" in message_lower:
            return "Check that all code paths properly acquire and release locks, and verify interrupt context handling"
        elif "null" in message_lower and "dereference" in message_lower:
            return "Add null pointer checks before dereferencing pointers, especially for user-provided data"
        elif "uninitialized" in message_lower:
            return "Initialize variables before use, especially in error paths and conditional branches"
        elif "cast truncat" in message_lower:
            return "Verify that cast operations don't lose significant data; use explicit size checks if needed"
        elif "bitwise" in message_lower:
            return "Use proper bitwise operations and ensure consistent types for bit manipulation"
        elif "redeclar" in message_lower or "redefinition" in message_lower:
            return "Remove duplicate declarations or use proper header guards to prevent multiple definitions"
        elif "preprocessor" in message_lower or "macro" in message_lower:
            return "Check macro definitions for conflicts and ensure proper conditional compilation"
        else:
            return "Review sparse semantic analysis output and address kernel-specific coding issues"


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
            # Check if Docker is available
            result = subprocess.run(['docker', '--version'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                raise RuntimeError("Docker is not available")
            
            # Check if image already exists
            result = subprocess.run(['docker', 'images', '-q', self.image_name],
                                  capture_output=True, text=True, timeout=30)
            
            if not result.stdout.strip():
                # Build the image
                if not self._build_docker_image():
                    return False
            
            self.is_setup = True
            return True
            
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, RuntimeError) as e:
            print(f"Failed to setup kernel environment: {e}")
            return False
    
    def _build_docker_image(self) -> bool:
        """Build Docker image with kernel headers and build tools."""
        dockerfile_path = "docker/kernel-build/Dockerfile"
        
        if not os.path.exists(dockerfile_path):
            print(f"Dockerfile not found at {dockerfile_path}")
            return False
        
        try:
            # Build the image using the existing Dockerfile
            result = subprocess.run([
                'docker', 'build', '-t', self.image_name, 
                '-f', dockerfile_path, 'docker/kernel-build'
            ], capture_output=True, text=True, timeout=600)  # 10 minute timeout
            
            if result.returncode != 0:
                print(f"Docker build failed: {result.stderr}")
                return False
            
            return True
            
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError) as e:
            print(f"Failed to build Docker image: {e}")
            return False
    

    
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
                return CompilationStatus.ENVIRONMENT_ERROR, "", "Failed to setup compilation environment"
        
        try:
            # Create Makefile for the driver
            makefile_path = os.path.join(temp_dir, 'Makefile')
            self._create_makefile(source_files, makefile_path)
            
            # Run compilation in container
            docker_cmd = [
                'docker', 'run', '--rm',
                '-v', f'{temp_dir}:/workspace',
                '-w', '/workspace',
                self.image_name,
                'make', '-j$(nproc)'
            ]
            
            result = subprocess.run(
                docker_cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            # Also run sparse analysis if available
            sparse_stdout, sparse_stderr = self._run_sparse_analysis(temp_dir, source_files)
            
            # Combine outputs
            combined_stdout = result.stdout + "\n" + sparse_stdout
            combined_stderr = result.stderr + "\n" + sparse_stderr
            
            # Determine status
            if result.returncode == 0:
                if "warning" in combined_stderr.lower():
                    status = CompilationStatus.WARNINGS
                else:
                    status = CompilationStatus.SUCCESS
            else:
                status = CompilationStatus.ERRORS
            
            return status, combined_stdout, combined_stderr
            
        except subprocess.TimeoutExpired:
            return CompilationStatus.TIMEOUT, "", "Compilation timed out"
        except Exception as e:
            return CompilationStatus.ENVIRONMENT_ERROR, "", f"Compilation failed: {str(e)}"
    
    def _create_makefile(self, source_files: List[str], makefile_path: str) -> None:
        """Create Makefile for driver compilation."""
        template_path = "templates/Makefile.driver"
        
        if not os.path.exists(template_path):
            raise FileNotFoundError(f"Makefile template not found at {template_path}")
        
        # Extract base names without extensions
        obj_files = []
        for source_file in source_files:
            base_name = os.path.splitext(os.path.basename(source_file))[0]
            obj_files.append(f"{base_name}.o")
        
        # Read template and substitute variables
        with open(template_path, 'r') as f:
            template_content = f.read()
        
        # Replace template variables
        makefile_content = template_content.replace('$(OBJECTS)', ' '.join(obj_files))
        
        with open(makefile_path, 'w') as f:
            f.write(makefile_content)
    
    def _run_sparse_analysis(self, temp_dir: str, source_files: List[str]) -> Tuple[str, str]:
        """Run comprehensive sparse semantic analysis on the source files."""
        try:
            # Run multiple sparse analysis passes with different configurations
            all_stdout = ""
            all_stderr = ""
            
            # Standard sparse analysis
            stdout, stderr = self._run_sparse_pass(temp_dir, "sparse")
            all_stdout += stdout + "\n"
            all_stderr += stderr + "\n"
            
            # Enhanced sparse analysis with additional checks
            stdout, stderr = self._run_sparse_pass(temp_dir, "sparse-enhanced")
            all_stdout += stdout + "\n"
            all_stderr += stderr + "\n"
            
            # Context-sensitive analysis for locking
            stdout, stderr = self._run_sparse_pass(temp_dir, "sparse-context")
            all_stdout += stdout + "\n"
            all_stderr += stderr + "\n"
            
            return all_stdout, all_stderr
            
        except Exception as e:
            return "", f"Sparse analysis failed: {str(e)}"
    
    def _run_sparse_pass(self, temp_dir: str, target: str) -> Tuple[str, str]:
        """Run a specific sparse analysis pass."""
        try:
            docker_cmd = [
                'docker', 'run', '--rm',
                '-v', f'{temp_dir}:/workspace',
                '-w', '/workspace',
                self.image_name,
                'make', target
            ]
            
            result = subprocess.run(
                docker_cmd,
                capture_output=True,
                text=True,
                timeout=120  # 2 minute timeout per pass
            )
            
            return result.stdout, result.stderr
            
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
            return "", f"Sparse pass '{target}' failed or timed out"


class CompilationMessageParser:
    """Parses compilation output to extract structured error and warning information."""
    
    # GCC message patterns
    GCC_PATTERN = re.compile(
        r'(?P<file>[^:]+):(?P<line>\d+):(?P<column>\d+):\s*'
        r'(?P<type>error|warning|note):\s*(?P<message>.*)'
    )
    
    # Enhanced sparse message patterns
    SPARSE_PATTERN = re.compile(
        r'(?P<file>[^:]+):(?P<line>\d+):(?P<column>\d+):\s*'
        r'(?P<type>warning|error):\s*(?P<message>.*)'
    )
    
    # Sparse-specific semantic issue patterns for better categorization
    SPARSE_SEMANTIC_PATTERNS = {
        'address_space': re.compile(r'incorrect type.*different address spaces'),
        'endianness': re.compile(r'cast.*different base types|incorrect type.*endianness'),
        'context_imbalance': re.compile(r'context imbalance|context problem'),
        'locking': re.compile(r'context.*lock|unlock.*context'),
        'null_pointer': re.compile(r'dereference.*null|null.*dereference'),
        'uninitialized': re.compile(r'uninitialized|may be used uninitialized'),
        'cast_truncation': re.compile(r'cast truncates bits|truncated'),
        'bitwise_operation': re.compile(r'dubious.*bitwise|bitwise.*different'),
        'symbol_redeclaration': re.compile(r'symbol.*redeclared|redefinition'),
        'preprocessor': re.compile(r'preprocessor|macro.*redefined')
    }
    
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
        
        # Parse both stdout and stderr line by line for better control
        lines = combined_output.split('\n')
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            # Determine if this is a sparse message or GCC message
            # Sparse messages typically come from sparse analysis and have specific patterns
            is_sparse_message = self._is_sparse_message(line, stdout, stderr)
            
            if is_sparse_message:
                # Try sparse pattern
                sparse_match = self.SPARSE_PATTERN.match(line)
                if sparse_match:
                    message = self._create_sparse_message_from_match(sparse_match)
                    if message:
                        self.messages.append(message)
                    continue
            
            # Try GCC pattern for regular compilation messages
            gcc_match = self.GCC_PATTERN.match(line)
            if gcc_match:
                message = self._create_message_from_match(gcc_match)
                if message:
                    self.messages.append(message)
        
        return self.messages
    
    def _is_sparse_message(self, line: str, stdout: str, stderr: str) -> bool:
        """Determine if a message line is from sparse analysis."""
        # Check if the line contains sparse-specific patterns
        line_lower = line.lower()
        
        # Sparse-specific message indicators (more comprehensive)
        sparse_indicators = [
            'different address spaces',
            'cast from restricted',
            'context imbalance',
            'noderef expression', 
            'cast truncates bits',
            'dubious.*bitwise',
            'symbol.*redeclared',
            'incorrect type.*endianness',
            'restricted.*',
            'noderef',
            'context.*lock',
            'lock.*context',
            'cast.*restricted',
            'bitwise.*different',
            'endian',
            '__be32',
            '__le32',
            '__user',
            '__kernel',
            '__iomem'
        ]
        
        # Check for sparse-specific patterns
        for indicator in sparse_indicators:
            if re.search(indicator, line_lower):
                return True
        
        # Additional check: if the message contains kernel-specific annotations
        kernel_annotations = ['__user', '__kernel', '__iomem', '__be32', '__le32', '__be16', '__le16']
        for annotation in kernel_annotations:
            if annotation in line:
                return True
        
        return False
    
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
    
    def _create_sparse_message_from_match(self, match) -> Optional[CompilationMessage]:
        """Create CompilationMessage from sparse regex match."""
        try:
            file_path = match.group('file')
            line = int(match.group('line'))
            column = int(match.group('column'))
            message_type = match.group('type')
            raw_message = match.group('message').strip()
            
            # Categorize sparse message by semantic issue type
            semantic_category = self._categorize_sparse_message(raw_message)
            message = f"[sparse:{semantic_category}] {raw_message}"
            
            # Determine severity based on semantic category and message type
            severity = self._get_sparse_severity(semantic_category, message_type, raw_message)
            
            return CompilationMessage(
                file=os.path.basename(file_path),
                line=line,
                column=column,
                message_type=f"sparse_{message_type}",
                message=message,
                severity=severity
            )
            
        except (ValueError, AttributeError):
            return None
    
    def _categorize_sparse_message(self, message: str) -> str:
        """Categorize sparse message by semantic issue type."""
        message_lower = message.lower()
        
        for category, pattern in self.SPARSE_SEMANTIC_PATTERNS.items():
            if pattern.search(message_lower):
                return category
        
        return "general"
    
    def _get_sparse_severity(self, category: str, message_type: str, message: str) -> Severity:
        """Determine severity based on sparse semantic category."""
        # Critical issues that can cause kernel crashes or security problems
        critical_categories = {'null_pointer', 'context_imbalance', 'locking'}
        
        # High severity issues that indicate serious problems
        high_categories = {'address_space', 'uninitialized', 'cast_truncation'}
        
        # Medium severity issues that should be addressed
        medium_categories = {'endianness', 'bitwise_operation', 'symbol_redeclaration'}
        
        if message_type == 'error':
            return Severity.CRITICAL
        
        if category in critical_categories:
            return Severity.CRITICAL
        elif category in high_categories:
            return Severity.HIGH
        elif category in medium_categories:
            return Severity.MEDIUM
        else:
            return Severity.LOW
    
    def get_statistics(self) -> Dict[str, int]:
        """Get comprehensive compilation and sparse analysis statistics."""
        stats = {
            'total_messages': len(self.messages),
            'errors': 0,
            'warnings': 0,
            'notes': 0,
            'sparse_warnings': 0,
            'sparse_errors': 0,
            'sparse_critical': 0,
            'sparse_high': 0,
            'sparse_medium': 0,
            'sparse_low': 0
        }
        
        # Sparse semantic category counts
        sparse_categories = {
            'address_space': 0,
            'endianness': 0,
            'context_imbalance': 0,
            'locking': 0,
            'null_pointer': 0,
            'uninitialized': 0,
            'cast_truncation': 0,
            'bitwise_operation': 0,
            'symbol_redeclaration': 0,
            'preprocessor': 0,
            'general': 0
        }
        
        for message in self.messages:
            if message.message_type == 'error':
                stats['errors'] += 1
            elif message.message_type == 'warning':
                stats['warnings'] += 1
            elif message.message_type == 'note':
                stats['notes'] += 1
            elif message.message_type.startswith('sparse_'):
                if message.message_type == 'sparse_warning':
                    stats['sparse_warnings'] += 1
                elif message.message_type == 'sparse_error':
                    stats['sparse_errors'] += 1
                
                # Count by severity
                if message.severity == Severity.CRITICAL:
                    stats['sparse_critical'] += 1
                elif message.severity == Severity.HIGH:
                    stats['sparse_high'] += 1
                elif message.severity == Severity.MEDIUM:
                    stats['sparse_medium'] += 1
                elif message.severity == Severity.LOW:
                    stats['sparse_low'] += 1
                
                # Extract category from sparse message
                if '[sparse:' in message.message:
                    category = message.message.split('[sparse:')[1].split(']')[0]
                    if category in sparse_categories:
                        sparse_categories[category] += 1
        
        # Add sparse category counts to stats
        for category, count in sparse_categories.items():
            stats[f'sparse_{category}'] = count
        
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
        return "compilation_analyzer"
    
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
        # Check for required Docker
        try:
            result = subprocess.run(['docker', '--version'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                return False
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
            return False
        
        # Validate kernel version if specified
        kernel_version = config.get('kernel_version', self.kernel_version)
        if not re.match(r'^\d+\.\d+$', kernel_version):
            return False
        
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
        
        # Deduct points for findings
        deductions = 0.0
        for finding in findings:
            if finding.severity == Severity.CRITICAL:
                deductions += 20.0
            elif finding.severity == Severity.HIGH:
                deductions += 10.0
            elif finding.severity == Severity.MEDIUM:
                deductions += 5.0
            elif finding.severity == Severity.LOW:
                deductions += 2.0
        
        # Cap deductions at base score
        final_score = max(0.0, base_score - deductions)
        return min(100.0, final_score)
    
    def setup(self) -> bool:
        """
        Set up the compilation environment.
        
        Returns:
            True if setup successful
        """
        return self.environment.setup_environment()