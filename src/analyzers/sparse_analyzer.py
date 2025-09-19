"""
Sparse semantic analyzer for Linux kernel driver code.

This module provides dedicated sparse analysis capabilities for detecting
kernel-specific semantic issues, context problems, and API usage violations.
"""

import os
import re
import subprocess
import tempfile
import shutil
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

from src.core.interfaces import BaseAnalyzer, AnalysisResult, AnalysisStatus, Finding, Severity


class SparseCheckType(Enum):
    """Types of sparse semantic checks."""
    STANDARD = "standard"
    ENHANCED = "enhanced"
    CONTEXT = "context"
    ENDIANNESS = "endianness"
    BITWISE = "bitwise"
    ALL = "all"


@dataclass
class SparseConfiguration:
    """Configuration for sparse analysis."""
    check_types: List[SparseCheckType]
    timeout: int = 180  # 3 minutes total timeout
    kernel_version: str = "5.15"
    additional_flags: List[str] = None
    
    def __post_init__(self):
        if self.additional_flags is None:
            self.additional_flags = []


class SparseAnalyzer(BaseAnalyzer):
    """Dedicated sparse semantic analyzer for kernel code."""
    
    # Sparse check configurations
    SPARSE_CONFIGS = {
        SparseCheckType.STANDARD: [
            "-D__CHECK_ENDIAN__"
        ],
        SparseCheckType.ENHANCED: [
            "-D__CHECK_ENDIAN__",
            "-Wbitwise",
            "-Wcast-to-as", 
            "-Wdefault-bitfield-sign",
            "-Wdo-while",
            "-Winit-cstring",
            "-Wone-bit-signed-bitfield",
            "-Wparen-string",
            "-Wptr-subtraction-blows",
            "-Wreturn-void",
            "-Wshadow",
            "-Wtransparent-union",
            "-Wtypesign",
            "-Wundef"
        ],
        SparseCheckType.CONTEXT: [
            "-D__CHECK_ENDIAN__",
            "-Wcontext",
            "-Wcast-truncate"
        ],
        SparseCheckType.ENDIANNESS: [
            "-D__CHECK_ENDIAN__",
            "-Wendian-mismatch",
            "-Wbitwise"
        ],
        SparseCheckType.BITWISE: [
            "-Wbitwise",
            "-Wbitwise-pointer",
            "-Wcast-to-as"
        ]
    }
    
    def __init__(self, config: Optional[SparseConfiguration] = None):
        """
        Initialize the sparse analyzer.
        
        Args:
            config: Sparse analysis configuration
        """
        self.config = config or SparseConfiguration(
            check_types=[SparseCheckType.STANDARD, SparseCheckType.ENHANCED]
        )
        self.image_name = f"linux-driver-eval:kernel-{self.config.kernel_version}"
    
    @property
    def name(self) -> str:
        """Return the name of this analyzer."""
        return "sparse_analyzer"
    
    @property
    def version(self) -> str:
        """Return the version of this analyzer."""
        return "1.0.0"
    
    def analyze(self, source_files: List[str], config: Dict[str, Any]) -> AnalysisResult:
        """
        Analyze source files using sparse semantic checker.
        
        Args:
            source_files: List of source file paths to analyze
            config: Additional configuration parameters
            
        Returns:
            AnalysisResult with sparse findings and metrics
        """
        try:
            # Create temporary directory for analysis
            with tempfile.TemporaryDirectory() as temp_dir:
                # Copy source files to temp directory
                temp_source_files = []
                for source_file in source_files:
                    if os.path.exists(source_file):
                        dest_path = os.path.join(temp_dir, os.path.basename(source_file))
                        shutil.copy2(source_file, dest_path)
                        temp_source_files.append(dest_path)
                
                if not temp_source_files:
                    return AnalysisResult(
                        analyzer=self.name,
                        status=AnalysisStatus.FAILURE,
                        findings=[Finding(
                            type="sparse_error",
                            severity=Severity.CRITICAL,
                            file="",
                            line=0,
                            column=0,
                            message="No valid source files provided for sparse analysis",
                            recommendation="Ensure source files exist and are accessible"
                        )],
                        metrics={"sparse_attempted": False},
                        score=0.0
                    )
                
                # Run sparse analysis
                findings, metrics = self._run_sparse_analysis(temp_dir, temp_source_files)
                
                # Determine overall status
                if not findings:
                    status = AnalysisStatus.SUCCESS
                elif any(f.severity == Severity.CRITICAL for f in findings):
                    status = AnalysisStatus.FAILURE
                else:
                    status = AnalysisStatus.WARNING
                
                # Calculate score based on findings
                score = self._calculate_sparse_score(findings)
                
                return AnalysisResult(
                    analyzer=self.name,
                    status=status,
                    findings=findings,
                    metrics=metrics,
                    score=score
                )
                
        except Exception as e:
            return AnalysisResult(
                analyzer=self.name,
                status=AnalysisStatus.FAILURE,
                findings=[Finding(
                    type="sparse_error",
                    severity=Severity.CRITICAL,
                    file="",
                    line=0,
                    column=0,
                    message=f"Sparse analysis failed: {str(e)}",
                    recommendation="Check system configuration and Docker availability"
                )],
                metrics={"sparse_attempted": False, "error": str(e)},
                score=0.0
            )
    
    def _run_sparse_analysis(self, temp_dir: str, source_files: List[str]) -> Tuple[List[Finding], Dict[str, Any]]:
        """Run comprehensive sparse analysis."""
        all_findings = []
        metrics = {
            "sparse_attempted": True,
            "kernel_version": self.config.kernel_version,
            "check_types": [ct.value for ct in self.config.check_types],
            "total_checks": 0,
            "successful_checks": 0
        }
        
        # Create Makefile for sparse analysis
        self._create_sparse_makefile(temp_dir, source_files)
        
        # Run each configured check type
        for check_type in self.config.check_types:
            if check_type == SparseCheckType.ALL:
                # Run all check types
                for ct in [SparseCheckType.STANDARD, SparseCheckType.ENHANCED, 
                          SparseCheckType.CONTEXT, SparseCheckType.ENDIANNESS, 
                          SparseCheckType.BITWISE]:
                    findings = self._run_sparse_check(temp_dir, ct)
                    all_findings.extend(findings)
                    metrics["total_checks"] += 1
                    if findings is not None:
                        metrics["successful_checks"] += 1
            else:
                findings = self._run_sparse_check(temp_dir, check_type)
                all_findings.extend(findings)
                metrics["total_checks"] += 1
                if findings is not None:
                    metrics["successful_checks"] += 1
        
        # Calculate additional metrics
        metrics.update(self._calculate_sparse_metrics(all_findings))
        
        return all_findings, metrics
    
    def _run_sparse_check(self, temp_dir: str, check_type: SparseCheckType) -> List[Finding]:
        """Run a specific type of sparse check."""
        try:
            # Get sparse flags for this check type
            sparse_flags = self.SPARSE_CONFIGS.get(check_type, [])
            sparse_flags.extend(self.config.additional_flags)
            
            # Create custom Makefile target for this check
            makefile_target = f"sparse-{check_type.value}"
            
            # Run sparse analysis
            docker_cmd = [
                'docker', 'run', '--rm',
                '-v', f'{temp_dir}:/workspace',
                '-w', '/workspace',
                self.image_name,
                'make', makefile_target
            ]
            
            result = subprocess.run(
                docker_cmd,
                capture_output=True,
                text=True,
                timeout=self.config.timeout // len(self.config.check_types)
            )
            
            # Parse sparse output
            return self._parse_sparse_output(result.stdout, result.stderr, check_type)
            
        except subprocess.TimeoutExpired:
            return [Finding(
                type="sparse_timeout",
                severity=Severity.MEDIUM,
                file="",
                line=0,
                column=0,
                message=f"Sparse {check_type.value} analysis timed out",
                recommendation="Consider reducing code complexity or increasing timeout"
            )]
        except Exception as e:
            return [Finding(
                type="sparse_error",
                severity=Severity.MEDIUM,
                file="",
                line=0,
                column=0,
                message=f"Sparse {check_type.value} analysis failed: {str(e)}",
                recommendation="Check sparse configuration and system setup"
            )]
    
    def _create_sparse_makefile(self, temp_dir: str, source_files: List[str]) -> None:
        """Create Makefile with sparse analysis targets."""
        # Extract object file names
        obj_files = []
        for source_file in source_files:
            base_name = os.path.splitext(os.path.basename(source_file))[0]
            obj_files.append(f"{base_name}.o")
        
        makefile_content = f"""
# Sparse analysis Makefile
obj-m := {' '.join(obj_files)}

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

# Base sparse command
SPARSE_BASE = $(MAKE) -C $(KDIR) M=$(PWD) C=2

# Sparse check targets
sparse-standard:
\t$(SPARSE_BASE) CF="{' '.join(self.SPARSE_CONFIGS[SparseCheckType.STANDARD])}" modules

sparse-enhanced:
\t$(SPARSE_BASE) CF="{' '.join(self.SPARSE_CONFIGS[SparseCheckType.ENHANCED])}" modules

sparse-context:
\t$(SPARSE_BASE) CF="{' '.join(self.SPARSE_CONFIGS[SparseCheckType.CONTEXT])}" modules

sparse-endianness:
\t$(SPARSE_BASE) CF="{' '.join(self.SPARSE_CONFIGS[SparseCheckType.ENDIANNESS])}" modules

sparse-bitwise:
\t$(SPARSE_BASE) CF="{' '.join(self.SPARSE_CONFIGS[SparseCheckType.BITWISE])}" modules

.PHONY: sparse-standard sparse-enhanced sparse-context sparse-endianness sparse-bitwise
"""
        
        makefile_path = os.path.join(temp_dir, 'Makefile')
        with open(makefile_path, 'w') as f:
            f.write(makefile_content)
    
    def _parse_sparse_output(self, stdout: str, stderr: str, check_type: SparseCheckType) -> List[Finding]:
        """Parse sparse output to extract findings."""
        findings = []
        combined_output = stdout + "\n" + stderr
        
        # Sparse message pattern
        sparse_pattern = re.compile(
            r'(?P<file>[^:]+):(?P<line>\d+):(?P<column>\d+):\s*'
            r'(?P<type>warning|error):\s*(?P<message>.*)'
        )
        
        for match in sparse_pattern.finditer(combined_output):
            try:
                file_path = match.group('file')
                line = int(match.group('line'))
                column = int(match.group('column'))
                message_type = match.group('type')
                message = match.group('message').strip()
                
                # Categorize and create finding
                category = self._categorize_sparse_issue(message)
                severity = self._get_sparse_severity(category, message_type)
                
                finding = Finding(
                    type=f"sparse_{category}",
                    severity=severity,
                    file=os.path.basename(file_path),
                    line=line,
                    column=column,
                    message=f"[{check_type.value}] {message}",
                    recommendation=self._get_sparse_recommendation(category, message)
                )
                
                findings.append(finding)
                
            except (ValueError, AttributeError):
                continue
        
        return findings
    
    def _categorize_sparse_issue(self, message: str) -> str:
        """Categorize sparse issue by type."""
        message_lower = message.lower()
        
        # More comprehensive pattern matching
        if "address space" in message_lower or "different address spaces" in message_lower:
            return "address_space"
        elif ("endian" in message_lower or "restricted" in message_lower or 
              "__be32" in message_lower or "__le32" in message_lower or
              "cast from restricted" in message_lower):
            return "endianness"
        elif "context" in message_lower and ("imbalance" in message_lower or "problem" in message_lower):
            return "context"
        elif "lock" in message_lower or "unlock" in message_lower:
            return "locking"
        elif "null" in message_lower and "dereference" in message_lower:
            return "null_pointer"
        elif "uninitialized" in message_lower or "may be used uninitialized" in message_lower:
            return "uninitialized"
        elif "cast" in message_lower and ("truncat" in message_lower or "bits" in message_lower):
            return "cast_truncation"
        elif ("bitwise" in message_lower or "dubious" in message_lower or 
              ("&" in message and "!" in message)):
            return "bitwise"
        elif "redeclar" in message_lower or "redefinition" in message_lower:
            return "redeclaration"
        else:
            return "semantic"
    
    def _get_sparse_severity(self, category: str, message_type: str) -> Severity:
        """Determine severity based on sparse issue category."""
        critical_categories = {'null_pointer', 'context', 'locking'}
        high_categories = {'address_space', 'uninitialized', 'cast_truncation'}
        medium_categories = {'endianness', 'bitwise', 'redeclaration'}
        
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
    
    def _get_sparse_recommendation(self, category: str, message: str) -> str:
        """Get recommendation for sparse issue category."""
        recommendations = {
            'address_space': "Use proper address space annotations (__user, __kernel, __iomem) and appropriate access functions",
            'endianness': "Use proper endianness conversion functions (cpu_to_le32, be32_to_cpu, etc.)",
            'context': "Ensure proper context handling and use appropriate kernel APIs for the current context",
            'locking': "Verify lock/unlock pairing and use appropriate locking primitives",
            'null_pointer': "Add null pointer checks before dereferencing pointers",
            'uninitialized': "Initialize variables before use, especially in error paths",
            'cast_truncation': "Verify cast operations don't lose significant data",
            'bitwise': "Use proper bitwise operations and ensure type consistency",
            'redeclaration': "Remove duplicate declarations or use proper header guards",
            'semantic': "Review sparse output and address kernel-specific semantic issues"
        }
        
        return recommendations.get(category, "Address the sparse semantic issue identified")
    
    def _calculate_sparse_metrics(self, findings: List[Finding]) -> Dict[str, Any]:
        """Calculate detailed sparse analysis metrics."""
        metrics = {
            'total_findings': len(findings),
            'critical_issues': 0,
            'high_issues': 0,
            'medium_issues': 0,
            'low_issues': 0
        }
        
        # Count by category
        categories = {}
        for finding in findings:
            # Count by severity
            if finding.severity == Severity.CRITICAL:
                metrics['critical_issues'] += 1
            elif finding.severity == Severity.HIGH:
                metrics['high_issues'] += 1
            elif finding.severity == Severity.MEDIUM:
                metrics['medium_issues'] += 1
            elif finding.severity == Severity.LOW:
                metrics['low_issues'] += 1
            
            # Count by category
            category = finding.type.replace('sparse_', '')
            categories[category] = categories.get(category, 0) + 1
        
        # Add category counts
        for category, count in categories.items():
            metrics[f'{category}_count'] = count
        
        return metrics
    
    def _calculate_sparse_score(self, findings: List[Finding]) -> float:
        """
        Calculate sparse analysis score based on findings.
        
        Args:
            findings: List of sparse findings
            
        Returns:
            Score from 0.0 to 100.0
        """
        if not findings:
            return 100.0
        
        base_score = 100.0
        deductions = 0.0
        
        for finding in findings:
            if finding.severity == Severity.CRITICAL:
                deductions += 25.0
            elif finding.severity == Severity.HIGH:
                deductions += 15.0
            elif finding.severity == Severity.MEDIUM:
                deductions += 8.0
            elif finding.severity == Severity.LOW:
                deductions += 3.0
        
        final_score = max(0.0, base_score - deductions)
        return min(100.0, final_score)
    
    def validate_config(self, config: Dict[str, Any]) -> bool:
        """
        Validate configuration for the sparse analyzer.
        
        Args:
            config: Configuration to validate
            
        Returns:
            True if configuration is valid
        """
        # Check for Docker availability
        try:
            result = subprocess.run(['docker', '--version'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                return False
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
            return False
        
        # Check if sparse is available in the image
        try:
            result = subprocess.run([
                'docker', 'run', '--rm', self.image_name, 'which', 'sparse'
            ], capture_output=True, text=True, timeout=30)
            
            return result.returncode == 0
            
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
            return False