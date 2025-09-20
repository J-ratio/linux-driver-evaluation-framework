"""
Security scanner for Linux kernel driver code.

This module provides comprehensive security analysis by integrating:
- Flawfinder for buffer overflow and security vulnerability detection
- Custom kernel security pattern matching rules
- Race condition detection using static analysis techniques
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


class SecurityCheckType(Enum):
    """Types of security checks."""
    FLAWFINDER = "flawfinder"
    KERNEL_SECURITY = "kernel_security"
    RACE_CONDITIONS = "race_conditions"
    ALL = "all"


@dataclass
class SecurityConfiguration:
    """Configuration for security analysis."""
    check_types: List[SecurityCheckType]
    timeout: int = 300  # 5 minutes total timeout
    flawfinder_min_level: int = 1  # Minimum risk level for Flawfinder
    enable_context_analysis: bool = True
    custom_security_rules: List[str] = None
    
    def __post_init__(self):
        if self.custom_security_rules is None:
            self.custom_security_rules = [
                "buffer_overflow_patterns",
                "privilege_escalation",
                "input_validation",
                "memory_corruption",
                "concurrency_issues"
            ]


class SecurityScanner(BaseAnalyzer):
    """
    Comprehensive security scanner for Linux kernel driver code.
    
    This analyzer combines multiple security analysis techniques to detect:
    - Buffer overflows and memory corruption vulnerabilities
    - Race conditions and concurrency issues
    - Privilege escalation vulnerabilities
    - Input validation failures
    - Kernel-specific security anti-patterns
    """
    
    # Dangerous functions that should be flagged
    DANGEROUS_FUNCTIONS = {
        'strcpy': {
            'severity': Severity.HIGH,
            'message': 'strcpy() can cause buffer overflows',
            'recommendation': 'Use strncpy() or strlcpy() instead'
        },
        'sprintf': {
            'severity': Severity.HIGH,
            'message': 'sprintf() can cause buffer overflows',
            'recommendation': 'Use snprintf() with proper buffer size checking'
        },
        'strcat': {
            'severity': Severity.MEDIUM,
            'message': 'strcat() can cause buffer overflows',
            'recommendation': 'Use strncat() or strlcat() instead'
        },
        'gets': {
            'severity': Severity.CRITICAL,
            'message': 'gets() is inherently unsafe',
            'recommendation': 'Use fgets() or safer input methods'
        },
        'vsprintf': {
            'severity': Severity.HIGH,
            'message': 'vsprintf() can cause buffer overflows',
            'recommendation': 'Use vsnprintf() with proper buffer size checking'
        }
    }
    
    # Kernel-specific security patterns
    KERNEL_SECURITY_PATTERNS = {
        'unchecked_copy_from_user': {
            'pattern': r'copy_from_user\s*\([^)]+\)\s*(?![;,]\s*(?:if|&&|\|\|))',
            'severity': Severity.CRITICAL,
            'message': 'Unchecked copy_from_user() can lead to kernel memory corruption',
            'recommendation': 'Always check return value of copy_from_user()'
        },
        'unchecked_copy_to_user': {
            'pattern': r'copy_to_user\s*\([^)]+\)\s*(?![;,]\s*(?:if|&&|\|\|))',
            'severity': Severity.HIGH,
            'message': 'Unchecked copy_to_user() can indicate data leakage',
            'recommendation': 'Always check return value of copy_to_user()'
        },
        'unchecked_get_user': {
            'pattern': r'get_user\s*\([^)]+\)\s*(?![;,]\s*(?:if|&&|\|\|))',
            'severity': Severity.HIGH,
            'message': 'Unchecked get_user() can lead to security issues',
            'recommendation': 'Always check return value of get_user()'
        },
        'unchecked_put_user': {
            'pattern': r'put_user\s*\([^)]+\)\s*(?![;,]\s*(?:if|&&|\|\|))',
            'severity': Severity.HIGH,
            'message': 'Unchecked put_user() can indicate data leakage',
            'recommendation': 'Always check return value of put_user()'
        },
        'direct_hardware_access': {
            'pattern': r'(?:inb|inw|inl|outb|outw|outl)\s*\(',
            'severity': Severity.MEDIUM,
            'message': 'Direct hardware I/O without proper validation',
            'recommendation': 'Ensure proper port validation and access control'
        },
        'unchecked_kmalloc': {
            'pattern': r'kmalloc\s*\([^)]+\)\s*(?![;,]\s*(?:if|&&|\|\|))',
            'severity': Severity.HIGH,
            'message': 'Unchecked kmalloc() can lead to null pointer dereference',
            'recommendation': 'Always check return value of kmalloc()'
        },
        'integer_overflow_risk': {
            'pattern': r'kmalloc\s*\(\s*[^)]*\*[^)]*\)',
            'severity': Severity.MEDIUM,
            'message': 'Potential integer overflow in memory allocation',
            'recommendation': 'Use kmalloc_array() or check for overflow before multiplication'
        }
    }
    
    # Race condition patterns
    RACE_CONDITION_PATTERNS = {
        'toctou_file_access': {
            'pattern': r'(?:access|stat|lstat)\s*\([^)]+\).*(?:open|fopen)\s*\(',
            'severity': Severity.HIGH,
            'message': 'Potential TOCTOU (Time-of-Check-Time-of-Use) race condition',
            'recommendation': 'Use atomic operations or proper locking mechanisms'
        },
        'unlocked_global_access': {
            'pattern': r'(?:static|extern)\s+(?:int|long|char|void\s*\*)\s+\w+.*=',
            'severity': Severity.MEDIUM,
            'message': 'Global variable access without visible locking',
            'recommendation': 'Protect global variables with appropriate locking mechanisms'
        },
        'missing_lock_check': {
            'pattern': r'(?:spin_lock|mutex_lock|read_lock|write_lock)\s*\([^)]+\)(?:(?!(?:spin_unlock|mutex_unlock|read_unlock|write_unlock)).)*return',
            'severity': Severity.CRITICAL,
            'message': 'Lock acquired but not released on all paths',
            'recommendation': 'Ensure locks are released on all code paths'
        }
    }
    
    def __init__(self, config: Optional[SecurityConfiguration] = None):
        """
        Initialize the security scanner.
        
        Args:
            config: Security analysis configuration
        """
        self.config = config or SecurityConfiguration(
            check_types=[SecurityCheckType.FLAWFINDER, SecurityCheckType.KERNEL_SECURITY, SecurityCheckType.RACE_CONDITIONS]
        )
        self.image_name = "linux-driver-eval:kernel-5.15"
    
    @property
    def name(self) -> str:
        """Return the name of this analyzer."""
        return "security"
    
    @property
    def version(self) -> str:
        """Return the version of this analyzer."""
        return "1.0.0"
    
    def analyze(self, source_files: List[str], config: Dict[str, Any]) -> AnalysisResult:
        """
        Analyze source files for security vulnerabilities.
        
        Args:
            source_files: List of source file paths to analyze
            config: Additional configuration parameters
            
        Returns:
            AnalysisResult with security findings and metrics
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
                            type="security_error",
                            severity=Severity.CRITICAL,
                            file="",
                            line=0,
                            column=0,
                            message="No valid source files provided for security analysis",
                            recommendation="Ensure source files exist and are accessible"
                        )],
                        metrics={"security_attempted": False},
                        score=0.0
                    )
                
                # Run security analysis
                findings, metrics = self._run_security_analysis(temp_dir, temp_source_files)
                
                # Determine overall status
                if not findings:
                    status = AnalysisStatus.SUCCESS
                elif any(f.severity == Severity.CRITICAL for f in findings):
                    status = AnalysisStatus.FAILURE
                else:
                    status = AnalysisStatus.WARNING
                
                # Calculate score based on findings
                score = self._calculate_security_score(findings)
                
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
                    type="security_error",
                    severity=Severity.CRITICAL,
                    file="",
                    line=0,
                    column=0,
                    message=f"Security analysis failed: {str(e)}",
                    recommendation="Check system configuration and tool availability"
                )],
                metrics={"security_attempted": False, "error": str(e)},
                score=0.0
            )
    
    def validate_config(self, config: Dict[str, Any]) -> bool:
        """
        Validate the configuration for this analyzer.
        
        Args:
            config: Configuration to validate
            
        Returns:
            True if configuration is valid, False otherwise
        """
        try:
            # Check for required configuration keys
            if 'timeout' in config and not isinstance(config['timeout'], int):
                return False
            
            if 'flawfinder_min_level' in config:
                level = config['flawfinder_min_level']
                if not isinstance(level, int) or level < 0 or level > 5:
                    return False
            
            return True
        except Exception:
            return False
    
    def _run_security_analysis(self, temp_dir: str, source_files: List[str]) -> Tuple[List[Finding], Dict[str, Any]]:
        """Run comprehensive security analysis."""
        all_findings = []
        metrics = {
            "security_attempted": True,
            "check_types": [ct.value for ct in self.config.check_types],
            "total_checks": 0,
            "successful_checks": 0,
            "flawfinder_min_level": self.config.flawfinder_min_level
        }
        
        # Run each configured check type
        for check_type in self.config.check_types:
            if check_type == SecurityCheckType.ALL:
                # Run all check types
                for ct in [SecurityCheckType.FLAWFINDER, SecurityCheckType.KERNEL_SECURITY, 
                          SecurityCheckType.RACE_CONDITIONS]:
                    findings = self._run_security_check(temp_dir, source_files, ct)
                    if findings is not None:
                        all_findings.extend(findings)
                        metrics["successful_checks"] += 1
                    metrics["total_checks"] += 1
            else:
                findings = self._run_security_check(temp_dir, source_files, check_type)
                if findings is not None:
                    all_findings.extend(findings)
                    metrics["successful_checks"] += 1
                metrics["total_checks"] += 1
        
        # Calculate additional metrics
        metrics.update(self._calculate_security_metrics(all_findings))
        
        return all_findings, metrics
    
    def _run_security_check(self, temp_dir: str, source_files: List[str], check_type: SecurityCheckType) -> List[Finding]:
        """Run a specific type of security check."""
        try:
            if check_type == SecurityCheckType.FLAWFINDER:
                return self._run_flawfinder_analysis(temp_dir, source_files)
            elif check_type == SecurityCheckType.KERNEL_SECURITY:
                return self._run_kernel_security_analysis(temp_dir, source_files)
            elif check_type == SecurityCheckType.RACE_CONDITIONS:
                return self._run_race_condition_analysis(temp_dir, source_files)
            else:
                return []
                
        except subprocess.TimeoutExpired:
            return [Finding(
                type="security_timeout",
                severity=Severity.MEDIUM,
                file="",
                line=0,
                column=0,
                message=f"Security {check_type.value} analysis timed out",
                recommendation="Consider reducing code complexity or increasing timeout"
            )]
        except Exception as e:
            return [Finding(
                type="security_error",
                severity=Severity.MEDIUM,
                file="",
                line=0,
                column=0,
                message=f"Security {check_type.value} analysis failed: {str(e)}",
                recommendation="Check tool configuration and system setup"
            )]
    
    def _run_flawfinder_analysis(self, temp_dir: str, source_files: List[str]) -> List[Finding]:
        """Run Flawfinder for buffer overflow and security vulnerability detection."""
        findings = []
        
        try:
            # Create flawfinder command
            docker_cmd = [
                'docker', 'run', '--rm',
                '-v', f'{temp_dir}:/workspace',
                '-w', '/workspace',
                self.image_name,
                'flawfinder',
                '--minlevel', str(self.config.flawfinder_min_level),
                '--context',
                '--dataonly',
                '--quiet'
            ] + [os.path.basename(f) for f in source_files]
            
            result = subprocess.run(
                docker_cmd,
                capture_output=True,
                text=True,
                timeout=self.config.timeout // 3  # Divide timeout among check types
            )
            
            # Parse flawfinder output
            findings = self._parse_flawfinder_output(result.stdout, result.stderr)
            
        except subprocess.TimeoutExpired:
            findings.append(Finding(
                type="flawfinder_timeout",
                severity=Severity.MEDIUM,
                file="",
                line=0,
                column=0,
                message="Flawfinder analysis timed out",
                recommendation="Consider reducing code complexity"
            ))
        except Exception as e:
            findings.append(Finding(
                type="flawfinder_error",
                severity=Severity.LOW,
                file="",
                line=0,
                column=0,
                message=f"Flawfinder analysis failed: {str(e)}",
                recommendation="Check flawfinder installation and configuration"
            ))
        
        return findings
    
    def _parse_flawfinder_output(self, stdout: str, stderr: str) -> List[Finding]:
        """Parse Flawfinder output."""
        findings = []
        combined_output = stdout + "\n" + stderr
        
        # Flawfinder output pattern: filename:line:column: [level] (rulename) message
        pattern = re.compile(
            r'(?P<file>[^:]+):(?P<line>\d+):(?P<column>\d+):\s*'
            r'\[(?P<level>\d+)\]\s*'
            r'(?:\((?P<rule>[^)]+)\))?\s*'
            r'(?P<message>.*)'
        )
        
        for line in combined_output.split('\n'):
            line = line.strip()
            if not line:
                continue
            
            match = pattern.match(line)
            if match:
                try:
                    file_path = match.group('file')
                    line_num = int(match.group('line'))
                    column = int(match.group('column'))
                    level = int(match.group('level'))
                    rule = match.group('rule') or 'unknown'
                    message = match.group('message').strip()
                    
                    # Convert flawfinder level to severity
                    severity = self._flawfinder_level_to_severity(level)
                    
                    finding = Finding(
                        type=f"flawfinder_{rule}",
                        severity=severity,
                        file=os.path.basename(file_path),
                        line=line_num,
                        column=column,
                        message=f"[Flawfinder] {message}",
                        recommendation=self._get_flawfinder_recommendation(rule, message)
                    )
                    findings.append(finding)
                    
                except (ValueError, AttributeError):
                    continue
        
        return findings
    
    def _flawfinder_level_to_severity(self, level: int) -> Severity:
        """Convert Flawfinder risk level to Severity."""
        if level >= 4:
            return Severity.CRITICAL
        elif level == 3:
            return Severity.HIGH
        elif level == 2:
            return Severity.MEDIUM
        else:
            return Severity.LOW
    
    def _get_flawfinder_recommendation(self, rule: str, message: str) -> str:
        """Get recommendation for Flawfinder findings."""
        message_lower = message.lower()
        
        if 'buffer' in message_lower and 'overflow' in message_lower:
            return "Use safer string functions with bounds checking (strncpy, snprintf, etc.)"
        elif 'format string' in message_lower:
            return "Use format strings with proper validation and avoid user-controlled format strings"
        elif 'race condition' in message_lower:
            return "Use proper synchronization mechanisms to prevent race conditions"
        elif 'random' in message_lower:
            return "Use cryptographically secure random number generators for security-sensitive operations"
        elif 'shell' in message_lower:
            return "Avoid shell command execution or properly sanitize inputs"
        else:
            return "Review the security issue and implement appropriate mitigations"
    
    def _run_kernel_security_analysis(self, temp_dir: str, source_files: List[str]) -> List[Finding]:
        """Run custom kernel security pattern matching."""
        findings = []
        
        for source_file in source_files:
            try:
                with open(source_file, 'r') as f:
                    content = f.read()
                
                # Check for dangerous functions
                file_findings = self._check_dangerous_functions(content, source_file)
                findings.extend(file_findings)
                
                # Check for kernel-specific security patterns
                file_findings = self._check_kernel_security_patterns(content, source_file)
                findings.extend(file_findings)
                
                # Check for privilege escalation patterns
                file_findings = self._check_privilege_escalation(content, source_file)
                findings.extend(file_findings)
                
            except Exception as e:
                findings.append(Finding(
                    type="kernel_security_error",
                    severity=Severity.LOW,
                    file=os.path.basename(source_file),
                    line=0,
                    column=0,
                    message=f"Kernel security analysis failed: {str(e)}",
                    recommendation="Check file accessibility and format"
                ))
        
        return findings
    
    def _check_dangerous_functions(self, content: str, source_file: str) -> List[Finding]:
        """Check for usage of dangerous functions."""
        findings = []
        lines = content.split('\n')
        
        for i, line in enumerate(lines, 1):
            line_stripped = line.strip()
            
            for func_name, func_info in self.DANGEROUS_FUNCTIONS.items():
                pattern = rf'\b{func_name}\s*\('
                match = re.search(pattern, line_stripped)
                if match:
                    findings.append(Finding(
                        type=f"dangerous_function_{func_name}",
                        severity=func_info['severity'],
                        file=os.path.basename(source_file),
                        line=i,
                        column=match.start(),
                        message=func_info['message'],
                        recommendation=func_info['recommendation']
                    ))
        
        return findings
    
    def _check_kernel_security_patterns(self, content: str, source_file: str) -> List[Finding]:
        """Check for kernel-specific security patterns."""
        findings = []
        lines = content.split('\n')
        
        for pattern_name, pattern_info in self.KERNEL_SECURITY_PATTERNS.items():
            pattern = re.compile(pattern_info['pattern'], re.MULTILINE | re.DOTALL)
            
            for match in pattern.finditer(content):
                # Find line number for the match
                line_num = content[:match.start()].count('\n') + 1
                
                findings.append(Finding(
                    type=f"kernel_security_{pattern_name}",
                    severity=pattern_info['severity'],
                    file=os.path.basename(source_file),
                    line=line_num,
                    column=match.start() - content.rfind('\n', 0, match.start()),
                    message=pattern_info['message'],
                    recommendation=pattern_info['recommendation']
                ))
        
        return findings
    
    def _check_privilege_escalation(self, content: str, source_file: str) -> List[Finding]:
        """Check for potential privilege escalation vulnerabilities."""
        findings = []
        lines = content.split('\n')
        
        # Patterns that might indicate privilege escalation risks
        privilege_patterns = [
            {
                'pattern': r'capable\s*\(\s*CAP_SYS_ADMIN\s*\)',
                'message': 'Usage of CAP_SYS_ADMIN capability - very broad privileges',
                'recommendation': 'Use more specific capabilities instead of CAP_SYS_ADMIN'
            },
            {
                'pattern': r'current->cred',
                'message': 'Direct manipulation of process credentials',
                'recommendation': 'Use proper kernel APIs for credential management'
            },
            {
                'pattern': r'set_current_groups',
                'message': 'Direct group manipulation detected',
                'recommendation': 'Ensure proper authorization before changing process groups'
            },
            {
                'pattern': r'commit_creds\s*\(',
                'message': 'Direct credential commitment detected',
                'recommendation': 'Ensure credentials are properly validated before committing'
            }
        ]
        
        for i, line in enumerate(lines, 1):
            line_stripped = line.strip()
            
            for pattern_info in privilege_patterns:
                match = re.search(pattern_info['pattern'], line_stripped)
                if match:
                    findings.append(Finding(
                        type="privilege_escalation_risk",
                        severity=Severity.HIGH,
                        file=os.path.basename(source_file),
                        line=i,
                        column=match.start(),
                        message=pattern_info['message'],
                        recommendation=pattern_info['recommendation']
                    ))
        
        return findings
    
    def _run_race_condition_analysis(self, temp_dir: str, source_files: List[str]) -> List[Finding]:
        """Run race condition detection using static analysis."""
        findings = []
        
        for source_file in source_files:
            try:
                with open(source_file, 'r') as f:
                    content = f.read()
                
                # Check for race condition patterns
                file_findings = self._check_race_condition_patterns(content, source_file)
                findings.extend(file_findings)
                
                # Check for locking issues
                file_findings = self._check_locking_issues(content, source_file)
                findings.extend(file_findings)
                
                # Check for atomic operation usage
                file_findings = self._check_atomic_operations(content, source_file)
                findings.extend(file_findings)
                
            except Exception as e:
                findings.append(Finding(
                    type="race_condition_error",
                    severity=Severity.LOW,
                    file=os.path.basename(source_file),
                    line=0,
                    column=0,
                    message=f"Race condition analysis failed: {str(e)}",
                    recommendation="Check file accessibility and format"
                ))
        
        return findings
    
    def _check_race_condition_patterns(self, content: str, source_file: str) -> List[Finding]:
        """Check for race condition patterns."""
        findings = []
        
        for pattern_name, pattern_info in self.RACE_CONDITION_PATTERNS.items():
            pattern = re.compile(pattern_info['pattern'], re.MULTILINE | re.DOTALL)
            
            for match in pattern.finditer(content):
                # Find line number for the match
                line_num = content[:match.start()].count('\n') + 1
                
                findings.append(Finding(
                    type=f"race_condition_{pattern_name}",
                    severity=pattern_info['severity'],
                    file=os.path.basename(source_file),
                    line=line_num,
                    column=match.start() - content.rfind('\n', 0, match.start()),
                    message=pattern_info['message'],
                    recommendation=pattern_info['recommendation']
                ))
        
        return findings
    
    def _check_locking_issues(self, content: str, source_file: str) -> List[Finding]:
        """Check for locking-related issues."""
        findings = []
        lines = content.split('\n')
        
        # Track lock/unlock pairs
        lock_stack = []
        
        for i, line in enumerate(lines, 1):
            line_stripped = line.strip()
            
            # Check for lock acquisitions
            lock_patterns = [
                r'spin_lock(?:_irqsave|_irq|_bh)?\s*\(',
                r'mutex_lock(?:_interruptible)?\s*\(',
                r'read_lock(?:_irqsave|_irq|_bh)?\s*\(',
                r'write_lock(?:_irqsave|_irq|_bh)?\s*\('
            ]
            
            for pattern in lock_patterns:
                if re.search(pattern, line_stripped):
                    lock_stack.append((i, pattern))
            
            # Check for lock releases
            unlock_patterns = [
                r'spin_unlock(?:_irqrestore|_irq|_bh)?\s*\(',
                r'mutex_unlock\s*\(',
                r'read_unlock(?:_irqrestore|_irq|_bh)?\s*\(',
                r'write_unlock(?:_irqrestore|_irq|_bh)?\s*\('
            ]
            
            for pattern in unlock_patterns:
                if re.search(pattern, line_stripped) and lock_stack:
                    lock_stack.pop()
            
            # Check for return statements with held locks
            if 'return' in line_stripped and lock_stack:
                findings.append(Finding(
                    type="lock_not_released",
                    severity=Severity.CRITICAL,
                    file=os.path.basename(source_file),
                    line=i,
                    column=line_stripped.find('return'),
                    message=f"Return statement with {len(lock_stack)} unreleased lock(s)",
                    recommendation="Ensure all acquired locks are released before returning"
                ))
        
        # Check for unreleased locks at end of function
        if lock_stack:
            findings.append(Finding(
                type="unreleased_locks",
                severity=Severity.HIGH,
                file=os.path.basename(source_file),
                line=len(lines),
                column=0,
                message=f"{len(lock_stack)} lock(s) acquired but not released",
                recommendation="Ensure all acquired locks are properly released"
            ))
        
        return findings
    
    def _check_atomic_operations(self, content: str, source_file: str) -> List[Finding]:
        """Check for proper atomic operation usage."""
        findings = []
        lines = content.split('\n')
        
        for i, line in enumerate(lines, 1):
            line_stripped = line.strip()
            
            # Check for non-atomic operations on shared variables
            if re.search(r'\+\+|\-\-', line_stripped) and 'atomic' not in line_stripped:
                # Look for global or static variables
                if re.search(r'(?:static|extern)\s+\w+', line_stripped):
                    findings.append(Finding(
                        type="non_atomic_increment",
                        severity=Severity.MEDIUM,
                        file=os.path.basename(source_file),
                        line=i,
                        column=0,
                        message="Non-atomic increment/decrement on potentially shared variable",
                        recommendation="Use atomic operations for shared variable modifications"
                    ))
        
        return findings
    
    def _calculate_security_score(self, findings: List[Finding]) -> float:
        """Calculate security score based on findings."""
        if not findings:
            return 100.0
        
        # Weight findings by severity
        severity_weights = {
            Severity.CRITICAL: 20,
            Severity.HIGH: 10,
            Severity.MEDIUM: 5,
            Severity.LOW: 2,
            Severity.INFO: 1
        }
        
        total_penalty = sum(severity_weights.get(f.severity, 1) for f in findings)
        
        # Calculate score (max penalty of 100 points)
        score = max(0.0, 100.0 - min(total_penalty, 100.0))
        
        return score
    
    def _calculate_security_metrics(self, findings: List[Finding]) -> Dict[str, Any]:
        """Calculate additional security metrics."""
        metrics = {
            "total_findings": len(findings),
            "critical_findings": len([f for f in findings if f.severity == Severity.CRITICAL]),
            "high_findings": len([f for f in findings if f.severity == Severity.HIGH]),
            "medium_findings": len([f for f in findings if f.severity == Severity.MEDIUM]),
            "low_findings": len([f for f in findings if f.severity == Severity.LOW]),
            "info_findings": len([f for f in findings if f.severity == Severity.INFO])
        }
        
        # Categorize findings by type
        finding_types = {}
        for finding in findings:
            finding_type = finding.type.split('_')[0]  # Get base type
            finding_types[finding_type] = finding_types.get(finding_type, 0) + 1
        
        metrics["finding_types"] = finding_types
        
        return metrics