"""
Correctness analyzer for Linux kernel driver code.

This module provides comprehensive correctness analysis by integrating:
- Clang Static Analyzer for semantic analysis
- Coccinelle for Linux kernel API pattern matching
- Custom validation rules for common driver implementation patterns
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


class CorrectnessCheckType(Enum):
    """Types of correctness checks."""
    CLANG_STATIC = "clang_static"
    COCCINELLE = "coccinelle"
    CUSTOM_VALIDATION = "custom_validation"
    ALL = "all"


@dataclass
class CorrectnessConfiguration:
    """Configuration for correctness analysis."""
    check_types: List[CorrectnessCheckType]
    timeout: int = 300  # 5 minutes total timeout
    kernel_version: str = "5.15"
    clang_checkers: List[str] = None
    coccinelle_rules: List[str] = None
    custom_rules: List[str] = None
    
    def __post_init__(self):
        if self.clang_checkers is None:
            self.clang_checkers = [
                "core",
                "deadcode",
                "security",
                "unix",
                "alpha.core",
                "alpha.security"
            ]
        if self.coccinelle_rules is None:
            self.coccinelle_rules = [
                "api_usage",
                "resource_management",
                "error_handling",
                "locking_patterns"
            ]
        if self.custom_rules is None:
            self.custom_rules = [
                "driver_patterns",
                "input_validation",
                "memory_safety"
            ]


class CorrectnessAnalyzer(BaseAnalyzer):
    """
    Comprehensive correctness analyzer for Linux kernel driver code.
    
    This analyzer combines multiple static analysis tools to detect:
    - Semantic errors and API misuse
    - Resource leaks and memory issues
    - Kernel API pattern violations
    - Common driver implementation mistakes
    """
    
    # Clang Static Analyzer checker configurations
    CLANG_CHECKERS = {
        "core": [
            "core.CallAndMessage",
            "core.DivideZero", 
            "core.NonNullParamChecker",
            "core.NullDereference",
            "core.StackAddressEscape",
            "core.UndefinedBinaryOperatorResult",
            "core.VLASize",
            "core.uninitialized.ArraySubscript",
            "core.uninitialized.Assign",
            "core.uninitialized.Branch",
            "core.uninitialized.CapturedBlockVariable",
            "core.uninitialized.UndefReturn"
        ],
        "deadcode": [
            "deadcode.DeadStores"
        ],
        "security": [
            "security.insecureAPI.UncheckedReturn",
            "security.insecureAPI.getpw",
            "security.insecureAPI.gets",
            "security.insecureAPI.mkstemp",
            "security.insecureAPI.mktemp",
            "security.insecureAPI.rand",
            "security.insecureAPI.strcpy",
            "security.insecureAPI.vfork"
        ],
        "unix": [
            "unix.API",
            "unix.Malloc",
            "unix.MallocSizeof",
            "unix.MismatchedDeallocator",
            "unix.cstring.BadSizeArg",
            "unix.cstring.NullArg"
        ],
        "alpha.core": [
            "alpha.core.BoolAssignment",
            "alpha.core.CastSize",
            "alpha.core.CastToStruct",
            "alpha.core.FixedAddr",
            "alpha.core.PointerArithm",
            "alpha.core.PointerSub",
            "alpha.core.SizeofPtr"
        ],
        "alpha.security": [
            "alpha.security.ArrayBound",
            "alpha.security.ArrayBoundV2",
            "alpha.security.MallocOverflow",
            "alpha.security.ReturnPtrRange"
        ]
    }
    
    def __init__(self, config: Optional[CorrectnessConfiguration] = None):
        """
        Initialize the correctness analyzer.
        
        Args:
            config: Correctness analysis configuration
        """
        self.config = config or CorrectnessConfiguration(
            check_types=[CorrectnessCheckType.CLANG_STATIC, CorrectnessCheckType.COCCINELLE, CorrectnessCheckType.CUSTOM_VALIDATION]
        )
        self.image_name = f"linux-driver-eval:kernel-{self.config.kernel_version}"
    
    @property
    def name(self) -> str:
        """Return the name of this analyzer."""
        return "correctness_analyzer"
    
    @property
    def version(self) -> str:
        """Return the version of this analyzer."""
        return "1.0.0"
    
    def analyze(self, source_files: List[str], config: Dict[str, Any]) -> AnalysisResult:
        """
        Analyze source files for correctness issues.
        
        Args:
            source_files: List of source file paths to analyze
            config: Additional configuration parameters
            
        Returns:
            AnalysisResult with correctness findings and metrics
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
                            type="correctness_error",
                            severity=Severity.CRITICAL,
                            file="",
                            line=0,
                            column=0,
                            message="No valid source files provided for correctness analysis",
                            recommendation="Ensure source files exist and are accessible"
                        )],
                        metrics={"correctness_attempted": False},
                        score=0.0
                    )
                
                # Run correctness analysis
                findings, metrics = self._run_correctness_analysis(temp_dir, temp_source_files)
                
                # Determine overall status
                if not findings:
                    status = AnalysisStatus.SUCCESS
                elif any(f.severity == Severity.CRITICAL for f in findings):
                    status = AnalysisStatus.FAILURE
                else:
                    status = AnalysisStatus.WARNING
                
                # Calculate score based on findings
                score = self._calculate_correctness_score(findings)
                
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
                    type="correctness_error",
                    severity=Severity.CRITICAL,
                    file="",
                    line=0,
                    column=0,
                    message=f"Correctness analysis failed: {str(e)}",
                    recommendation="Check system configuration and tool availability"
                )],
                metrics={"correctness_attempted": False, "error": str(e)},
                score=0.0
            )
    
    def _run_correctness_analysis(self, temp_dir: str, source_files: List[str]) -> Tuple[List[Finding], Dict[str, Any]]:
        """Run comprehensive correctness analysis."""
        all_findings = []
        metrics = {
            "correctness_attempted": True,
            "kernel_version": self.config.kernel_version,
            "check_types": [ct.value for ct in self.config.check_types],
            "total_checks": 0,
            "successful_checks": 0
        }
        
        # Run each configured check type
        for check_type in self.config.check_types:
            if check_type == CorrectnessCheckType.ALL:
                # Run all check types
                for ct in [CorrectnessCheckType.CLANG_STATIC, CorrectnessCheckType.COCCINELLE, 
                          CorrectnessCheckType.CUSTOM_VALIDATION]:
                    findings = self._run_correctness_check(temp_dir, source_files, ct)
                    if findings is not None:
                        all_findings.extend(findings)
                        metrics["successful_checks"] += 1
                    metrics["total_checks"] += 1
            else:
                findings = self._run_correctness_check(temp_dir, source_files, check_type)
                if findings is not None:
                    all_findings.extend(findings)
                    metrics["successful_checks"] += 1
                metrics["total_checks"] += 1
        
        # Calculate additional metrics
        metrics.update(self._calculate_correctness_metrics(all_findings))
        
        return all_findings, metrics
    
    def _run_correctness_check(self, temp_dir: str, source_files: List[str], check_type: CorrectnessCheckType) -> List[Finding]:
        """Run a specific type of correctness check."""
        try:
            if check_type == CorrectnessCheckType.CLANG_STATIC:
                return self._run_clang_static_analysis(temp_dir, source_files)
            elif check_type == CorrectnessCheckType.COCCINELLE:
                return self._run_coccinelle_analysis(temp_dir, source_files)
            elif check_type == CorrectnessCheckType.CUSTOM_VALIDATION:
                return self._run_custom_validation(temp_dir, source_files)
            else:
                return []
                
        except subprocess.TimeoutExpired:
            return [Finding(
                type="correctness_timeout",
                severity=Severity.MEDIUM,
                file="",
                line=0,
                column=0,
                message=f"Correctness {check_type.value} analysis timed out",
                recommendation="Consider reducing code complexity or increasing timeout"
            )]
        except Exception as e:
            return [Finding(
                type="correctness_error",
                severity=Severity.MEDIUM,
                file="",
                line=0,
                column=0,
                message=f"Correctness {check_type.value} analysis failed: {str(e)}",
                recommendation="Check tool configuration and system setup"
            )] 
   
    def _run_clang_static_analysis(self, temp_dir: str, source_files: List[str]) -> List[Finding]:
        """Run Clang Static Analyzer for semantic analysis."""
        findings = []
        
        # Build checker list from configuration
        enabled_checkers = []
        for checker_group in self.config.clang_checkers:
            if checker_group in self.CLANG_CHECKERS:
                enabled_checkers.extend(self.CLANG_CHECKERS[checker_group])
        
        checker_args = []
        for checker in enabled_checkers:
            checker_args.extend(["-enable-checker", checker])
        
        # Run clang static analyzer on each source file
        for source_file in source_files:
            try:
                # Create analysis command
                docker_cmd = [
                    'docker', 'run', '--rm',
                    '-v', f'{temp_dir}:/workspace',
                    '-w', '/workspace',
                    self.image_name,
                    'clang', '--analyze',
                    '-Xanalyzer', '-analyzer-output=text',
                    '-I/lib/modules/$(uname -r)/build/include',
                    '-I/lib/modules/$(uname -r)/build/arch/x86/include',
                    '-D__KERNEL__',
                    '-DMODULE'
                ] + checker_args + [os.path.basename(source_file)]
                
                result = subprocess.run(
                    docker_cmd,
                    capture_output=True,
                    text=True,
                    timeout=self.config.timeout // 3  # Divide timeout among check types
                )
                
                # Parse clang static analyzer output
                file_findings = self._parse_clang_output(result.stdout, result.stderr, source_file)
                findings.extend(file_findings)
                
            except subprocess.TimeoutExpired:
                findings.append(Finding(
                    type="clang_timeout",
                    severity=Severity.MEDIUM,
                    file=os.path.basename(source_file),
                    line=0,
                    column=0,
                    message="Clang static analysis timed out",
                    recommendation="Consider reducing code complexity"
                ))
            except Exception as e:
                findings.append(Finding(
                    type="clang_error",
                    severity=Severity.LOW,
                    file=os.path.basename(source_file),
                    line=0,
                    column=0,
                    message=f"Clang static analysis failed: {str(e)}",
                    recommendation="Check clang configuration"
                ))
        
        return findings
    
    def _parse_clang_output(self, stdout: str, stderr: str, source_file: str) -> List[Finding]:
        """Parse Clang Static Analyzer output."""
        findings = []
        combined_output = stdout + "\n" + stderr
        
        # Clang static analyzer output patterns
        warning_pattern = re.compile(
            r'(?P<file>[^:]+):(?P<line>\d+):(?P<column>\d+):\s*'
            r'warning:\s*(?P<message>.*?)\s*\[(?P<checker>[^\]]+)\]'
        )
        
        error_pattern = re.compile(
            r'(?P<file>[^:]+):(?P<line>\d+):(?P<column>\d+):\s*'
            r'error:\s*(?P<message>.*)'
        )
        
        # Parse warnings
        for match in warning_pattern.finditer(combined_output):
            finding = self._create_clang_finding(match, "warning", source_file)
            if finding:
                findings.append(finding)
        
        # Parse errors
        for match in error_pattern.finditer(combined_output):
            finding = self._create_clang_finding(match, "error", source_file)
            if finding:
                findings.append(finding)
        
        return findings
    
    def _create_clang_finding(self, match, finding_type: str, source_file: str) -> Optional[Finding]:
        """Create Finding from Clang Static Analyzer match."""
        try:
            file_path = match.group('file')
            line = int(match.group('line'))
            column = int(match.group('column'))
            message = match.group('message').strip()
            
            # Get checker name if available
            checker = match.groupdict().get('checker', 'unknown')
            
            # Determine severity based on checker and message
            severity = self._get_clang_severity(checker, message, finding_type)
            
            # Categorize the issue
            category = self._categorize_clang_issue(checker, message)
            
            return Finding(
                type=f"clang_{category}",
                severity=severity,
                file=os.path.basename(file_path),
                line=line,
                column=column,
                message=f"[{checker}] {message}",
                recommendation=self._get_clang_recommendation(category, message)
            )
            
        except (ValueError, AttributeError):
            return None
    
    def _get_clang_severity(self, checker: str, message: str, finding_type: str) -> Severity:
        """Determine severity for Clang Static Analyzer findings."""
        if finding_type == "error":
            return Severity.CRITICAL
        
        # Critical security and correctness issues
        critical_patterns = [
            "null pointer dereference",
            "use after free",
            "double free",
            "buffer overflow",
            "stack buffer overflow",
            "uninitialized variable"
        ]
        
        # High severity issues
        high_patterns = [
            "memory leak",
            "resource leak",
            "division by zero",
            "array bounds",
            "undefined behavior"
        ]
        
        message_lower = message.lower()
        
        for pattern in critical_patterns:
            if pattern in message_lower:
                return Severity.CRITICAL
        
        for pattern in high_patterns:
            if pattern in message_lower:
                return Severity.HIGH
        
        # Check checker-specific severity
        if any(sec_checker in checker for sec_checker in ["security", "alpha.security"]):
            return Severity.HIGH
        elif "core" in checker:
            return Severity.MEDIUM
        else:
            return Severity.LOW
    
    def _categorize_clang_issue(self, checker: str, message: str) -> str:
        """Categorize Clang Static Analyzer issue."""
        message_lower = message.lower()
        
        if "null" in message_lower and "dereference" in message_lower:
            return "null_dereference"
        elif "memory leak" in message_lower or "leak" in message_lower:
            return "memory_leak"
        elif "uninitialized" in message_lower:
            return "uninitialized"
        elif "buffer" in message_lower and "overflow" in message_lower:
            return "buffer_overflow"
        elif "division by zero" in message_lower:
            return "division_by_zero"
        elif "dead" in message_lower and "store" in message_lower:
            return "dead_store"
        elif "security" in checker:
            return "security"
        elif "unix" in checker:
            return "api_misuse"
        else:
            return "semantic"
    
    def _get_clang_recommendation(self, category: str, message: str) -> str:
        """Get recommendation for Clang Static Analyzer issue."""
        recommendations = {
            'null_dereference': "Add null pointer checks before dereferencing pointers",
            'memory_leak': "Ensure proper cleanup of allocated memory in all code paths",
            'uninitialized': "Initialize variables before use, especially in conditional branches",
            'buffer_overflow': "Use safe string functions and validate buffer bounds",
            'division_by_zero': "Add checks to ensure divisor is not zero",
            'dead_store': "Remove unused assignments or verify the logic is correct",
            'security': "Review security implications and use secure coding practices",
            'api_misuse': "Check API documentation and ensure proper usage patterns",
            'semantic': "Review the semantic issue and fix according to language standards"
        }
        
        return recommendations.get(category, "Address the static analysis issue identified")
    
    def _run_coccinelle_analysis(self, temp_dir: str, source_files: List[str]) -> List[Finding]:
        """Run Coccinelle for Linux kernel API pattern matching."""
        findings = []
        
        # Create Coccinelle semantic patches for kernel API patterns
        self._create_coccinelle_rules(temp_dir)
        
        # Run Coccinelle analysis for each rule
        for rule in self.config.coccinelle_rules:
            try:
                rule_file = f"{rule}.cocci"
                rule_path = os.path.join(temp_dir, "cocci_rules", rule_file)
                
                if not os.path.exists(rule_path):
                    continue
                
                # Run Coccinelle on all source files
                for source_file in source_files:
                    docker_cmd = [
                        'docker', 'run', '--rm',
                        '-v', f'{temp_dir}:/workspace',
                        '-w', '/workspace',
                        self.image_name,
                        'spatch',
                        '--sp-file', f'cocci_rules/{rule_file}',
                        '--dir', '.',
                        '--include-headers',
                        '--very-quiet'
                    ]
                    
                    result = subprocess.run(
                        docker_cmd,
                        capture_output=True,
                        text=True,
                        timeout=self.config.timeout // 3
                    )
                    
                    # Parse Coccinelle output
                    rule_findings = self._parse_coccinelle_output(result.stdout, result.stderr, rule, source_file)
                    findings.extend(rule_findings)
                    
            except subprocess.TimeoutExpired:
                findings.append(Finding(
                    type="coccinelle_timeout",
                    severity=Severity.MEDIUM,
                    file="",
                    line=0,
                    column=0,
                    message=f"Coccinelle rule '{rule}' timed out",
                    recommendation="Consider simplifying the semantic patch"
                ))
            except Exception as e:
                findings.append(Finding(
                    type="coccinelle_error",
                    severity=Severity.LOW,
                    file="",
                    line=0,
                    column=0,
                    message=f"Coccinelle rule '{rule}' failed: {str(e)}",
                    recommendation="Check Coccinelle rule syntax"
                ))
        
        return findings
    
    def _create_coccinelle_rules(self, temp_dir: str) -> None:
        """Create Coccinelle semantic patch rules for kernel API patterns."""
        rules_dir = os.path.join(temp_dir, "cocci_rules")
        os.makedirs(rules_dir, exist_ok=True)
        
        # API usage patterns
        api_usage_rule = """
// Check for proper error handling in kernel API calls
@@
expression E;
@@
E = kmalloc(...);
+ if (!E) return -ENOMEM;

@@
expression E;
@@
E = kzalloc(...);
+ if (!E) return -ENOMEM;

@@
expression E;
@@
E = ioremap(...);
+ if (!E) return -ENOMEM;
"""
        
        # Resource management patterns
        resource_mgmt_rule = """
// Check for proper resource cleanup
@@
expression E;
@@
E = kmalloc(...);
... when != kfree(E)
    when != E = NULL
return ...;

@@
expression E;
@@
E = ioremap(...);
... when != iounmap(E)
    when != E = NULL
return ...;
"""
        
        # Error handling patterns
        error_handling_rule = """
// Check for proper error code propagation
@@
expression E;
@@
E = platform_get_resource(...);
+ if (!E) return -ENODEV;

@@
expression E;
@@
E = devm_ioremap_resource(...);
+ if (IS_ERR(E)) return PTR_ERR(E);
"""
        
        # Locking patterns
        locking_rule = """
// Check for proper lock/unlock pairing
@@
expression lock;
@@
spin_lock(lock);
... when != spin_unlock(lock)
return ...;

@@
expression lock;
@@
mutex_lock(lock);
... when != mutex_unlock(lock)
return ...;
"""
        
        # Write rules to files
        rules = {
            "api_usage": api_usage_rule,
            "resource_management": resource_mgmt_rule,
            "error_handling": error_handling_rule,
            "locking_patterns": locking_rule
        }
        
        for rule_name, rule_content in rules.items():
            rule_path = os.path.join(rules_dir, f"{rule_name}.cocci")
            with open(rule_path, 'w') as f:
                f.write(rule_content)
    
    def _parse_coccinelle_output(self, stdout: str, stderr: str, rule: str, source_file: str) -> List[Finding]:
        """Parse Coccinelle output."""
        findings = []
        combined_output = stdout + "\n" + stderr
        
        # Coccinelle typically outputs diff-like format or specific messages
        # Look for file:line patterns and transformation suggestions
        pattern = re.compile(r'(?P<file>[^:]+):(?P<line>\d+):.*')
        
        for line in combined_output.split('\n'):
            line = line.strip()
            if not line:
                continue
            
            match = pattern.match(line)
            if match:
                try:
                    file_path = match.group('file')
                    line_num = int(match.group('line'))
                    
                    finding = Finding(
                        type=f"coccinelle_{rule}",
                        severity=self._get_coccinelle_severity(rule),
                        file=os.path.basename(file_path),
                        line=line_num,
                        column=0,
                        message=f"Kernel API pattern issue detected by rule '{rule}'",
                        recommendation=self._get_coccinelle_recommendation(rule)
                    )
                    findings.append(finding)
                    
                except (ValueError, AttributeError):
                    continue
        
        return findings
    
    def _get_coccinelle_severity(self, rule: str) -> Severity:
        """Get severity for Coccinelle rule violations."""
        severity_map = {
            'api_usage': Severity.HIGH,
            'resource_management': Severity.CRITICAL,
            'error_handling': Severity.HIGH,
            'locking_patterns': Severity.CRITICAL
        }
        return severity_map.get(rule, Severity.MEDIUM)
    
    def _get_coccinelle_recommendation(self, rule: str) -> str:
        """Get recommendation for Coccinelle rule violations."""
        recommendations = {
            'api_usage': "Follow proper kernel API usage patterns and check return values",
            'resource_management': "Ensure proper cleanup of allocated resources in all code paths",
            'error_handling': "Implement proper error handling and return appropriate error codes",
            'locking_patterns': "Ensure proper lock/unlock pairing to prevent deadlocks"
        }
        return recommendations.get(rule, "Follow kernel coding best practices")
    
    def _run_custom_validation(self, temp_dir: str, source_files: List[str]) -> List[Finding]:
        """Run custom validation rules for common driver implementation patterns."""
        findings = []
        
        for source_file in source_files:
            try:
                with open(source_file, 'r') as f:
                    content = f.read()
                
                # Run custom validation rules
                file_findings = []
                file_findings.extend(self._check_driver_patterns(content, source_file))
                file_findings.extend(self._check_input_validation(content, source_file))
                file_findings.extend(self._check_memory_safety(content, source_file))
                
                findings.extend(file_findings)
                
            except Exception as e:
                findings.append(Finding(
                    type="custom_validation_error",
                    severity=Severity.LOW,
                    file=os.path.basename(source_file),
                    line=0,
                    column=0,
                    message=f"Custom validation failed: {str(e)}",
                    recommendation="Check file accessibility and format"
                ))
        
        return findings
    
    def _check_driver_patterns(self, content: str, source_file: str) -> List[Finding]:
        """Check for common Linux driver implementation patterns."""
        findings = []
        lines = content.split('\n')
        
        # Check for required driver structure patterns
        has_init = False
        has_exit = False
        has_module_license = False
        has_file_operations = False
        
        for i, line in enumerate(lines, 1):
            line_stripped = line.strip()
            
            # Check for module init/exit functions
            if re.search(r'module_init\s*\(', line_stripped):
                has_init = True
            elif re.search(r'module_exit\s*\(', line_stripped):
                has_exit = True
            elif re.search(r'MODULE_LICENSE\s*\(', line_stripped):
                has_module_license = True
            elif re.search(r'struct\s+file_operations', line_stripped):
                has_file_operations = True
            
            # Check for dangerous function usage
            dangerous_functions = ['strcpy', 'sprintf', 'gets', 'strcat']
            for func in dangerous_functions:
                if re.search(rf'\b{func}\s*\(', line_stripped):
                    findings.append(Finding(
                        type="dangerous_function",
                        severity=Severity.HIGH,
                        file=os.path.basename(source_file),
                        line=i,
                        column=line.find(func),
                        message=f"Use of dangerous function '{func}' detected",
                        recommendation=f"Replace '{func}' with safer alternatives like strncpy, snprintf, etc."
                    ))
            
            # Check for proper copy_from_user/copy_to_user usage
            if 'copy_from_user' in line_stripped and 'if' not in line_stripped:
                findings.append(Finding(
                    type="unchecked_copy_from_user",
                    severity=Severity.HIGH,
                    file=os.path.basename(source_file),
                    line=i,
                    column=0,
                    message="copy_from_user return value not checked",
                    recommendation="Always check return value of copy_from_user for security"
                ))
        
        # Check for missing required patterns
        if not has_init:
            findings.append(Finding(
                type="missing_module_init",
                severity=Severity.CRITICAL,
                file=os.path.basename(source_file),
                line=0,
                column=0,
                message="Missing module_init() declaration",
                recommendation="Add module_init() to register driver initialization function"
            ))
        
        if not has_exit:
            findings.append(Finding(
                type="missing_module_exit",
                severity=Severity.CRITICAL,
                file=os.path.basename(source_file),
                line=0,
                column=0,
                message="Missing module_exit() declaration",
                recommendation="Add module_exit() to register driver cleanup function"
            ))
        
        if not has_module_license:
            findings.append(Finding(
                type="missing_module_license",
                severity=Severity.HIGH,
                file=os.path.basename(source_file),
                line=0,
                column=0,
                message="Missing MODULE_LICENSE declaration",
                recommendation="Add MODULE_LICENSE() to specify driver license"
            ))
        
        return findings
    
    def _check_input_validation(self, content: str, source_file: str) -> List[Finding]:
        """Check for proper input validation patterns."""
        findings = []
        lines = content.split('\n')
        
        for i, line in enumerate(lines, 1):
            line_stripped = line.strip()
            
            # Check for array access without bounds checking
            array_access_pattern = r'\w+\s*\[\s*\w+\s*\]'
            if re.search(array_access_pattern, line_stripped):
                # Look for bounds checking in surrounding lines
                context_start = max(0, i-3)
                context_end = min(len(lines), i+2)
                context = '\n'.join(lines[context_start:context_end])
                
                if not re.search(r'if\s*\(.*<.*\)|if\s*\(.*>.*\)', context):
                    findings.append(Finding(
                        type="unchecked_array_access",
                        severity=Severity.MEDIUM,
                        file=os.path.basename(source_file),
                        line=i,
                        column=0,
                        message="Array access without bounds checking",
                        recommendation="Add bounds checking before array access"
                    ))
            
            # Check for pointer dereference without null checking
            if '->' in line_stripped and 'if' not in line_stripped:
                # Simple heuristic - look for null checks in nearby lines
                context_start = max(0, i-3)
                context_end = min(len(lines), i+2)
                context = '\n'.join(lines[context_start:context_end])
                
                if not re.search(r'if\s*\(.*!\s*\w+\)|if\s*\(\s*\w+\s*==\s*NULL\)', context):
                    findings.append(Finding(
                        type="unchecked_pointer_dereference",
                        severity=Severity.MEDIUM,
                        file=os.path.basename(source_file),
                        line=i,
                        column=0,
                        message="Pointer dereference without null checking",
                        recommendation="Add null pointer checks before dereferencing"
                    ))
        
        return findings
    
    def _check_memory_safety(self, content: str, source_file: str) -> List[Finding]:
        """Check for memory safety issues."""
        findings = []
        lines = content.split('\n')
        
        allocated_vars = set()
        freed_vars = set()
        
        for i, line in enumerate(lines, 1):
            line_stripped = line.strip()
            
            # Track memory allocations
            alloc_match = re.search(r'(\w+)\s*=\s*(k[mz]alloc|vmalloc|ioremap)\s*\(', line_stripped)
            if alloc_match:
                var_name = alloc_match.group(1)
                allocated_vars.add(var_name)
            
            # Track memory deallocations
            free_match = re.search(r'(kfree|vfree|iounmap)\s*\(\s*(\w+)\s*\)', line_stripped)
            if free_match:
                var_name = free_match.group(2)
                freed_vars.add(var_name)
            
            # Check for use after free patterns
            if free_match:
                var_name = free_match.group(2)
                # Look ahead for usage of freed variable
                for j in range(i, min(len(lines), i+10)):
                    if var_name in lines[j] and 'kfree' not in lines[j] and 'vfree' not in lines[j]:
                        findings.append(Finding(
                            type="use_after_free",
                            severity=Severity.CRITICAL,
                            file=os.path.basename(source_file),
                            line=j+1,
                            column=0,
                            message=f"Potential use after free of variable '{var_name}'",
                            recommendation="Avoid using freed memory and set pointer to NULL after freeing"
                        ))
                        break
        
        # Check for memory leaks (allocated but not freed)
        leaked_vars = allocated_vars - freed_vars
        for var in leaked_vars:
            findings.append(Finding(
                type="memory_leak",
                severity=Severity.HIGH,
                file=os.path.basename(source_file),
                line=0,
                column=0,
                message=f"Potential memory leak: variable '{var}' allocated but not freed",
                recommendation="Ensure proper cleanup of allocated memory in all code paths"
            ))
        
        return findings
    
    def _calculate_correctness_metrics(self, findings: List[Finding]) -> Dict[str, Any]:
        """Calculate detailed correctness analysis metrics."""
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
            category = finding.type
            categories[category] = categories.get(category, 0) + 1
        
        # Add category counts
        for category, count in categories.items():
            metrics[f'{category}_count'] = count
        
        return metrics
    
    def _calculate_correctness_score(self, findings: List[Finding]) -> float:
        """
        Calculate correctness analysis score based on findings.
        
        Args:
            findings: List of correctness findings
            
        Returns:
            Score from 0.0 to 100.0
        """
        if not findings:
            return 100.0
        
        base_score = 100.0
        deductions = 0.0
        
        for finding in findings:
            if finding.severity == Severity.CRITICAL:
                deductions += 30.0
            elif finding.severity == Severity.HIGH:
                deductions += 20.0
            elif finding.severity == Severity.MEDIUM:
                deductions += 10.0
            elif finding.severity == Severity.LOW:
                deductions += 5.0
        
        final_score = max(0.0, base_score - deductions)
        return min(100.0, final_score)
    
    def validate_config(self, config: Dict[str, Any]) -> bool:
        """
        Validate configuration for the correctness analyzer.
        
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
        
        # Check if required tools are available in the image
        required_tools = ['clang', 'spatch']  # spatch is the Coccinelle command
        
        for tool in required_tools:
            try:
                result = subprocess.run([
                    'docker', 'run', '--rm', self.image_name, 'which', tool
                ], capture_output=True, text=True, timeout=30)
                
                if result.returncode != 0:
                    return False
                    
            except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
                return False
        
        return True