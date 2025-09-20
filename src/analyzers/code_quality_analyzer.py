"""
Code quality analyzer for Linux kernel driver code.

This module provides comprehensive code quality analysis by integrating:
- checkpatch.pl for Linux kernel coding style compliance
- Cyclomatic complexity analysis for maintainability assessment
- Documentation coverage analysis for driver functions and structures
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


class CodeQualityCheckType(Enum):
    """Types of code quality checks."""
    CHECKPATCH = "checkpatch"
    COMPLEXITY = "complexity"
    DOCUMENTATION = "documentation"
    ALL = "all"


@dataclass
class CodeQualityConfiguration:
    """Configuration for code quality analysis."""
    check_types: List[CodeQualityCheckType]
    timeout: int = 300  # 5 minutes total timeout
    checkpatch_strict: bool = False
    max_complexity: int = 10
    min_doc_coverage: float = 0.7  # 70% documentation coverage
    ignore_checkpatch_types: List[str] = None
    
    def __post_init__(self):
        if self.ignore_checkpatch_types is None:
            self.ignore_checkpatch_types = [
                "LONG_LINE_COMMENT",  # Allow longer comment lines
                "CAMELCASE"  # Some kernel APIs use camelCase
            ]


class CodeQualityAnalyzer(BaseAnalyzer):
    """
    Comprehensive code quality analyzer for Linux kernel driver code.
    
    This analyzer combines multiple quality analysis tools to assess:
    - Coding style compliance with Linux kernel standards
    - Code complexity and maintainability metrics
    - Documentation coverage and quality
    """
    
    # Complexity thresholds for different severity levels
    COMPLEXITY_THRESHOLDS = {
        'low': 10,
        'medium': 20,
        'high': 30,
        'critical': 40
    }
    
    # Documentation patterns to look for
    DOC_PATTERNS = {
        'function_doc': r'/\*\*\s*\n(?:\s*\*[^\n]*\n)*\s*\*/\s*(?:static\s+)?(?:inline\s+)?(?:\w+\s+)*\w+\s*\([^)]*\)\s*{',
        'struct_doc': r'/\*\*\s*\n(?:\s*\*[^\n]*\n)*\s*\*/\s*struct\s+\w+\s*{',
        'enum_doc': r'/\*\*\s*\n(?:\s*\*[^\n]*\n)*\s*\*/\s*enum\s+\w+\s*{',
        'define_doc': r'/\*\*\s*\n(?:\s*\*[^\n]*\n)*\s*\*/\s*#define\s+\w+'
    }
    
    def __init__(self, config: Optional[CodeQualityConfiguration] = None):
        """
        Initialize the code quality analyzer.
        
        Args:
            config: Code quality analysis configuration
        """
        self.config = config or CodeQualityConfiguration(
            check_types=[CodeQualityCheckType.CHECKPATCH, CodeQualityCheckType.COMPLEXITY, CodeQualityCheckType.DOCUMENTATION]
        )
        self.image_name = "linux-driver-eval:kernel-5.15"
    
    @property
    def name(self) -> str:
        """Return the name of this analyzer."""
        return "code_quality"
    
    @property
    def version(self) -> str:
        """Return the version of this analyzer."""
        return "1.0.0"
    
    def analyze(self, source_files: List[str], config: Dict[str, Any]) -> AnalysisResult:
        """
        Analyze source files for code quality issues.
        
        Args:
            source_files: List of source file paths to analyze
            config: Additional configuration parameters
            
        Returns:
            AnalysisResult with code quality findings and metrics
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
                            type="code_quality_error",
                            severity=Severity.CRITICAL,
                            file="",
                            line=0,
                            column=0,
                            message="No valid source files provided for code quality analysis",
                            recommendation="Ensure source files exist and are accessible"
                        )],
                        metrics={"code_quality_attempted": False},
                        score=0.0
                    )
                
                # Run code quality analysis
                findings, metrics = self._run_code_quality_analysis(temp_dir, temp_source_files)
                
                # Determine overall status
                if not findings:
                    status = AnalysisStatus.SUCCESS
                elif any(f.severity == Severity.CRITICAL for f in findings):
                    status = AnalysisStatus.FAILURE
                else:
                    status = AnalysisStatus.WARNING
                
                # Calculate score based on findings
                score = self._calculate_code_quality_score(findings, metrics)
                
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
                    type="code_quality_error",
                    severity=Severity.CRITICAL,
                    file="",
                    line=0,
                    column=0,
                    message=f"Code quality analysis failed: {str(e)}",
                    recommendation="Check system configuration and tool availability"
                )],
                metrics={"code_quality_attempted": False, "error": str(e)},
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
            
            if 'max_complexity' in config:
                complexity = config['max_complexity']
                if not isinstance(complexity, int) or complexity < 1:
                    return False
            
            if 'min_doc_coverage' in config:
                coverage = config['min_doc_coverage']
                if not isinstance(coverage, (int, float)) or coverage < 0 or coverage > 1:
                    return False
            
            return True
        except Exception:
            return False
    
    def _run_code_quality_analysis(self, temp_dir: str, source_files: List[str]) -> Tuple[List[Finding], Dict[str, Any]]:
        """Run comprehensive code quality analysis."""
        all_findings = []
        metrics = {
            "code_quality_attempted": True,
            "check_types": [ct.value for ct in self.config.check_types],
            "total_checks": 0,
            "successful_checks": 0,
            "checkpatch_strict": self.config.checkpatch_strict,
            "max_complexity": self.config.max_complexity,
            "min_doc_coverage": self.config.min_doc_coverage
        }

        # Run each configured check type
        for check_type in self.config.check_types:
            if check_type == CodeQualityCheckType.ALL:
                # Run all check types
                for ct in [CodeQualityCheckType.CHECKPATCH, CodeQualityCheckType.COMPLEXITY, 
                          CodeQualityCheckType.DOCUMENTATION]:
                    findings = self._run_code_quality_check(temp_dir, source_files, ct)
                    if findings is not None:
                        all_findings.extend(findings)
                        metrics["successful_checks"] += 1
                    metrics["total_checks"] += 1
            else:
                findings = self._run_code_quality_check(temp_dir, source_files, check_type)
                if findings is not None:
                    all_findings.extend(findings)
                    metrics["successful_checks"] += 1
                metrics["total_checks"] += 1
        
        # Calculate additional metrics
        metrics.update(self._calculate_code_quality_metrics(all_findings, source_files))
        
        return all_findings, metrics
    
    def _run_code_quality_check(self, temp_dir: str, source_files: List[str], check_type: CodeQualityCheckType) -> List[Finding]:
        """Run a specific type of code quality check."""
        try:
            if check_type == CodeQualityCheckType.CHECKPATCH:
                return self._run_checkpatch_analysis(temp_dir, source_files)
            elif check_type == CodeQualityCheckType.COMPLEXITY:
                return self._run_complexity_analysis(temp_dir, source_files)
            elif check_type == CodeQualityCheckType.DOCUMENTATION:
                return self._run_documentation_analysis(temp_dir, source_files)
            else:
                return []
                
        except subprocess.TimeoutExpired:
            return [Finding(
                type="code_quality_timeout",
                severity=Severity.MEDIUM,
                file="",
                line=0,
                column=0,
                message=f"Code quality {check_type.value} analysis timed out",
                recommendation="Consider reducing code complexity or increasing timeout"
            )]
        except Exception as e:
            return [Finding(
                type="code_quality_error",
                severity=Severity.MEDIUM,
                file="",
                line=0,
                column=0,
                message=f"Code quality {check_type.value} analysis failed: {str(e)}",
                recommendation="Check tool configuration and system setup"
            )]
    
    def _run_checkpatch_analysis(self, temp_dir: str, source_files: List[str]) -> List[Finding]:
        """Run checkpatch.pl for Linux kernel coding style compliance."""
        findings = []
        
        # Download checkpatch.pl if not available
        checkpatch_path = os.path.join(temp_dir, "checkpatch.pl")
        self._ensure_checkpatch_available(temp_dir)
        
        for source_file in source_files:
            try:
                # Build checkpatch command
                cmd_args = ['perl', 'checkpatch.pl', '--no-tree', '--file']
                
                if self.config.checkpatch_strict:
                    cmd_args.append('--strict')
                
                # Add ignore types
                for ignore_type in self.config.ignore_checkpatch_types:
                    cmd_args.extend(['--ignore', ignore_type])
                
                cmd_args.append(os.path.basename(source_file))
                
                # Run checkpatch in Docker container
                docker_cmd = [
                    'docker', 'run', '--rm',
                    '-v', f'{temp_dir}:/workspace',
                    '-w', '/workspace',
                    self.image_name
                ] + cmd_args
                
                result = subprocess.run(
                    docker_cmd,
                    capture_output=True,
                    text=True,
                    timeout=self.config.timeout // 3  # Divide timeout among check types
                )
                
                # Parse checkpatch output
                file_findings = self._parse_checkpatch_output(result.stdout, result.stderr, source_file)
                findings.extend(file_findings)
                
            except subprocess.TimeoutExpired:
                findings.append(Finding(
                    type="checkpatch_timeout",
                    severity=Severity.MEDIUM,
                    file=os.path.basename(source_file),
                    line=0,
                    column=0,
                    message="Checkpatch analysis timed out",
                    recommendation="Consider reducing file size or complexity"
                ))
            except Exception as e:
                findings.append(Finding(
                    type="checkpatch_error",
                    severity=Severity.LOW,
                    file=os.path.basename(source_file),
                    line=0,
                    column=0,
                    message=f"Checkpatch analysis failed: {str(e)}",
                    recommendation="Check checkpatch.pl availability and configuration"
                ))
        
        return findings
    
    def _ensure_checkpatch_available(self, temp_dir: str) -> None:
        """Ensure checkpatch.pl is available in the temp directory."""
        checkpatch_path = os.path.join(temp_dir, "checkpatch.pl")
        
        if not os.path.exists(checkpatch_path):
            # Create a simplified checkpatch.pl script for basic style checking
            checkpatch_content = '''#!/usr/bin/perl
# Simplified checkpatch.pl for basic Linux kernel style checking

use strict;
use warnings;

my $file = $ARGV[-1];
my $strict = grep { $_ eq '--strict' } @ARGV;
my @ignore_types = ();

# Parse ignore types
for my $i (0..$#ARGV-1) {
    if ($ARGV[$i] eq '--ignore' && $i < $#ARGV) {
        push @ignore_types, $ARGV[$i+1];
    }
}

open(my $fh, '<', $file) or die "Cannot open file: $!";
my @lines = <$fh>;
close($fh);

my $line_num = 0;
my $errors = 0;
my $warnings = 0;

for my $line (@lines) {
    $line_num++;
    chomp $line;
    
    # Check line length (warning at 80, error at 100)
    if (length($line) > 100) {
        print "ERROR:LONG_LINE: line over 100 characters\\n";
        print "#$line_num: FILE: $file:$line_num:\\n";
        $errors++;
    } elsif (length($line) > 80 && !grep { $_ eq 'LONG_LINE' } @ignore_types) {
        print "WARNING:LONG_LINE: line over 80 characters\\n";
        print "#$line_num: FILE: $file:$line_num:\\n";
        $warnings++;
    }
    
    # Check for trailing whitespace
    if ($line =~ /\\s+$/ && !grep { $_ eq 'TRAILING_WHITESPACE' } @ignore_types) {
        print "ERROR:TRAILING_WHITESPACE: trailing whitespace\\n";
        print "#$line_num: FILE: $file:$line_num:\\n";
        $errors++;
    }
    
    # Check for spaces instead of tabs for indentation
    if ($line =~ /^        / && $line !~ /^\\t/ && !grep { $_ eq 'LEADING_SPACE' } @ignore_types) {
        print "ERROR:LEADING_SPACE: please, no spaces at the start of a line\\n";
        print "#$line_num: FILE: $file:$line_num:\\n";
        $errors++;
    }
    
    # Check for missing space after keywords
    if ($line =~ /\\b(if|for|while|switch)\\(/ && !grep { $_ eq 'SPACING' } @ignore_types) {
        print "ERROR:SPACING: space required after that '$1'\\n";
        print "#$line_num: FILE: $file:$line_num:\\n";
        $errors++;
    }
    
    # Check for C99 comments in kernel code
    if ($line =~ m|//| && !grep { $_ eq 'C99_COMMENTS' } @ignore_types) {
        print "ERROR:C99_COMMENTS: do not use C99 // comments\\n";
        print "#$line_num: FILE: $file:$line_num:\\n";
        $errors++;
    }
    
    # Check for missing braces
    if ($line =~ /^\\s*(if|else|for|while|do)\\s*\\([^)]*\\)\\s*[^{;]/ && !grep { $_ eq 'BRACES' } @ignore_types) {
        print "WARNING:BRACES: braces {} are necessary for all arms of this statement\\n";
        print "#$line_num: FILE: $file:$line_num:\\n";
        $warnings++;
    }
}

print "\\ntotal: $errors errors, $warnings warnings, " . scalar(@lines) . " lines checked\\n";

if ($errors > 0) {
    exit(1);
} elsif ($warnings > 0) {
    exit(2);
} else {
    exit(0);
}
'''
            
            with open(checkpatch_path, 'w') as f:
                f.write(checkpatch_content)
            
            os.chmod(checkpatch_path, 0o755)
    
    def _parse_checkpatch_output(self, stdout: str, stderr: str, source_file: str) -> List[Finding]:
        """Parse checkpatch.pl output."""
        findings = []
        combined_output = stdout + "\n" + stderr
        
        # Checkpatch output patterns
        # ERROR:TYPE: message
        # #line_num: FILE: filename:line_num:
        error_pattern = re.compile(r'ERROR:([^:]+):\s*(.*)')
        warning_pattern = re.compile(r'WARNING:([^:]+):\s*(.*)')
        line_pattern = re.compile(r'#(\d+):\s*FILE:\s*([^:]+):(\d+):')
        
        lines = combined_output.split('\n')
        current_finding = None
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            # Check for error/warning
            error_match = error_pattern.match(line)
            warning_match = warning_pattern.match(line)
            
            if error_match:
                current_finding = {
                    'type': error_match.group(1),
                    'message': error_match.group(2),
                    'severity': Severity.LOW
                }
            elif warning_match:
                current_finding = {
                    'type': warning_match.group(1),
                    'message': warning_match.group(2),
                    'severity': Severity.LOW
                }
            
            # Check for line information
            line_match = line_pattern.match(line)
            if line_match and current_finding:
                line_num = int(line_match.group(1))
                file_path = line_match.group(2)
                
                finding = Finding(
                    type=f"checkpatch_{current_finding['type'].lower()}",
                    severity=current_finding['severity'],
                    file=os.path.basename(file_path),
                    line=line_num,
                    column=0,
                    message=f"[checkpatch] {current_finding['message']}",
                    recommendation=self._get_checkpatch_recommendation(current_finding['type'])
                )
                findings.append(finding)
                current_finding = None
        
        return findings
    
    def _get_checkpatch_recommendation(self, error_type: str) -> str:
        """Get recommendation for checkpatch error types."""
        recommendations = {
            'LONG_LINE': "Break long lines at appropriate points, preferably before operators",
            'TRAILING_WHITESPACE': "Remove trailing whitespace from the end of lines",
            'LEADING_SPACE': "Use tabs instead of spaces for indentation",
            'SPACING': "Add required spaces after keywords and around operators",
            'C99_COMMENTS': "Use /* */ style comments instead of // comments",
            'BRACES': "Add braces around all conditional and loop statements",
            'CAMELCASE': "Use lowercase with underscores instead of camelCase",
            'OPEN_BRACE': "Place opening braces on the same line as the statement",
            'CLOSE_BRACE': "Place closing braces on their own line"
        }
        return recommendations.get(error_type, "Follow Linux kernel coding style guidelines")
    
    def _run_complexity_analysis(self, temp_dir: str, source_files: List[str]) -> List[Finding]:
        """Run cyclomatic complexity analysis for maintainability assessment."""
        findings = []
        
        for source_file in source_files:
            try:
                with open(source_file, 'r') as f:
                    content = f.read()
                
                # Analyze complexity for each function
                functions = self._extract_functions(content)
                
                for func_name, func_info in functions.items():
                    complexity = self._calculate_cyclomatic_complexity(func_info['body'])
                    
                    if complexity > self.config.max_complexity:
                        severity = self._get_complexity_severity(complexity)
                        
                        finding = Finding(
                            type="high_complexity",
                            severity=severity,
                            file=os.path.basename(source_file),
                            line=func_info['line'],
                            column=0,
                            message=f"Function '{func_name}' has cyclomatic complexity of {complexity} (threshold: {self.config.max_complexity})",
                            recommendation=self._get_complexity_recommendation(complexity)
                        )
                        findings.append(finding)
                
            except Exception as e:
                findings.append(Finding(
                    type="complexity_error",
                    severity=Severity.LOW,
                    file=os.path.basename(source_file),
                    line=0,
                    column=0,
                    message=f"Complexity analysis failed: {str(e)}",
                    recommendation="Check file format and accessibility"
                ))
        
        return findings
    
    def _extract_functions(self, content: str) -> Dict[str, Dict[str, Any]]:
        """Extract function definitions from C code."""
        functions = {}
        lines = content.split('\n')
        
        # Function detection pattern that excludes static inline functions
        func_pattern = re.compile(
            r'^\s*(?:static\s+)?(?:const\s+)?'
            r'(?:\w+\s+)*(\w+)\s*\([^)]*\)\s*{'
        )
        
        # Pattern to detect static inline functions (to exclude)
        inline_pattern = re.compile(r'^\s*static\s+inline\s+')
        
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            
            # Skip static inline functions
            if inline_pattern.match(lines[i]):
                i += 1
                continue
                
            match = func_pattern.match(lines[i])
            
            if match:
                func_name = match.group(1)
                start_line = i + 1
                
                # Find function body (simple brace matching)
                brace_count = 1
                func_body = []
                i += 1
                
                while i < len(lines) and brace_count > 0:
                    line = lines[i]
                    func_body.append(line)
                    
                    # Count braces (simplified)
                    brace_count += line.count('{') - line.count('}')
                    i += 1
                
                functions[func_name] = {
                    'line': start_line,
                    'body': '\n'.join(func_body)
                }
            else:
                i += 1
        
        return functions
    
    def _calculate_cyclomatic_complexity(self, func_body: str) -> int:
        """Calculate cyclomatic complexity of a function."""
        # Start with base complexity of 1
        complexity = 1
        
        # Decision points that increase complexity
        decision_patterns = [
            r'\bif\s*\(',
            r'\belse\s+if\s*\(',
            r'\bwhile\s*\(',
            r'\bfor\s*\(',
            r'\bdo\s*{',
            r'\bswitch\s*\(',
            r'\bcase\s+',
            r'\bdefault\s*:',
            r'\b\?\s*.*\s*:',  # Ternary operator
            r'\&\&',  # Logical AND
            r'\|\|'   # Logical OR
        ]
        
        for pattern in decision_patterns:
            matches = re.findall(pattern, func_body, re.IGNORECASE)
            complexity += len(matches)
        
        return complexity
    
    def _get_complexity_severity(self, complexity: int) -> Severity:
        """Get severity level based on complexity score."""
        if complexity >= self.COMPLEXITY_THRESHOLDS['critical']:
            return Severity.CRITICAL
        elif complexity >= self.COMPLEXITY_THRESHOLDS['high']:
            return Severity.HIGH
        elif complexity >= self.COMPLEXITY_THRESHOLDS['medium']:
            return Severity.MEDIUM
        else:
            return Severity.LOW
    
    def _get_complexity_recommendation(self, complexity: int) -> str:
        """Get recommendation based on complexity level."""
        if complexity >= 20:
            return "Consider breaking this function into smaller, more focused functions"
        elif complexity >= 15:
            return "This function is quite complex. Consider refactoring to improve maintainability"
        elif complexity >= 10:
            return "Consider simplifying this function or breaking it into smaller parts"
        else:
            return "Consider minor refactoring to reduce complexity"
    
    def _run_documentation_analysis(self, temp_dir: str, source_files: List[str]) -> List[Finding]:
        """Run documentation coverage analysis for driver functions and structures."""
        findings = []
        
        for source_file in source_files:
            try:
                with open(source_file, 'r') as f:
                    content = f.read()
                
                # Analyze documentation coverage
                doc_analysis = self._analyze_documentation_coverage(content, source_file)
                findings.extend(doc_analysis['findings'])
                
            except Exception as e:
                findings.append(Finding(
                    type="documentation_error",
                    severity=Severity.LOW,
                    file=os.path.basename(source_file),
                    line=0,
                    column=0,
                    message=f"Documentation analysis failed: {str(e)}",
                    recommendation="Check file format and accessibility"
                ))
        
        return findings
    
    def _analyze_documentation_coverage(self, content: str, source_file: str) -> Dict[str, Any]:
        """Analyze documentation coverage for functions and structures."""
        findings = []
        
        # Find all documentable items
        functions = self._find_functions_for_docs(content)
        structs = self._find_structs_for_docs(content)
        enums = self._find_enums_for_docs(content)
        defines = self._find_defines_for_docs(content)
        
        # Check documentation for functions
        for func_name, func_info in functions.items():
            if not self._has_documentation(content, func_info['start'], 'function') and not ["if", "for"].__contains__(func_name):
                findings.append(Finding(
                    type="missing_function_doc",
                    severity=Severity.MEDIUM,
                    file=os.path.basename(source_file),
                    line=func_info['line'],
                    column=0,
                    message=f"Function '{func_name}' lacks proper documentation",
                    recommendation="Add kernel-doc style documentation for this function"
                ))
        
        # Check documentation for structures
        for struct_name, struct_info in structs.items():
            if not self._has_documentation(content, struct_info['start'], 'struct'):
                findings.append(Finding(
                    type="missing_struct_doc",
                    severity=Severity.LOW,
                    file=os.path.basename(source_file),
                    line=struct_info['line'],
                    column=0,
                    message=f"Structure '{struct_name}' lacks proper documentation",
                    recommendation="Add kernel-doc style documentation for this structure"
                ))
        
        # Check documentation for enums
        for enum_name, enum_info in enums.items():
            if not self._has_documentation(content, enum_info['start'], 'enum'):
                findings.append(Finding(
                    type="missing_enum_doc",
                    severity=Severity.LOW,
                    file=os.path.basename(source_file),
                    line=enum_info['line'],
                    column=0,
                    message=f"Enum '{enum_name}' lacks proper documentation",
                    recommendation="Add kernel-doc style documentation for this enum"
                ))
        
        total_items = len(functions) + len(structs) + len(enums)
        documented_items = total_items - len([f for f in findings if 'missing_' in f.type])
        coverage = documented_items / total_items if total_items > 0 else 1.0
        
        if coverage < self.config.min_doc_coverage:
            findings.append(Finding(
                type="low_doc_coverage",
                severity=Severity.MEDIUM,
                file=os.path.basename(source_file),
                line=0,
                column=0,
                message=f"Documentation coverage is {coverage:.1%} (minimum: {self.config.min_doc_coverage:.1%})",
                recommendation="Add documentation for more functions and data structures"
            ))
        
        return {
            'findings': findings,
            'coverage': coverage,
            'total_items': total_items,
            'documented_items': documented_items
        }
    
    def _find_functions_for_docs(self, content: str) -> Dict[str, Dict[str, Any]]:
        """Find functions that should be documented."""
        functions = {}
        lines = content.split('\n')
        
        # Pattern for function definitions (excluding static inline functions)
        func_pattern = re.compile(
            r'^\s*(?!static\s+inline\s+)(?:static\s+)?(?:const\s+)?'
            r'(?:\w+\s+)*(\w+)\s*\([^)]*\)\s*{'
        )
        
        for i, line in enumerate(lines):
            match = func_pattern.match(line)
            if match:
                func_name = match.group(1)
                # Skip common small functions that don't need docs
                if func_name not in ['init', 'exit', 'probe', 'remove']:
                    functions[func_name] = {
                        'line': i + 1,
                        'start': content.find(line)
                    }
        
        return functions
    
    def _find_structs_for_docs(self, content: str) -> Dict[str, Dict[str, Any]]:
        """Find structures that should be documented."""
        structs = {}
        
        struct_pattern = re.compile(r'struct\s+(\w+)\s*{', re.MULTILINE)
        
        for match in struct_pattern.finditer(content):
            struct_name = match.group(1)
            line_num = content[:match.start()].count('\n') + 1
            
            structs[struct_name] = {
                'line': line_num,
                'start': match.start()
            }
        
        return structs
    
    def _find_enums_for_docs(self, content: str) -> Dict[str, Dict[str, Any]]:
        """Find enums that should be documented."""
        enums = {}
        
        enum_pattern = re.compile(r'enum\s+(\w+)\s*{', re.MULTILINE)
        
        for match in enum_pattern.finditer(content):
            enum_name = match.group(1)
            line_num = content[:match.start()].count('\n') + 1
            
            enums[enum_name] = {
                'line': line_num,
                'start': match.start()
            }
        
        return enums
    
    def _find_defines_for_docs(self, content: str) -> Dict[str, Dict[str, Any]]:
        """Find important defines that should be documented."""
        defines = {}
        
        # Only look for complex defines, not simple constants
        define_pattern = re.compile(r'#define\s+(\w+)\s*\([^)]*\)', re.MULTILINE)
        
        for match in define_pattern.finditer(content):
            define_name = match.group(1)
            line_num = content[:match.start()].count('\n') + 1
            
            defines[define_name] = {
                'line': line_num,
                'start': match.start()
            }
        
        return defines
    
    def _has_documentation(self, content: str, item_start: int, item_type: str) -> bool:
        """Check if an item has proper kernel-doc documentation."""
        # Look backwards from the item for kernel-doc comment
        before_item = content[:item_start]
        
        # Kernel-doc pattern: /** ... */
        doc_pattern = re.compile(r'/\*\*\s*\n(?:\s*\*[^\n]*\n)*\s*\*/', re.MULTILINE | re.DOTALL)
        
        # Find the last documentation comment before the item
        matches = list(doc_pattern.finditer(before_item))
        if not matches:
            return False
        
        last_doc = matches[-1]
        
        # Check if the documentation is close enough to the item (within 5 lines)
        lines_between = before_item[last_doc.end():].count('\n')
        
        return lines_between <= 5
    
    def _calculate_code_quality_score(self, findings: List[Finding], metrics: Dict[str, Any]) -> float:
        """Calculate code quality score based on findings and metrics."""
        if not findings:
            return 100.0
        
        # Start with perfect score
        score = 100.0
        
        # Deduct points based on severity
        severity_penalties = {
            Severity.CRITICAL: 20,
            Severity.HIGH: 10,
            Severity.MEDIUM: 5,
            Severity.LOW: 2,
            Severity.INFO: 1
        }
                
        for finding in findings:
            penalty = severity_penalties.get(finding.severity, 1)
            score -= penalty
        
        # Additional penalties for specific issues
        checkpatch_errors = len([f for f in findings if f.type.startswith('checkpatch_') and f.severity in [Severity.CRITICAL, Severity.HIGH]])
        complexity_issues = len([f for f in findings if f.type == 'high_complexity'])
        doc_issues = len([f for f in findings if 'doc' in f.type])
        
        # Extra penalties for systematic issues
        if checkpatch_errors > 10:
            score -= 10  # Many style violations
        if complexity_issues > 3:
            score -= 15  # Multiple complex functions
        if doc_issues > 5:
            score -= 10  # Poor documentation
        
        return max(0.0, score)
    
    def _calculate_code_quality_metrics(self, findings: List[Finding], source_files: List[str]) -> Dict[str, Any]:
        """Calculate additional code quality metrics."""
        metrics = {}
        
        # Count findings by type
        checkpatch_findings = [f for f in findings if f.type.startswith('checkpatch_')]
        complexity_findings = [f for f in findings if f.type == 'high_complexity']
        doc_findings = [f for f in findings if 'doc' in f.type]
        
        metrics.update({
            'total_findings': len(findings),
            'checkpatch_violations': len(checkpatch_findings),
            'complexity_violations': len(complexity_findings),
            'documentation_issues': len(doc_findings),
            'files_analyzed': len(source_files)
        })
        
        # Calculate severity distribution
        severity_counts = {}
        for severity in Severity:
            severity_counts[severity.value] = len([f for f in findings if f.severity == severity])
        
        metrics['severity_distribution'] = severity_counts
        
        return metrics