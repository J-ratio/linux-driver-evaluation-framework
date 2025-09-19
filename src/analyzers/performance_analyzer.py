"""
Performance analyzer for Linux kernel driver code.

This module provides comprehensive performance analysis by implementing:
- Algorithmic complexity analysis for driver functions
- Memory allocation pattern detection and scoring
- I/O efficiency analysis for device communication patterns
"""

import os
import re
import tempfile
import shutil
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

from src.core.interfaces import BaseAnalyzer, AnalysisResult, AnalysisStatus, Finding, Severity


class PerformanceCheckType(Enum):
    """Types of performance checks."""
    ALGORITHMIC_COMPLEXITY = "algorithmic_complexity"
    MEMORY_ALLOCATION = "memory_allocation"
    IO_EFFICIENCY = "io_efficiency"
    ALL = "all"


@dataclass
class PerformanceConfiguration:
    """Configuration for performance analysis."""
    check_types: List[PerformanceCheckType]
    timeout: int = 300
    max_complexity_threshold: int = 15
    memory_efficiency_threshold: float = 0.7
    io_efficiency_threshold: float = 0.6
    enable_detailed_analysis: bool = True
    
    def __post_init__(self):
        if not self.check_types:
            self.check_types = [
                PerformanceCheckType.ALGORITHMIC_COMPLEXITY,
                PerformanceCheckType.MEMORY_ALLOCATION,
                PerformanceCheckType.IO_EFFICIENCY
            ]


class PerformanceAnalyzer(BaseAnalyzer):
    """
    Comprehensive performance analyzer for Linux kernel driver code.
    
    This analyzer evaluates performance characteristics including:
    - Algorithmic complexity of driver functions
    - Memory allocation patterns and efficiency
    - I/O operation efficiency and optimization
    """
    
    COMPLEXITY_THRESHOLDS = {
        'excellent': 5,
        'good': 10,
        'acceptable': 15,
        'poor': 25,
        'critical': 50
    }
    
    def __init__(self, config: Optional[PerformanceConfiguration] = None):
        """Initialize the performance analyzer."""
        self.config = config or PerformanceConfiguration(
            check_types=[
                PerformanceCheckType.ALGORITHMIC_COMPLEXITY,
                PerformanceCheckType.MEMORY_ALLOCATION,
                PerformanceCheckType.IO_EFFICIENCY
            ]
        )
    
    @property
    def name(self) -> str:
        """Return the name of this analyzer."""
        return "performance_analyzer"
    
    @property
    def version(self) -> str:
        """Return the version of this analyzer."""
        return "1.0.0"  
  
    def analyze(self, source_files: List[str], config: Dict[str, Any]) -> AnalysisResult:
        """Analyze source files for performance issues."""
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
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
                            type="performance_error",
                            severity=Severity.CRITICAL,
                            file="",
                            line=0,
                            column=0,
                            message="No valid source files provided for performance analysis",
                            recommendation="Ensure source files exist and are accessible"
                        )],
                        metrics={"performance_attempted": False},
                        score=0.0
                    )
                
                findings, metrics = self._run_performance_analysis(temp_dir, temp_source_files)
                
                if not findings:
                    status = AnalysisStatus.SUCCESS
                elif any(f.severity == Severity.CRITICAL for f in findings):
                    status = AnalysisStatus.FAILURE
                else:
                    status = AnalysisStatus.WARNING
                
                score = self._calculate_performance_score(findings, metrics)
                
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
                    type="performance_error",
                    severity=Severity.CRITICAL,
                    file="",
                    line=0,
                    column=0,
                    message=f"Performance analysis failed: {str(e)}",
                    recommendation="Check system configuration and file accessibility"
                )],
                metrics={"performance_attempted": False, "error": str(e)},
                score=0.0
            )
    
    def validate_config(self, config: Dict[str, Any]) -> bool:
        """Validate the configuration for this analyzer."""
        try:
            if 'timeout' in config and not isinstance(config['timeout'], int):
                return False
            
            if 'max_complexity_threshold' in config:
                threshold = config['max_complexity_threshold']
                if not isinstance(threshold, int) or threshold < 1:
                    return False
            
            if 'memory_efficiency_threshold' in config:
                threshold = config['memory_efficiency_threshold']
                if not isinstance(threshold, (int, float)) or threshold < 0 or threshold > 1:
                    return False
            
            if 'io_efficiency_threshold' in config:
                threshold = config['io_efficiency_threshold']
                if not isinstance(threshold, (int, float)) or threshold < 0 or threshold > 1:
                    return False
            
            return True
        except Exception:
            return False    

    def _run_performance_analysis(self, temp_dir: str, source_files: List[str]) -> Tuple[List[Finding], Dict[str, Any]]:
        """Run comprehensive performance analysis."""
        all_findings = []
        metrics = {
            "performance_attempted": True,
            "check_types": [ct.value for ct in self.config.check_types],
            "total_checks": 0,
            "successful_checks": 0,
            "max_complexity_threshold": self.config.max_complexity_threshold,
            "memory_efficiency_threshold": self.config.memory_efficiency_threshold,
            "io_efficiency_threshold": self.config.io_efficiency_threshold
        }
        
        for check_type in self.config.check_types:
            if check_type == PerformanceCheckType.ALL:
                for ct in [PerformanceCheckType.ALGORITHMIC_COMPLEXITY, 
                          PerformanceCheckType.MEMORY_ALLOCATION, 
                          PerformanceCheckType.IO_EFFICIENCY]:
                    findings = self._run_performance_check(temp_dir, source_files, ct)
                    if findings is not None:
                        all_findings.extend(findings)
                        metrics["successful_checks"] += 1
                    metrics["total_checks"] += 1
            else:
                findings = self._run_performance_check(temp_dir, source_files, check_type)
                if findings is not None:
                    all_findings.extend(findings)
                    metrics["successful_checks"] += 1
                metrics["total_checks"] += 1
        
        metrics.update(self._calculate_performance_metrics(all_findings, source_files))
        return all_findings, metrics
    
    def _run_performance_check(self, temp_dir: str, source_files: List[str], check_type: PerformanceCheckType) -> List[Finding]:
        """Run a specific type of performance check."""
        try:
            if check_type == PerformanceCheckType.ALGORITHMIC_COMPLEXITY:
                return self._analyze_algorithmic_complexity(temp_dir, source_files)
            elif check_type == PerformanceCheckType.MEMORY_ALLOCATION:
                return self._analyze_memory_allocation_patterns(temp_dir, source_files)
            elif check_type == PerformanceCheckType.IO_EFFICIENCY:
                return self._analyze_io_efficiency(temp_dir, source_files)
            else:
                return []
        except Exception as e:
            return [Finding(
                type="performance_error",
                severity=Severity.MEDIUM,
                file="",
                line=0,
                column=0,
                message=f"Performance {check_type.value} analysis failed: {str(e)}",
                recommendation="Check file accessibility and system configuration"
            )]    

    def _analyze_algorithmic_complexity(self, temp_dir: str, source_files: List[str]) -> List[Finding]:
        """Analyze algorithmic complexity of driver functions."""
        findings = []
        
        for source_file in source_files:
            try:
                with open(source_file, 'r') as f:
                    content = f.read()
                
                functions = self._extract_functions_with_body(content)
                
                for func_name, func_info in functions.items():
                    complexity_score = self._calculate_algorithmic_complexity(func_info['body'])
                    
                    if complexity_score > self.config.max_complexity_threshold:
                        severity = self._get_complexity_severity(complexity_score)
                        
                        finding = Finding(
                            type="high_algorithmic_complexity",
                            severity=severity,
                            file=os.path.basename(source_file),
                            line=func_info['line'],
                            column=0,
                            message=f"Function '{func_name}' has high algorithmic complexity score: {complexity_score}",
                            recommendation=self._get_complexity_recommendation(complexity_score)
                        )
                        findings.append(finding)
                    
                    # Check for performance anti-patterns
                    anti_patterns = self._detect_performance_anti_patterns(func_info['body'], func_name)
                    for pattern_finding in anti_patterns:
                        pattern_finding.file = os.path.basename(source_file)
                        pattern_finding.line += func_info['line']
                        findings.append(pattern_finding)
                
            except Exception as e:
                findings.append(Finding(
                    type="complexity_analysis_error",
                    severity=Severity.LOW,
                    file=os.path.basename(source_file),
                    line=0,
                    column=0,
                    message=f"Algorithmic complexity analysis failed: {str(e)}",
                    recommendation="Check file format and accessibility"
                ))
        
        return findings
    
    def _analyze_memory_allocation_patterns(self, temp_dir: str, source_files: List[str]) -> List[Finding]:
        """Analyze memory allocation patterns and detect inefficiencies."""
        findings = []
        
        for source_file in source_files:
            try:
                with open(source_file, 'r') as f:
                    content = f.read()
                
                unsafe_findings = self._detect_unsafe_allocations(content, source_file)
                findings.extend(unsafe_findings)
                
                leak_findings = self._detect_memory_leaks(content, source_file)
                findings.extend(leak_findings)
                
            except Exception as e:
                findings.append(Finding(
                    type="memory_analysis_error",
                    severity=Severity.LOW,
                    file=os.path.basename(source_file),
                    line=0,
                    column=0,
                    message=f"Memory allocation analysis failed: {str(e)}",
                    recommendation="Check file format and accessibility"
                ))
        
        return findings
    
    def _analyze_io_efficiency(self, temp_dir: str, source_files: List[str]) -> List[Finding]:
        """Analyze I/O efficiency for device communication patterns."""
        findings = []
        
        for source_file in source_files:
            try:
                with open(source_file, 'r') as f:
                    content = f.read()
                
                io_findings = self._detect_io_inefficiencies(content, source_file)
                findings.extend(io_findings)
                
                dma_findings = self._analyze_dma_usage(content, source_file)
                findings.extend(dma_findings)
                
            except Exception as e:
                findings.append(Finding(
                    type="io_analysis_error",
                    severity=Severity.LOW,
                    file=os.path.basename(source_file),
                    line=0,
                    column=0,
                    message=f"I/O efficiency analysis failed: {str(e)}",
                    recommendation="Check file format and accessibility"
                ))
        
        return findings    

    def _extract_functions_with_body(self, content: str) -> Dict[str, Dict[str, Any]]:
        """Extract function definitions with their complete bodies."""
        functions = {}
        lines = content.split('\n')
        
        func_pattern = re.compile(
            r'^\s*(?:static\s+)?(?:inline\s+)?'
            r'(?:const\s+)?(?:\w+\s+)*(\w+)\s*\([^)]*\)\s*{'
        )
        
        i = 0
        while i < len(lines):
            match = func_pattern.match(lines[i])
            
            if match:
                func_name = match.group(1)
                start_line = i + 1
                
                brace_count = 1
                func_body = []
                i += 1
                
                while i < len(lines) and brace_count > 0:
                    line = lines[i]
                    func_body.append(line)
                    brace_count += line.count('{') - line.count('}')
                    i += 1
                
                functions[func_name] = {
                    'line': start_line,
                    'body': '\n'.join(func_body),
                    'length': len(func_body)
                }
            else:
                i += 1
        
        return functions
    
    def _calculate_algorithmic_complexity(self, func_body: str) -> int:
        """Calculate algorithmic complexity score for a function."""
        complexity_score = 1
        
        nested_loops = self._count_nested_loops(func_body)
        complexity_score += nested_loops * 10
        
        linear_patterns = [
            r'\bfor\s*\(',
            r'\bwhile\s*\(',
            r'\bdo\s*{',
            r'list_for_each',
            r'hash_for_each'
        ]
        
        for pattern in linear_patterns:
            matches = len(re.findall(pattern, func_body, re.IGNORECASE))
            complexity_score += matches * 2
        
        return complexity_score
    
    def _count_nested_loops(self, func_body: str) -> int:
        """Count nested loops in function body."""
        lines = func_body.split('\n')
        max_nesting = 0
        current_nesting = 0
        
        loop_patterns = [
            r'\bfor\s*\(',
            r'\bwhile\s*\(',
            r'\bdo\s*{'
        ]
        
        for line in lines:
            line = line.strip()
            
            for pattern in loop_patterns:
                if re.search(pattern, line):
                    current_nesting += 1
                    max_nesting = max(max_nesting, current_nesting)
                    break
            
            if '}' in line and current_nesting > 0:
                brace_count = line.count('}') - line.count('{')
                current_nesting = max(0, current_nesting - brace_count)
        
        return max_nesting
    
    def _get_complexity_severity(self, complexity_score: int) -> Severity:
        """Get severity level based on complexity score."""
        if complexity_score >= self.COMPLEXITY_THRESHOLDS['critical']:
            return Severity.CRITICAL
        elif complexity_score >= self.COMPLEXITY_THRESHOLDS['poor']:
            return Severity.HIGH
        elif complexity_score >= self.COMPLEXITY_THRESHOLDS['acceptable']:
            return Severity.MEDIUM
        else:
            return Severity.LOW
    
    def _get_complexity_recommendation(self, complexity_score: int) -> str:
        """Get recommendation based on complexity score."""
        if complexity_score >= 50:
            return "Critical complexity: Consider major refactoring, breaking into smaller functions, or using more efficient algorithms"
        elif complexity_score >= 25:
            return "High complexity: Consider refactoring to reduce nested loops and improve algorithm efficiency"
        elif complexity_score >= 15:
            return "Moderate complexity: Consider optimizing loops and reducing algorithmic complexity"
        else:
            return "Consider minor optimizations to improve performance"
    
    def _detect_performance_anti_patterns(self, func_body: str, func_name: str) -> List[Finding]:
        """Detect common performance anti-patterns."""
        findings = []
        lines = func_body.split('\n')
        
        # Anti-pattern: String operations in loops
        in_loop = False
        loop_depth = 0
        
        for i, line in enumerate(lines, 1):
            line_stripped = line.strip()
            
            # Track loop nesting
            if re.search(r'\b(for|while|do)\s*[\({]', line_stripped):
                in_loop = True
                loop_depth += 1
            elif '}' in line_stripped:
                loop_depth = max(0, loop_depth - 1)
                if loop_depth == 0:
                    in_loop = False
            
            if in_loop:
                # String operations in loops
                string_ops = [
                    r'strlen\s*\(',
                    r'strcmp\s*\(',
                    r'strcpy\s*\(',
                    r'strcat\s*\(',
                    r'sprintf\s*\('
                ]
                
                for pattern in string_ops:
                    if re.search(pattern, line_stripped):
                        findings.append(Finding(
                            type="string_operation_in_loop",
                            severity=Severity.MEDIUM,
                            file="",  # Will be set by caller
                            line=i,
                            column=0,
                            message=f"String operation in loop may cause performance degradation",
                            recommendation="Consider moving string operations outside loops or using more efficient alternatives"
                        ))
                
                # Memory allocation in loops
                alloc_patterns = [
                    r'kmalloc\s*\(',
                    r'kzalloc\s*\(',
                    r'vmalloc\s*\('
                ]
                
                for pattern in alloc_patterns:
                    if re.search(pattern, line_stripped):
                        findings.append(Finding(
                            type="allocation_in_loop",
                            severity=Severity.HIGH,
                            file="",  # Will be set by caller
                            line=i,
                            column=0,
                            message=f"Memory allocation in loop can cause performance issues",
                            recommendation="Consider pre-allocating memory outside the loop or using memory pools"
                        ))
        
        return findings   
 
    def _detect_unsafe_allocations(self, content: str, source_file: str) -> List[Finding]:
        """Detect unsafe memory allocation patterns."""
        findings = []
        lines = content.split('\n')
        
        for i, line in enumerate(lines, 1):
            line_stripped = line.strip()
            
            if re.search(r'kmalloc\s*\([^)]*\*[^)]*\)', line_stripped):
                findings.append(Finding(
                    type="unsafe_allocation_size",
                    severity=Severity.MEDIUM,
                    file=os.path.basename(source_file),
                    line=i,
                    column=0,
                    message="Multiplication in kmalloc size parameter may cause integer overflow",
                    recommendation="Use kmalloc_array() or check for overflow before multiplication"
                ))
            
            small_alloc_match = re.search(r'kmalloc\s*\(\s*(\d+)\s*[,)]', line_stripped)
            if small_alloc_match:
                size = int(small_alloc_match.group(1))
                if size <= 64:
                    findings.append(Finding(
                        type="small_heap_allocation",
                        severity=Severity.LOW,
                        file=os.path.basename(source_file),
                        line=i,
                        column=0,
                        message=f"Small allocation ({size} bytes) could use stack instead of heap",
                        recommendation="Consider using stack allocation for small, short-lived data"
                    ))
        
        return findings
    
    def _detect_memory_leaks(self, content: str, source_file: str) -> List[Finding]:
        """Detect potential memory leaks."""
        findings = []
        lines = content.split('\n')
        
        allocations = {}
        deallocations = set()
        
        alloc_patterns = [
            r'(\w+)\s*=\s*kmalloc\s*\(',
            r'(\w+)\s*=\s*kzalloc\s*\(',
            r'(\w+)\s*=\s*vmalloc\s*\('
        ]
        
        dealloc_patterns = [
            r'kfree\s*\(\s*(\w+)\s*\)',
            r'vfree\s*\(\s*(\w+)\s*\)'
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern in alloc_patterns:
                match = re.search(pattern, line)
                if match:
                    var_name = match.group(1)
                    allocations[var_name] = i
        
        for i, line in enumerate(lines, 1):
            for pattern in dealloc_patterns:
                matches = re.finditer(pattern, line)
                for match in matches:
                    var_name = match.group(1)
                    deallocations.add(var_name)
        
        for var_name, line_num in allocations.items():
            if var_name not in deallocations:
                findings.append(Finding(
                    type="potential_memory_leak",
                    severity=Severity.HIGH,
                    file=os.path.basename(source_file),
                    line=line_num,
                    column=0,
                    message=f"Variable '{var_name}' allocated but not freed",
                    recommendation="Ensure all allocated memory is properly freed to prevent memory leaks"
                ))
        
        return findings
    
    def _detect_io_inefficiencies(self, content: str, source_file: str) -> List[Finding]:
        """Detect I/O inefficiency patterns."""
        findings = []
        lines = content.split('\n')
        
        for i, line in enumerate(lines, 1):
            line_stripped = line.strip()
            
            delay_match = re.search(r'(?:udelay|mdelay)\s*\(\s*(\d+)\s*\)', line_stripped)
            if delay_match:
                delay_value = int(delay_match.group(1))
                delay_type = 'udelay' if 'udelay' in line_stripped else 'mdelay'
                
                if delay_type == 'udelay' and delay_value > 1000:
                    findings.append(Finding(
                        type="excessive_udelay",
                        severity=Severity.MEDIUM,
                        file=os.path.basename(source_file),
                        line=i,
                        column=0,
                        message=f"Excessive udelay({delay_value}) - consider using msleep() for delays > 1ms",
                        recommendation="Use msleep() for long delays to avoid busy waiting"
                    ))
                elif delay_type == 'mdelay' and delay_value > 10:
                    findings.append(Finding(
                        type="excessive_mdelay",
                        severity=Severity.HIGH,
                        file=os.path.basename(source_file),
                        line=i,
                        column=0,
                        message=f"Excessive mdelay({delay_value}) - busy waiting for {delay_value}ms",
                        recommendation="Use msleep() or other non-blocking alternatives for long delays"
                    ))
            
            if re.search(r'while\s*\([^)]*(?:readl|inb|ioread)', line_stripped):
                findings.append(Finding(
                    type="polling_loop",
                    severity=Severity.MEDIUM,
                    file=os.path.basename(source_file),
                    line=i,
                    column=0,
                    message="Polling loop detected - may waste CPU cycles",
                    recommendation="Consider using interrupts or more efficient polling with delays"
                ))
        
        return findings
    
    def _analyze_dma_usage(self, content: str, source_file: str) -> List[Finding]:
        """Analyze DMA usage patterns."""
        findings = []
        lines = content.split('\n')
        
        has_dma_alloc = False
        has_dma_free = False
        has_dma_map = False
        has_dma_unmap = False
        
        for i, line in enumerate(lines, 1):
            line_stripped = line.strip()
            
            if re.search(r'dma_alloc_coherent\s*\(', line_stripped):
                has_dma_alloc = True
            elif re.search(r'dma_free_coherent\s*\(', line_stripped):
                has_dma_free = True
            elif re.search(r'dma_map_single\s*\(', line_stripped):
                has_dma_map = True
            elif re.search(r'dma_unmap_single\s*\(', line_stripped):
                has_dma_unmap = True
            
            if re.search(r'dma_map_single\s*\([^)]+\)\s*(?![;,]\s*(?:if|&&|\|\|))', line_stripped):
                findings.append(Finding(
                    type="unchecked_dma_mapping",
                    severity=Severity.HIGH,
                    file=os.path.basename(source_file),
                    line=i,
                    column=0,
                    message="DMA mapping without error checking",
                    recommendation="Always check DMA mapping results with dma_mapping_error()"
                ))
        
        if has_dma_alloc and not has_dma_free:
            findings.append(Finding(
                type="dma_memory_leak",
                severity=Severity.HIGH,
                file=os.path.basename(source_file),
                line=0,
                column=0,
                message="DMA memory allocated but not freed",
                recommendation="Ensure all DMA allocations are properly freed with dma_free_coherent()"
            ))
        
        if has_dma_map and not has_dma_unmap:
            findings.append(Finding(
                type="dma_mapping_leak",
                severity=Severity.HIGH,
                file=os.path.basename(source_file),
                line=0,
                column=0,
                message="DMA mapping created but not unmapped",
                recommendation="Ensure all DMA mappings are properly unmapped with dma_unmap_single()"
            ))
        
        return findings    
    def _calculate_performance_metrics(self, findings: List[Finding], source_files: List[str]) -> Dict[str, Any]:
        """Calculate additional performance metrics."""
        metrics = {}
        
        finding_types = {}
        severity_counts = {severity.value: 0 for severity in Severity}
        
        for finding in findings:
            finding_type = finding.type
            finding_types[finding_type] = finding_types.get(finding_type, 0) + 1
            severity_counts[finding.severity.value] += 1
        
        metrics.update({
            'total_findings': len(findings),
            'finding_types': finding_types,
            'severity_distribution': severity_counts,
            'files_analyzed': len(source_files)
        })
        
        complexity_findings = [f for f in findings if 'complexity' in f.type]
        memory_findings = [f for f in findings if 'memory' in f.type or 'allocation' in f.type]
        io_findings = [f for f in findings if 'io' in f.type or 'dma' in f.type or 'delay' in f.type]
        
        metrics.update({
            'complexity_issues': len(complexity_findings),
            'memory_issues': len(memory_findings),
            'io_issues': len(io_findings)
        })
        
        return metrics
    
    def _calculate_performance_score(self, findings: List[Finding], metrics: Dict[str, Any]) -> float:
        """Calculate overall performance score based on findings and metrics."""
        if not findings:
            return 100.0
        
        score = 100.0
        
        severity_penalties = {
            Severity.CRITICAL: 25,
            Severity.HIGH: 15,
            Severity.MEDIUM: 8,
            Severity.LOW: 3,
            Severity.INFO: 1
        }
        
        for finding in findings:
            penalty = severity_penalties.get(finding.severity, 5)
            score -= penalty
        
        complexity_issues = metrics.get('complexity_issues', 0)
        memory_issues = metrics.get('memory_issues', 0)
        io_issues = metrics.get('io_issues', 0)
        
        if complexity_issues > 3:
            score -= (complexity_issues - 3) * 2
        if memory_issues > 3:
            score -= (memory_issues - 3) * 2
        if io_issues > 3:
            score -= (io_issues - 3) * 2
        
        return max(0.0, score)