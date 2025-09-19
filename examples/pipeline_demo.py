#!/usr/bin/env python3
"""
Demo script showing how to use the static analysis pipeline and result aggregation.

This script demonstrates the basic usage of the pipeline orchestrator and
result aggregation system with mock analyzers.
"""

import sys
import os
import logging
from typing import Dict, List, Any

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.core.interfaces import BaseAnalyzer, AnalysisResult, AnalysisStatus, Finding, Severity
from src.analyzers.pipeline import StaticAnalysisPipeline, PipelineConfig
from src.analyzers.aggregator import StandardResultAggregator, AggregationConfig


class DemoCorrectnessAnalyzer(BaseAnalyzer):
    """Demo correctness analyzer."""
    
    @property
    def name(self) -> str:
        return "correctness_analyzer"
    
    @property
    def version(self) -> str:
        return "1.0.0"
    
    def analyze(self, source_files: List[str], config: Dict[str, Any]) -> AnalysisResult:
        findings = [
            Finding(
                type="null_pointer_dereference",
                severity=Severity.HIGH,
                file=source_files[0] if source_files else "driver.c",
                line=45,
                column=12,
                message="Potential null pointer dereference",
                recommendation="Add null check before dereferencing pointer"
            ),
            Finding(
                type="resource_leak",
                severity=Severity.MEDIUM,
                file=source_files[0] if source_files else "driver.c",
                line=78,
                column=8,
                message="Memory allocated but not freed",
                recommendation="Add kfree() call in error path"
            )
        ]
        
        return AnalysisResult(
            analyzer=self.name,
            status=AnalysisStatus.SUCCESS,
            findings=findings,
            metrics={"issues_found": len(findings), "lines_analyzed": 150},
            score=75.0
        )
    
    def validate_config(self, config: Dict[str, Any]) -> bool:
        return True


class DemoSecurityAnalyzer(BaseAnalyzer):
    """Demo security analyzer."""
    
    @property
    def name(self) -> str:
        return "security_analyzer"
    
    @property
    def version(self) -> str:
        return "1.0.0"
    
    def analyze(self, source_files: List[str], config: Dict[str, Any]) -> AnalysisResult:
        findings = [
            Finding(
                type="buffer_overflow",
                severity=Severity.CRITICAL,
                file=source_files[0] if source_files else "driver.c",
                line=32,
                column=15,
                message="Potential buffer overflow in strcpy call",
                recommendation="Use strncpy or strlcpy instead"
            ),
            Finding(
                type="race_condition",
                severity=Severity.HIGH,
                file=source_files[0] if source_files else "driver.c",
                line=45,  # Same line as correctness analyzer finding
                column=12,
                message="Race condition detected in shared resource access",
                recommendation="Add proper locking mechanism"
            )
        ]
        
        return AnalysisResult(
            analyzer=self.name,
            status=AnalysisStatus.SUCCESS,
            findings=findings,
            metrics={"security_issues": len(findings), "vulnerability_score": 8.5},
            score=60.0
        )
    
    def validate_config(self, config: Dict[str, Any]) -> bool:
        return True


class DemoCodeQualityAnalyzer(BaseAnalyzer):
    """Demo code quality analyzer."""
    
    @property
    def name(self) -> str:
        return "code_quality_analyzer"
    
    @property
    def version(self) -> str:
        return "1.0.0"
    
    def analyze(self, source_files: List[str], config: Dict[str, Any]) -> AnalysisResult:
        findings = [
            Finding(
                type="style_violation",
                severity=Severity.LOW,
                file=source_files[0] if source_files else "driver.c",
                line=12,
                column=1,
                message="Line exceeds 80 characters",
                recommendation="Break long line into multiple lines"
            ),
            Finding(
                type="complexity",
                severity=Severity.MEDIUM,
                file=source_files[0] if source_files else "driver.c",
                line=95,
                column=1,
                message="Function has high cyclomatic complexity (15)",
                recommendation="Consider breaking function into smaller functions"
            )
        ]
        
        return AnalysisResult(
            analyzer=self.name,
            status=AnalysisStatus.SUCCESS,
            findings=findings,
            metrics={"style_violations": 1, "complexity_score": 6.2},
            score=82.0
        )
    
    def validate_config(self, config: Dict[str, Any]) -> bool:
        return True


def setup_logging():
    """Set up logging for the demo."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )


def main():
    """Main demo function."""
    setup_logging()
    logger = logging.getLogger(__name__)
    
    print("=== Static Analysis Pipeline Demo ===\n")
    
    # Create pipeline with configuration
    pipeline_config = PipelineConfig(
        max_workers=3,
        enable_parallel=True,
        timeout_seconds=60
    )
    pipeline = StaticAnalysisPipeline(pipeline_config)
    
    # Register demo analyzers
    print("Registering analyzers...")
    pipeline.register_analyzer(DemoCorrectnessAnalyzer)
    pipeline.register_analyzer(DemoSecurityAnalyzer)
    pipeline.register_analyzer(DemoCodeQualityAnalyzer)
    
    # Show registered analyzers
    analyzer_info = pipeline.get_analyzer_info()
    print(f"Registered {len(analyzer_info)} analyzers:")
    for name, info in analyzer_info.items():
        print(f"  - {name} v{info['version']}")
    print()
    
    # Prepare analysis
    source_files = ["examples/test_driver.c"]  # Mock file path
    analyzer_configs = {
        "correctness_analyzer": {"strict_mode": True},
        "security_analyzer": {"check_all_vulnerabilities": True},
        "code_quality_analyzer": {"style_guide": "linux_kernel"}
    }
    
    # Run analysis
    print("Running analysis pipeline...")
    results = pipeline.run_analysis(source_files, analyzer_configs)
    
    print(f"Analysis completed with {len(results)} results\n")
    
    # Show individual results
    print("=== Individual Analyzer Results ===")
    for result in results:
        print(f"\nAnalyzer: {result.analyzer}")
        print(f"Status: {result.status.value}")
        print(f"Score: {result.score:.1f}")
        print(f"Findings: {len(result.findings)}")
        for finding in result.findings:
            print(f"  - {finding.severity.value.upper()}: {finding.message} "
                  f"({finding.file}:{finding.line})")
    
    # Aggregate results
    print("\n=== Result Aggregation ===")
    aggregator = StandardResultAggregator(AggregationConfig(
        enable_deduplication=True,
        merge_similar_findings=True
    ))
    
    aggregated = aggregator.aggregate(results)
    
    print(f"Total analyzers: {aggregated['total_analyzers']}")
    print(f"Successful analyzers: {aggregated['successful_analyzers']}")
    print(f"Total findings (after deduplication): {aggregated['total_findings']}")
    print(f"Files with issues: {aggregated['summary']['files_with_issues']}")
    
    # Show severity breakdown
    severity_counts = aggregated['summary']['severity_counts']
    print("\nSeverity breakdown:")
    for severity, count in severity_counts.items():
        print(f"  - {severity.upper()}: {count}")
    
    # Show most common issue type
    most_common = aggregated['summary']['most_common_issue_type']
    if most_common:
        print(f"\nMost common issue type: {most_common}")
    
    # Show aggregated findings
    print(f"\n=== Deduplicated Findings ({len(aggregated['findings'])}) ===")
    for i, finding in enumerate(aggregated['findings'], 1):
        print(f"{i}. {finding.severity.value.upper()}: {finding.message}")
        print(f"   Location: {finding.file}:{finding.line}:{finding.column}")
        print(f"   Recommendation: {finding.recommendation}")
        print()
    
    # Show execution metrics
    print("=== Execution Metrics ===")
    metrics = aggregated['metrics']
    print(f"Total execution time: {metrics['total_execution_time']:.2f}s")
    print("Individual analyzer times:")
    for analyzer, time in metrics['execution_times'].items():
        print(f"  - {analyzer}: {time:.2f}s")
    
    print("\n=== Demo Complete ===")


if __name__ == "__main__":
    main()