#!/usr/bin/env python3
"""
Demonstration of the scoring and grading system.

This example shows how to use the weighted scoring algorithm and results
aggregation engine to evaluate Linux driver code quality.
"""

import sys
import os

# Add the project root to Python path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

from src.analyzers.scoring import WeightedScoringSystem, ScoringWeights
from src.analyzers.aggregator import EvaluationResultsAggregator
from src.models.evaluation import (
    AnalysisResult, Finding, Severity, AnalysisStatus
)


def create_sample_analysis_results():
    """Create sample analysis results for demonstration."""
    
    # Compilation results - successful with warnings
    compilation_result = AnalysisResult(
        analyzer="compilation",
        status=AnalysisStatus.SUCCESS,
        findings=[
            Finding(
                type="warning",
                severity=Severity.LOW,
                file="driver.c",
                line=45,
                column=10,
                message="Unused variable 'temp'",
                recommendation="Remove unused variable or mark as __attribute__((unused))"
            )
        ],
        metrics={"warnings": 1, "errors": 0}
    )
    
    # Security analysis results - found vulnerabilities
    security_result = AnalysisResult(
        analyzer="security",
        status=AnalysisStatus.SUCCESS,
        findings=[
            Finding(
                type="buffer_overflow",
                severity=Severity.HIGH,
                file="driver.c",
                line=78,
                column=5,
                message="Potential buffer overflow in strcpy call",
                recommendation="Use strncpy or strlcpy instead of strcpy"
            ),
            Finding(
                type="race_condition",
                severity=Severity.MEDIUM,
                file="driver.c",
                line=120,
                column=8,
                message="Potential race condition in shared resource access",
                recommendation="Add proper locking mechanism"
            )
        ],
        metrics={"vulnerabilities": 2, "high_risk": 1}
    )
    
    # Code quality analysis results
    code_quality_result = AnalysisResult(
        analyzer="code_quality",
        status=AnalysisStatus.SUCCESS,
        findings=[
            Finding(
                type="style_violation",
                severity=Severity.LOW,
                file="driver.c",
                line=25,
                column=1,
                message="Line exceeds 80 characters",
                recommendation="Break long lines according to kernel coding style"
            ),
            Finding(
                type="complexity",
                severity=Severity.MEDIUM,
                file="driver.c",
                line=95,
                column=1,
                message="Function has high cyclomatic complexity (15)",
                recommendation="Consider breaking function into smaller functions"
            )
        ],
        metrics={"style_violations": 1, "complexity_issues": 1}
    )
    
    # Performance analysis results
    performance_result = AnalysisResult(
        analyzer="performance",
        status=AnalysisStatus.SUCCESS,
        findings=[
            Finding(
                type="inefficient_loop",
                severity=Severity.LOW,
                file="driver.c",
                line=150,
                column=5,
                message="Inefficient nested loop structure",
                recommendation="Consider optimizing algorithm complexity"
            )
        ],
        metrics={"performance_issues": 1}
    )
    
    # Advanced features analysis results
    advanced_features_result = AnalysisResult(
        analyzer="advanced_features",
        status=AnalysisStatus.SUCCESS,
        findings=[],  # No issues, good implementation
        metrics={
            "power_management": True,
            "device_tree_support": True,
            "interrupt_handling": "advanced"
        }
    )
    
    return [
        compilation_result,
        security_result,
        code_quality_result,
        performance_result,
        advanced_features_result
    ]


def demonstrate_scoring_system():
    """Demonstrate the scoring and grading system."""
    
    print("=== Linux Driver Evaluation Framework - Scoring System Demo ===\n")
    
    # Create sample analysis results
    results = create_sample_analysis_results()
    
    print("Sample Analysis Results:")
    for result in results:
        print(f"  {result.analyzer}: {len(result.findings)} findings, status: {result.status.value}")
    print()
    
    # Initialize scoring system with default weights
    scoring_system = WeightedScoringSystem()
    
    print("Scoring Weights:")
    for dimension, weight in scoring_system.weights.items():
        print(f"  {dimension}: {weight:.1%}")
    print()
    
    # Calculate dimension scores
    dimension_scores = scoring_system.get_dimension_scores(results)
    
    print("Dimension Scores:")
    for dimension, score in dimension_scores.to_dict().items():
        grade = scoring_system.assign_grade(score)
        print(f"  {dimension}: {score:.1f}/100 (Grade: {grade.value})")
    print()
    
    # Calculate overall score
    overall_score = scoring_system.calculate_score(results)
    overall_grade = scoring_system.assign_grade(overall_score)
    
    print(f"Overall Score: {overall_score:.1f}/100 (Grade: {overall_grade.value})")
    print()
    
    # Demonstrate results aggregation
    aggregator = EvaluationResultsAggregator(scoring_system)
    
    # Create comprehensive report
    report = aggregator.create_comprehensive_report("demo-eval-001", results)
    
    print("Evaluation Summary:")
    print(f"  Total Issues: {report.summary.total_issues}")
    print(f"  Critical Issues: {report.summary.critical_issues}")
    print(f"  Compilation Status: {'Success' if report.summary.compilation_status else 'Failed'}")
    print()
    
    print("Recommendations:")
    for i, recommendation in enumerate(report.recommendations, 1):
        print(f"  {i}. {recommendation}")
    print()
    
    # Show detailed breakdown
    breakdown = aggregator.get_detailed_breakdown(results)
    
    print("Detailed Breakdown:")
    print(f"  Conflicts Resolved: {breakdown['conflict_resolution_stats']['conflicts_resolved']}")
    print(f"  Original Findings: {breakdown['conflict_resolution_stats']['original_findings']}")
    print(f"  Final Findings: {breakdown['conflict_resolution_stats']['deduplicated_findings']}")
    print()
    
    print("Dimension Contributions to Overall Score:")
    for dimension, data in breakdown['dimension_breakdown'].items():
        contribution = data['contribution_to_overall']
        print(f"  {dimension}: {contribution:.1f} points (weight: {data['weight']:.1%})")
    print()


def demonstrate_custom_weights():
    """Demonstrate custom scoring weights."""
    
    print("=== Custom Scoring Weights Demo ===\n")
    
    # Create custom weights that prioritize security
    custom_weights = ScoringWeights(
        correctness=0.30,    # 30%
        security=0.40,       # 40% (increased)
        code_quality=0.15,   # 15%
        performance=0.10,    # 10%
        advanced_features=0.05  # 5%
    )
    
    custom_scoring_system = WeightedScoringSystem(custom_weights)
    results = create_sample_analysis_results()
    
    # Compare scores with different weights
    default_score = WeightedScoringSystem().calculate_score(results)
    custom_score = custom_scoring_system.calculate_score(results)
    
    print("Score Comparison:")
    print(f"  Default weights: {default_score:.1f}")
    print(f"  Security-focused weights: {custom_score:.1f}")
    print(f"  Difference: {custom_score - default_score:+.1f}")
    print()
    
    print("Custom Weights Impact:")
    print("  With higher security weight, the same code gets a lower score")
    print("  due to the security vulnerabilities found in the analysis.")


if __name__ == "__main__":
    demonstrate_scoring_system()
    print("\n" + "="*60 + "\n")
    demonstrate_custom_weights()