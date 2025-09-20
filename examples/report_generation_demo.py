#!/usr/bin/env python3
"""
Demonstration of the report generation system.

This script shows how to use the comprehensive report generation functionality
to create HTML, PDF, and JSON reports with detailed findings and recommendations.
"""

import os
import sys
from datetime import datetime

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.models.evaluation import (
    EvaluationReport, DimensionScores, EvaluationSummary, Finding, 
    Severity, Grade
)
from src.reports.generator import ReportGenerator
from src.reports.summary import SummaryGenerator


def create_sample_evaluation_report():
    """Create a comprehensive sample evaluation report for demonstration."""
    
    # Create sample findings with various severities and types
    findings = [
        Finding(
            type="Buffer Overflow",
            severity=Severity.CRITICAL,
            file="driver.c",
            line=45,
            column=12,
            message="Potential buffer overflow in strcpy call - user input copied without bounds checking",
            recommendation="Replace strcpy with strncpy or use snprintf for safe string copying. Validate input length before copying."
        ),
        Finding(
            type="Memory Leak",
            severity=Severity.HIGH,
            file="driver.c",
            line=78,
            column=8,
            message="Memory allocated with kmalloc() but not freed in error path",
            recommendation="Add kfree() call in error handling path to prevent memory leak"
        ),
        Finding(
            type="Race Condition",
            severity=Severity.HIGH,
            file="driver.c",
            line=156,
            column=4,
            message="Shared resource accessed without proper locking mechanism",
            recommendation="Use mutex or spinlock to protect shared data structure access"
        ),
        Finding(
            type="API Misuse",
            severity=Severity.MEDIUM,
            file="driver.c",
            line=203,
            column=15,
            message="Deprecated kernel API function used - may be removed in future versions",
            recommendation="Update to use the current recommended API function"
        ),
        Finding(
            type="Style Violation",
            severity=Severity.LOW,
            file="driver.c",
            line=23,
            column=1,
            message="Line exceeds 80 characters (current: 95 characters)",
            recommendation="Break long lines for better readability according to kernel coding style"
        ),
        Finding(
            type="Documentation",
            severity=Severity.LOW,
            file="driver.c",
            line=112,
            column=1,
            message="Function lacks proper documentation comment",
            recommendation="Add kernel-doc style comment describing function parameters and return value"
        ),
        Finding(
            type="Performance",
            severity=Severity.INFO,
            file="driver.c",
            line=89,
            column=8,
            message="Inefficient loop structure - O(n²) complexity detected",
            recommendation="Consider using more efficient algorithm or data structure to reduce complexity"
        )
    ]
    
    # Create dimension scores reflecting the issues found
    dimension_scores = DimensionScores(
        correctness=65.0,  # Lower due to buffer overflow and memory leak
        security=55.0,     # Lower due to critical security issues
        code_quality=72.0, # Decent but affected by style and documentation issues
        performance=68.0,   # Good but some optimization opportunities
        advanced_features=45.0  # Basic implementation without advanced features
    )
    
    # Create summary statistics
    summary = EvaluationSummary(
        total_issues=7,
        critical_issues=1,
        compilation_status=True  # Code compiles but has runtime issues
    )
    
    # Create comprehensive recommendations
    recommendations = [
        "Immediately fix the critical buffer overflow vulnerability in the strcpy call",
        "Implement proper memory management with matching kmalloc/kfree calls",
        "Add appropriate locking mechanisms to prevent race conditions",
        "Update deprecated API calls to current kernel standards",
        "Improve code documentation with kernel-doc style comments",
        "Consider performance optimizations for loop-heavy operations",
        "Implement advanced driver features like power management for better integration"
    ]
    
    # Calculate overall score (weighted average)
    overall_score = (
        dimension_scores.correctness * 0.40 +
        dimension_scores.security * 0.25 +
        dimension_scores.code_quality * 0.20 +
        dimension_scores.performance * 0.10 +
        dimension_scores.advanced_features * 0.05
    )
    
    # Determine grade based on overall score
    if overall_score >= 90:
        grade = Grade.A
    elif overall_score >= 80:
        grade = Grade.B
    elif overall_score >= 70:
        grade = Grade.C
    elif overall_score >= 60:
        grade = Grade.D
    else:
        grade = Grade.F
    
    return EvaluationReport(
        evaluation_id=f"demo-eval-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
        overall_score=overall_score,
        grade=grade,
        dimension_scores=dimension_scores,
        summary=summary,
        detailed_findings=findings,
        recommendations=recommendations
    )


def demonstrate_report_generation():
    """Demonstrate the complete report generation workflow."""
    
    print("🚀 Linux Driver Evaluation Framework - Report Generation Demo")
    print("=" * 60)
    
    # Create sample evaluation report
    print("\n📊 Creating sample evaluation report...")
    evaluation_report = create_sample_evaluation_report()
    
    print(f"   Evaluation ID: {evaluation_report.evaluation_id}")
    print(f"   Overall Score: {evaluation_report.overall_score:.1f}/100")
    print(f"   Grade: {evaluation_report.grade.value}")
    print(f"   Total Issues: {evaluation_report.summary.total_issues}")
    print(f"   Critical Issues: {evaluation_report.summary.critical_issues}")
    
    # Initialize report generator
    print("\n📝 Initializing report generator...")
    output_dir = "demo_reports"
    report_generator = ReportGenerator(output_dir=output_dir)
    
    # Generate comprehensive reports
    print("\n🔄 Generating comprehensive reports...")
    output_files = report_generator.generate_comprehensive_report(
        evaluation_report,
        formats=['html', 'json'],  # Skip PDF for demo (requires additional dependencies)
        include_executive_summary=True
    )
    
    print("   Generated reports:")
    for format_type, file_path in output_files.items():
        print(f"   📄 {format_type.upper()}: {file_path}")
    
    # Generate API response
    print("\n🌐 Generating API response format...")
    api_response = report_generator.generate_api_response(evaluation_report)
    
    print("   API Response Structure:")
    print(f"   - Status: {api_response['status']}")
    print(f"   - Evaluation ID: {api_response['data']['evaluation_id']}")
    print(f"   - Overall Score: {api_response['data']['overall_score']}")
    print(f"   - Grade: {api_response['data']['grade']}")
    print(f"   - Available Links: {len(api_response['links'])} endpoints")
    
    # Demonstrate executive summary
    print("\n👔 Generating executive summary...")
    summary_generator = SummaryGenerator()
    executive_summary = summary_generator.generate_executive_summary(evaluation_report)
    
    print("   Executive Summary Highlights:")
    print(f"   - Overall Assessment: {executive_summary['overall_assessment'][:100]}...")
    print(f"   - Key Strengths: {len(executive_summary['key_strengths'])} identified")
    print(f"   - Critical Issues: {len(executive_summary['critical_issues'])} identified")
    print(f"   - Risk Level: {executive_summary['risk_assessment']['level']}")
    print(f"   - Readiness Status: {executive_summary['readiness_status']}")
    print(f"   - Next Steps: {len(executive_summary['next_steps'])} recommended actions")
    
    # Show sample findings breakdown
    print("\n🔍 Findings Breakdown:")
    severity_counts = {}
    for finding in evaluation_report.detailed_findings:
        severity = finding.severity.value
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    
    for severity, count in severity_counts.items():
        print(f"   - {severity.title()}: {count} issues")
    
    # Show dimension scores
    print("\n📈 Dimension Scores:")
    scores = evaluation_report.dimension_scores
    print(f"   - Correctness: {scores.correctness:.1f}/100 (40% weight)")
    print(f"   - Security: {scores.security:.1f}/100 (25% weight)")
    print(f"   - Code Quality: {scores.code_quality:.1f}/100 (20% weight)")
    print(f"   - Performance: {scores.performance:.1f}/100 (10% weight)")
    print(f"   - Advanced Features: {scores.advanced_features:.1f}/100 (5% weight)")
    
    print(f"\n✅ Demo completed! Check the '{output_dir}' directory for generated reports.")
    print("\n💡 Key Features Demonstrated:")
    print("   ✓ Comprehensive HTML report with detailed findings")
    print("   ✓ JSON API response format for programmatic access")
    print("   ✓ Executive summary for high-level stakeholders")
    print("   ✓ Weighted scoring across multiple quality dimensions")
    print("   ✓ Detailed recommendations and improvement priorities")
    print("   ✓ Risk assessment and readiness evaluation")


if __name__ == "__main__":
    try:
        demonstrate_report_generation()
    except Exception as e:
        print(f"❌ Error during demonstration: {e}")
        sys.exit(1)