"""
Summary generation for executive-level reporting.

This module provides functionality to generate executive summaries and
high-level insights from detailed evaluation reports.
"""

from typing import Dict, Any, List
from ..models.evaluation import EvaluationReport, Finding, Severity, Grade


class SummaryGenerator:
    """Generates executive summaries and high-level insights from evaluation reports."""
    
    def generate_executive_summary(self, evaluation_report: EvaluationReport) -> Dict[str, Any]:
        """
        Generate executive summary for high-level stakeholders.
        
        Args:
            evaluation_report: The detailed evaluation report
            
        Returns:
            Executive summary dictionary with key insights
        """
        # Analyze the report to extract key insights
        overall_assessment = self._generate_overall_assessment(evaluation_report)
        key_strengths = self._identify_key_strengths(evaluation_report)
        critical_issues = self._identify_critical_issues(evaluation_report)
        business_impact = self._assess_business_impact(evaluation_report)
        recommendation = self._generate_executive_recommendation(evaluation_report)
        risk_assessment = self._assess_risk_level(evaluation_report)
        
        return {
            'overall_assessment': overall_assessment,
            'key_strengths': key_strengths,
            'critical_issues': critical_issues,
            'business_impact': business_impact,
            'recommendation': recommendation,
            'risk_assessment': risk_assessment,
            'readiness_status': self._determine_readiness_status(evaluation_report),
            'next_steps': self._suggest_next_steps(evaluation_report)
        }
    
    def _generate_overall_assessment(self, report: EvaluationReport) -> str:
        """Generate overall assessment text."""
        score = report.overall_score
        grade = report.grade
        
        if grade == Grade.A:
            return f"The driver code demonstrates excellent quality with a score of {score:.1f}/100. " \
                   f"The implementation follows best practices and is ready for production deployment."
        
        elif grade == Grade.B:
            return f"The driver code shows good quality with a score of {score:.1f}/100. " \
                   f"Minor improvements are recommended before production deployment."
        
        elif grade == Grade.C:
            return f"The driver code has acceptable quality with a score of {score:.1f}/100. " \
                   f"Several issues need to be addressed to meet production standards."
        
        elif grade == Grade.D:
            return f"The driver code shows poor quality with a score of {score:.1f}/100. " \
                   f"Significant improvements are required before considering production use."
        
        else:  # Grade F
            return f"The driver code fails quality standards with a score of {score:.1f}/100. " \
                   f"Critical issues must be resolved before any deployment consideration."
    
    def _identify_key_strengths(self, report: EvaluationReport) -> List[str]:
        """Identify key strengths in the code."""
        strengths = []
        scores = report.dimension_scores
        
        if scores.correctness >= 80:
            strengths.append("Strong correctness with proper API usage and minimal compilation issues")
        
        if scores.security >= 80:
            strengths.append("Robust security implementation with proper input validation and memory management")
        
        if scores.code_quality >= 80:
            strengths.append("High code quality with good documentation and adherence to coding standards")
        
        if scores.performance >= 80:
            strengths.append("Efficient performance with optimized algorithms and resource usage")
        
        if scores.advanced_features >= 70:
            strengths.append("Implementation of advanced driver features like power management and device tree support")
        
        if report.summary.compilation_status:
            strengths.append("Code compiles successfully without errors")
        
        if report.summary.critical_issues == 0:
            strengths.append("No critical security or correctness issues identified")
        
        # If no specific strengths found, provide general positive feedback
        if not strengths and report.overall_score >= 60:
            strengths.append("Code demonstrates basic functionality and structure")
        
        return strengths
    
    def _identify_critical_issues(self, report: EvaluationReport) -> List[str]:
        """Identify critical issues that need immediate attention."""
        critical_issues = []
        
        # Check for critical findings
        critical_findings = [f for f in report.detailed_findings if f.severity == Severity.CRITICAL]
        if critical_findings:
            issue_types = set(f.type for f in critical_findings)
            for issue_type in issue_types:
                critical_issues.append(f"Critical {issue_type.lower()} issues requiring immediate attention")
        
        # Check compilation status
        if not report.summary.compilation_status:
            critical_issues.append("Code fails to compile, preventing basic functionality")
        
        # Check dimension scores for critical failures
        scores = report.dimension_scores
        
        if scores.correctness < 50:
            critical_issues.append("Severe correctness issues affecting basic driver functionality")
        
        if scores.security < 50:
            critical_issues.append("Critical security vulnerabilities posing significant risk")
        
        if scores.code_quality < 30:
            critical_issues.append("Poor code quality making maintenance and debugging difficult")
        
        return critical_issues
    
    def _assess_business_impact(self, report: EvaluationReport) -> Dict[str, str]:
        """Assess business impact of the code quality."""
        score = report.overall_score
        
        if score >= 80:
            return {
                'deployment_risk': 'Low',
                'maintenance_cost': 'Low',
                'time_to_market': 'Ready for deployment',
                'customer_impact': 'Positive - reliable and secure driver'
            }
        elif score >= 60:
            return {
                'deployment_risk': 'Medium',
                'maintenance_cost': 'Medium',
                'time_to_market': '1-2 weeks for improvements',
                'customer_impact': 'Neutral - functional but may need updates'
            }
        elif score >= 40:
            return {
                'deployment_risk': 'High',
                'maintenance_cost': 'High',
                'time_to_market': '2-4 weeks for significant improvements',
                'customer_impact': 'Negative - potential reliability issues'
            }
        else:
            return {
                'deployment_risk': 'Critical',
                'maintenance_cost': 'Very High',
                'time_to_market': '4+ weeks for major rework',
                'customer_impact': 'Severe - likely to cause system instability'
            }
    
    def _generate_executive_recommendation(self, report: EvaluationReport) -> str:
        """Generate executive-level recommendation."""
        score = report.overall_score
        critical_issues = report.summary.critical_issues
        
        if score >= 85 and critical_issues == 0:
            return "Approve for production deployment with standard testing procedures."
        
        elif score >= 70 and critical_issues <= 2:
            return "Approve for deployment after addressing identified issues and conducting additional testing."
        
        elif score >= 50:
            return "Require significant improvements before deployment. Consider code review and refactoring."
        
        else:
            return "Do not deploy. Requires major rework or complete reimplementation."
    
    def _assess_risk_level(self, report: EvaluationReport) -> Dict[str, str]:
        """Assess overall risk level."""
        critical_count = len([f for f in report.detailed_findings if f.severity == Severity.CRITICAL])
        high_count = len([f for f in report.detailed_findings if f.severity == Severity.HIGH])
        
        if critical_count > 0:
            risk_level = 'Critical'
            risk_description = f'{critical_count} critical issues pose immediate security or stability risks'
        elif high_count > 5:
            risk_level = 'High'
            risk_description = f'{high_count} high-severity issues may impact system reliability'
        elif high_count > 0:
            risk_level = 'Medium'
            risk_description = f'{high_count} high-severity issues should be addressed'
        elif report.overall_score < 60:
            risk_level = 'Medium'
            risk_description = 'Overall quality score indicates potential reliability concerns'
        else:
            risk_level = 'Low'
            risk_description = 'Code quality meets acceptable standards with minimal risk'
        
        return {
            'level': risk_level,
            'description': risk_description
        }
    
    def _determine_readiness_status(self, report: EvaluationReport) -> str:
        """Determine production readiness status."""
        score = report.overall_score
        critical_issues = report.summary.critical_issues
        compilation_status = report.summary.compilation_status
        
        if not compilation_status:
            return "Not Ready - Compilation Failures"
        elif critical_issues > 0:
            return "Not Ready - Critical Issues"
        elif score >= 80:
            return "Production Ready"
        elif score >= 70:
            return "Ready with Minor Fixes"
        elif score >= 50:
            return "Needs Improvement"
        else:
            return "Major Rework Required"
    
    def _suggest_next_steps(self, report: EvaluationReport) -> List[str]:
        """Suggest concrete next steps based on the evaluation."""
        next_steps = []
        scores = report.dimension_scores
        
        # Prioritize steps based on severity and impact
        if not report.summary.compilation_status:
            next_steps.append("1. Fix compilation errors to enable basic functionality")
        
        if report.summary.critical_issues > 0:
            next_steps.append("2. Address all critical security and correctness issues")
        
        # Add dimension-specific steps
        if scores.correctness < 70:
            next_steps.append("3. Review and fix API usage and semantic errors")
        
        if scores.security < 70:
            next_steps.append("4. Implement proper input validation and memory management")
        
        if scores.code_quality < 70:
            next_steps.append("5. Improve code documentation and style compliance")
        
        if scores.performance < 60:
            next_steps.append("6. Optimize algorithms and resource usage patterns")
        
        # Add general steps
        if len(next_steps) == 0:
            next_steps.append("1. Conduct final testing and validation")
            next_steps.append("2. Prepare for production deployment")
        else:
            next_steps.append(f"{len(next_steps) + 1}. Re-run evaluation after fixes")
            next_steps.append(f"{len(next_steps) + 2}. Conduct peer code review")
        
        return next_steps