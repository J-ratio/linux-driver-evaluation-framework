"""
Main report generator for the Linux Driver Evaluation Framework.

This module orchestrates the generation of comprehensive evaluation reports
in multiple formats (HTML, PDF, JSON) with detailed findings and recommendations.
"""

import os
import json
from typing import Dict, Any, Optional, List
from datetime import datetime
from pathlib import Path

from ..models.evaluation import EvaluationReport, Finding, Grade
from ..core.interfaces import Severity
from .templates import HTMLTemplate, PDFTemplate, JSONTemplate
from .summary import SummaryGenerator


class ReportGenerator:
    """Main report generator that coordinates template rendering and output generation."""
    
    def __init__(self, output_dir: str = "reports"):
        """
        Initialize the report generator.
        
        Args:
            output_dir: Directory to save generated reports
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        self.html_template = HTMLTemplate()
        self.pdf_template = PDFTemplate()
        self.json_template = JSONTemplate()
        self.summary_generator = SummaryGenerator()
    
    def generate_comprehensive_report(
        self, 
        evaluation_report: EvaluationReport,
        formats: List[str] = None,
        include_executive_summary: bool = True
    ) -> Dict[str, str]:
        """
        Generate comprehensive evaluation report in multiple formats.
        
        Args:
            evaluation_report: The evaluation report data
            formats: List of formats to generate ('html', 'pdf', 'json')
            include_executive_summary: Whether to include executive summary
            
        Returns:
            Dictionary mapping format names to output file paths
        """
        if formats is None:
            formats = ['html', 'pdf', 'json']
        
        # Generate executive summary if requested
        executive_summary = None
        if include_executive_summary:
            executive_summary = self.summary_generator.generate_executive_summary(
                evaluation_report
            )
        
        # Prepare enhanced report data
        enhanced_data = self._prepare_report_data(evaluation_report, executive_summary)
        
        output_files = {}
        
        # Generate each requested format
        for format_type in formats:
            if format_type.lower() == 'html':
                output_files['html'] = self._generate_html_report(enhanced_data)
            elif format_type.lower() == 'pdf':
                output_files['pdf'] = self._generate_pdf_report(enhanced_data)
            elif format_type.lower() == 'json':
                output_files['json'] = self._generate_json_report(enhanced_data)
        
        return output_files
    
    def generate_api_response(self, evaluation_report: EvaluationReport) -> Dict[str, Any]:
        """
        Generate JSON API response format for programmatic access.
        
        Args:
            evaluation_report: The evaluation report data
            
        Returns:
            Dictionary formatted for API response
        """
        return self.json_template.format_api_response(evaluation_report)
    
    def _prepare_report_data(
        self, 
        evaluation_report: EvaluationReport, 
        executive_summary: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Prepare enhanced report data with additional metadata and formatting.
        
        Args:
            evaluation_report: The evaluation report data
            executive_summary: Optional executive summary data
            
        Returns:
            Enhanced report data dictionary
        """
        # Group findings by severity and type
        findings_by_severity = self._group_findings_by_severity(
            evaluation_report.detailed_findings
        )
        findings_by_type = self._group_findings_by_type(
            evaluation_report.detailed_findings
        )
        
        # Calculate additional metrics
        metrics = self._calculate_additional_metrics(evaluation_report)
        
        # Prepare the enhanced data structure
        enhanced_data = {
            'report': evaluation_report,
            'executive_summary': executive_summary,
            'findings_by_severity': findings_by_severity,
            'findings_by_type': findings_by_type,
            'metrics': metrics,
            'generation_timestamp': datetime.now().isoformat(),
            'grade_description': self._get_grade_description(evaluation_report.grade),
            'improvement_priority': self._get_improvement_priority(evaluation_report)
        }
        
        return enhanced_data
    
    def _generate_html_report(self, enhanced_data: Dict[str, Any]) -> str:
        """Generate HTML report and save to file."""
        html_content = self.html_template.render(enhanced_data)
        
        filename = f"evaluation_report_{enhanced_data['report'].evaluation_id}.html"
        output_path = self.output_dir / filename
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return str(output_path)
    
    def _generate_pdf_report(self, enhanced_data: Dict[str, Any]) -> str:
        """Generate PDF report and save to file."""
        pdf_content = self.pdf_template.render(enhanced_data)
        
        filename = f"evaluation_report_{enhanced_data['report'].evaluation_id}.pdf"
        output_path = self.output_dir / filename
        
        with open(output_path, 'wb') as f:
            f.write(pdf_content)
        
        return str(output_path)
    
    def _generate_json_report(self, enhanced_data: Dict[str, Any]) -> str:
        """Generate JSON report and save to file."""
        json_content = self.json_template.render(enhanced_data)
        
        filename = f"evaluation_report_{enhanced_data['report'].evaluation_id}.json"
        output_path = self.output_dir / filename
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(json_content, f, indent=2, ensure_ascii=False)
        
        return str(output_path)
    
    def _group_findings_by_severity(self, findings: List[Finding]) -> Dict[str, List[Finding]]:
        """Group findings by severity level."""
        grouped = {severity.value: [] for severity in Severity}
        
        for finding in findings:
            grouped[finding.severity.value].append(finding)
        
        return grouped
    
    def _group_findings_by_type(self, findings: List[Finding]) -> Dict[str, List[Finding]]:
        """Group findings by type."""
        grouped = {}
        
        for finding in findings:
            if finding.type not in grouped:
                grouped[finding.type] = []
            grouped[finding.type].append(finding)
        
        return grouped
    
    def _calculate_additional_metrics(self, report: EvaluationReport) -> Dict[str, Any]:
        """Calculate additional metrics for the report."""
        findings = report.detailed_findings
        
        return {
            'total_files_analyzed': len(set(f.file for f in findings)),
            'avg_issues_per_file': len(findings) / max(len(set(f.file for f in findings)), 1),
            'severity_distribution': {
                severity.value: len([f for f in findings if f.severity == severity])
                for severity in Severity
            },
            'top_issue_types': self._get_top_issue_types(findings, limit=5),
            'files_with_most_issues': self._get_files_with_most_issues(findings, limit=5)
        }
    
    def _get_top_issue_types(self, findings: List[Finding], limit: int = 5) -> List[Dict[str, Any]]:
        """Get the most common issue types."""
        type_counts = {}
        for finding in findings:
            type_counts[finding.type] = type_counts.get(finding.type, 0) + 1
        
        sorted_types = sorted(type_counts.items(), key=lambda x: x[1], reverse=True)
        
        return [
            {'type': issue_type, 'count': count}
            for issue_type, count in sorted_types[:limit]
        ]
    
    def _get_files_with_most_issues(self, findings: List[Finding], limit: int = 5) -> List[Dict[str, Any]]:
        """Get files with the most issues."""
        file_counts = {}
        for finding in findings:
            file_counts[finding.file] = file_counts.get(finding.file, 0) + 1
        
        sorted_files = sorted(file_counts.items(), key=lambda x: x[1], reverse=True)
        
        return [
            {'file': filename, 'count': count}
            for filename, count in sorted_files[:limit]
        ]
    
    def _get_grade_description(self, grade: Grade) -> str:
        """Get descriptive text for the grade."""
        descriptions = {
            Grade.A: "Excellent - Production ready with minimal issues",
            Grade.B: "Good - Minor issues that should be addressed",
            Grade.C: "Acceptable - Several issues requiring attention",
            Grade.D: "Poor - Significant issues that must be fixed",
            Grade.F: "Failing - Critical issues preventing production use"
        }
        return descriptions.get(grade, "Unknown grade")
    
    def _get_improvement_priority(self, report: EvaluationReport) -> List[str]:
        """Get prioritized list of improvement areas."""
        priorities = []
        
        # Check dimension scores to identify areas needing improvement
        scores = report.dimension_scores
        
        if scores.correctness < 70:
            priorities.append("Correctness - Address compilation errors and API misuse")
        
        if scores.security < 70:
            priorities.append("Security - Fix buffer overflows and race conditions")
        
        if scores.code_quality < 70:
            priorities.append("Code Quality - Improve coding style and documentation")
        
        if scores.performance < 70:
            priorities.append("Performance - Optimize algorithms and memory usage")
        
        if scores.advanced_features < 50:
            priorities.append("Advanced Features - Implement power management and device tree support")
        
        return priorities