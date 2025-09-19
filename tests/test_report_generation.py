"""
Tests for the report generation system.

This module tests the comprehensive report generation functionality including
HTML, PDF, and JSON formats with detailed findings and recommendations.
"""

import pytest
import json
import tempfile
import os
from datetime import datetime
from pathlib import Path

from src.models.evaluation import (
    EvaluationReport, DimensionScores, EvaluationSummary, Finding, 
    Severity, Grade
)
from src.reports.generator import ReportGenerator
from src.reports.templates import HTMLTemplate, JSONTemplate
from src.reports.summary import SummaryGenerator


class TestReportGenerator:
    """Test cases for the ReportGenerator class."""
    
    @pytest.fixture
    def sample_evaluation_report(self):
        """Create a sample evaluation report for testing."""
        findings = [
            Finding(
                type="Buffer Overflow",
                severity=Severity.CRITICAL,
                file="driver.c",
                line=45,
                column=12,
                message="Potential buffer overflow in strcpy call",
                recommendation="Use strncpy or snprintf for safe string copying"
            ),
            Finding(
                type="Memory Leak",
                severity=Severity.HIGH,
                file="driver.c",
                line=78,
                column=8,
                message="Memory allocated but not freed",
                recommendation="Add kfree() call in error path"
            ),
            Finding(
                type="Style Violation",
                severity=Severity.LOW,
                file="driver.c",
                line=23,
                column=1,
                message="Line exceeds 80 characters",
                recommendation="Break long lines for better readability"
            )
        ]
        
        dimension_scores = DimensionScores(
            correctness=75.0,
            security=60.0,
            code_quality=80.0,
            performance=70.0,
            advanced_features=45.0
        )
        
        summary = EvaluationSummary(
            total_issues=3,
            critical_issues=1,
            compilation_status=True
        )
        
        return EvaluationReport(
            evaluation_id="test-eval-001",
            overall_score=68.5,
            grade=Grade.C,
            dimension_scores=dimension_scores,
            summary=summary,
            detailed_findings=findings,
            recommendations=[
                "Fix critical buffer overflow vulnerability",
                "Implement proper memory management",
                "Improve code style compliance"
            ]
        )
    
    @pytest.fixture
    def report_generator(self):
        """Create a ReportGenerator instance with temporary output directory."""
        with tempfile.TemporaryDirectory() as temp_dir:
            yield ReportGenerator(output_dir=temp_dir)
    
    def test_generate_comprehensive_report(self, report_generator, sample_evaluation_report):
        """Test comprehensive report generation in multiple formats."""
        output_files = report_generator.generate_comprehensive_report(
            sample_evaluation_report,
            formats=['html', 'json']
        )
        
        assert 'html' in output_files
        assert 'json' in output_files
        
        # Verify files were created
        assert os.path.exists(output_files['html'])
        assert os.path.exists(output_files['json'])
        
        # Verify HTML content
        with open(output_files['html'], 'r', encoding='utf-8') as f:
            html_content = f.read()
            assert 'Linux Driver Evaluation Report' in html_content
            assert 'test-eval-001' in html_content
            assert 'Buffer Overflow' in html_content
            assert '68.5' in html_content
    
    def test_generate_api_response(self, report_generator, sample_evaluation_report):
        """Test API response format generation."""
        api_response = report_generator.generate_api_response(sample_evaluation_report)
        
        assert api_response['status'] == 'success'
        assert api_response['data']['evaluation_id'] == 'test-eval-001'
        assert api_response['data']['overall_score'] == 68.5
        assert api_response['data']['grade'] == 'C'
        assert 'links' in api_response
        assert 'timestamp' in api_response
    
    def test_report_data_preparation(self, report_generator, sample_evaluation_report):
        """Test report data preparation and enhancement."""
        enhanced_data = report_generator._prepare_report_data(sample_evaluation_report)
        
        assert 'report' in enhanced_data
        assert 'findings_by_severity' in enhanced_data
        assert 'findings_by_type' in enhanced_data
        assert 'metrics' in enhanced_data
        assert 'generation_timestamp' in enhanced_data
        assert 'grade_description' in enhanced_data
        
        # Check findings grouping
        assert 'critical' in enhanced_data['findings_by_severity']
        assert len(enhanced_data['findings_by_severity']['critical']) == 1
        
        # Check metrics calculation
        metrics = enhanced_data['metrics']
        assert 'total_files_analyzed' in metrics
        assert 'severity_distribution' in metrics
        assert 'top_issue_types' in metrics


class TestHTMLTemplate:
    """Test cases for the HTMLTemplate class."""
    
    @pytest.fixture
    def html_template(self):
        """Create an HTMLTemplate instance."""
        return HTMLTemplate()
    
    @pytest.fixture
    def sample_data(self):
        """Create sample data for template rendering."""
        report = EvaluationReport(
            evaluation_id="test-001",
            overall_score=85.0,
            grade=Grade.B,
            dimension_scores=DimensionScores(80, 85, 90, 75, 60),
            summary=EvaluationSummary(2, 0, True),
            detailed_findings=[],
            recommendations=["Test recommendation"]
        )
        
        return {
            'report': report,
            'generation_timestamp': datetime.now().isoformat(),
            'findings_by_severity': {'critical': [], 'high': [], 'medium': [], 'low': [], 'info': []},
            'metrics': {'total_files_analyzed': 1, 'avg_issues_per_file': 2.0},
            'grade_description': 'Good quality code'
        }
    
    def test_html_template_render(self, html_template, sample_data):
        """Test HTML template rendering."""
        html_content = html_template.render(sample_data)
        
        assert '<!DOCTYPE html>' in html_content
        assert 'Linux Driver Evaluation Report' in html_content
        assert 'test-001' in html_content
        assert '85.0' in html_content
        assert 'Grade B' in html_content or 'grade-b' in html_content
    
    def test_html_template_css_styles(self, html_template):
        """Test CSS styles generation."""
        css_styles = html_template._get_css_styles()
        
        assert 'body {' in css_styles
        assert '.grade-a' in css_styles
        assert '.severity-critical' in css_styles
        assert 'font-family' in css_styles


class TestJSONTemplate:
    """Test cases for the JSONTemplate class."""
    
    @pytest.fixture
    def json_template(self):
        """Create a JSONTemplate instance."""
        return JSONTemplate()
    
    @pytest.fixture
    def sample_report(self):
        """Create a sample evaluation report."""
        return EvaluationReport(
            evaluation_id="json-test-001",
            overall_score=72.5,
            grade=Grade.B,
            dimension_scores=DimensionScores(70, 75, 80, 65, 55),
            summary=EvaluationSummary(5, 1, True),
            detailed_findings=[
                Finding("Test Issue", Severity.MEDIUM, "test.c", 10, 5, "Test message", "Test recommendation")
            ],
            recommendations=["Fix test issues"]
        )
    
    def test_json_template_render(self, json_template, sample_report):
        """Test JSON template rendering."""
        data = {
            'report': sample_report,
            'generation_timestamp': datetime.now().isoformat(),
            'findings_by_severity': {'medium': [sample_report.detailed_findings[0]]},
            'findings_by_type': {'Test Issue': [sample_report.detailed_findings[0]]},
            'metrics': {'total_files_analyzed': 1}
        }
        
        json_content = json_template.render(data)
        
        assert json_content['evaluation_id'] == 'json-test-001'
        assert json_content['overall_score'] == 72.5
        assert json_content['grade'] == 'B'
        assert 'dimension_scores' in json_content
        assert 'detailed_findings' in json_content
        assert len(json_content['detailed_findings']) == 1
    
    def test_api_response_format(self, json_template, sample_report):
        """Test API response formatting."""
        api_response = json_template.format_api_response(sample_report)
        
        assert api_response['status'] == 'success'
        assert 'data' in api_response
        assert 'links' in api_response
        assert 'timestamp' in api_response
        
        data = api_response['data']
        assert data['evaluation_id'] == 'json-test-001'
        assert data['overall_score'] == 72.5
        assert data['grade'] == 'B'


class TestSummaryGenerator:
    """Test cases for the SummaryGenerator class."""
    
    @pytest.fixture
    def summary_generator(self):
        """Create a SummaryGenerator instance."""
        return SummaryGenerator()
    
    @pytest.fixture
    def high_quality_report(self):
        """Create a high-quality evaluation report."""
        return EvaluationReport(
            evaluation_id="high-quality-001",
            overall_score=92.0,
            grade=Grade.A,
            dimension_scores=DimensionScores(95, 90, 88, 85, 80),
            summary=EvaluationSummary(2, 0, True),
            detailed_findings=[
                Finding("Minor Style", Severity.LOW, "test.c", 10, 5, "Minor style issue", "")
            ],
            recommendations=["Minor style improvements"]
        )
    
    @pytest.fixture
    def poor_quality_report(self):
        """Create a poor-quality evaluation report."""
        return EvaluationReport(
            evaluation_id="poor-quality-001",
            overall_score=35.0,
            grade=Grade.F,
            dimension_scores=DimensionScores(40, 30, 35, 45, 20),
            summary=EvaluationSummary(15, 5, False),
            detailed_findings=[
                Finding("Buffer Overflow", Severity.CRITICAL, "test.c", 10, 5, "Critical issue", ""),
                Finding("Memory Leak", Severity.CRITICAL, "test.c", 20, 8, "Another critical issue", "")
            ],
            recommendations=["Major rework required"]
        )
    
    def test_executive_summary_high_quality(self, summary_generator, high_quality_report):
        """Test executive summary generation for high-quality code."""
        summary = summary_generator.generate_executive_summary(high_quality_report)
        
        assert 'overall_assessment' in summary
        assert 'excellent quality' in summary['overall_assessment'].lower()
        assert 'key_strengths' in summary
        assert len(summary['key_strengths']) > 0
        assert 'critical_issues' in summary
        assert 'business_impact' in summary
        assert 'recommendation' in summary
        assert 'approve' in summary['recommendation'].lower()
    
    def test_executive_summary_poor_quality(self, summary_generator, poor_quality_report):
        """Test executive summary generation for poor-quality code."""
        summary = summary_generator.generate_executive_summary(poor_quality_report)
        
        assert 'overall_assessment' in summary
        assert 'fails quality standards' in summary['overall_assessment'].lower()
        assert 'critical_issues' in summary
        assert len(summary['critical_issues']) > 0
        assert 'recommendation' in summary
        assert 'do not deploy' in summary['recommendation'].lower()
    
    def test_risk_assessment(self, summary_generator, poor_quality_report):
        """Test risk assessment functionality."""
        summary = summary_generator.generate_executive_summary(poor_quality_report)
        risk_assessment = summary['risk_assessment']
        
        assert 'level' in risk_assessment
        assert 'description' in risk_assessment
        assert risk_assessment['level'] == 'Critical'
    
    def test_next_steps_generation(self, summary_generator, poor_quality_report):
        """Test next steps generation."""
        summary = summary_generator.generate_executive_summary(poor_quality_report)
        next_steps = summary['next_steps']
        
        assert isinstance(next_steps, list)
        assert len(next_steps) > 0
        assert any('compilation' in step.lower() for step in next_steps)
        assert any('critical' in step.lower() for step in next_steps)


if __name__ == '__main__':
    pytest.main([__file__])