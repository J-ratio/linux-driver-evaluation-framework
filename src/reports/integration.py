"""
Integration module for connecting report generation with the existing evaluation system.

This module provides integration points between the report generation system
and the existing analyzers, scoring, and pipeline components.
"""

from typing import Dict, Any, List, Optional
from pathlib import Path

from ..models.evaluation import EvaluationReport, EvaluationRequest
from ..analyzers.scoring import ScoringSystem
from ..analyzers.aggregator import ResultAggregator
from .generator import ReportGenerator
from .summary import SummaryGenerator


class ReportingIntegration:
    """Integration class for connecting report generation with the evaluation pipeline."""
    
    def __init__(self, output_dir: str = "reports"):
        """
        Initialize the reporting integration.
        
        Args:
            output_dir: Directory to save generated reports
        """
        self.report_generator = ReportGenerator(output_dir)
        self.summary_generator = SummaryGenerator()
    
    def generate_evaluation_reports(
        self,
        evaluation_request: EvaluationRequest,
        evaluation_report: EvaluationReport,
        formats: List[str] = None,
        include_executive_summary: bool = True
    ) -> Dict[str, Any]:
        """
        Generate comprehensive evaluation reports from pipeline results.
        
        Args:
            evaluation_request: Original evaluation request
            evaluation_report: Complete evaluation report
            formats: List of formats to generate ('html', 'pdf', 'json')
            include_executive_summary: Whether to include executive summary
            
        Returns:
            Dictionary containing report paths and metadata
        """
        if formats is None:
            formats = ['html', 'json']
        
        # Generate comprehensive reports
        output_files = self.report_generator.generate_comprehensive_report(
            evaluation_report,
            formats=formats,
            include_executive_summary=include_executive_summary
        )
        
        # Generate API response format
        api_response = self.report_generator.generate_api_response(evaluation_report)
        
        # Generate executive summary if requested
        executive_summary = None
        if include_executive_summary:
            executive_summary = self.summary_generator.generate_executive_summary(
                evaluation_report
            )
        
        return {
            'output_files': output_files,
            'api_response': api_response,
            'executive_summary': executive_summary,
            'evaluation_id': evaluation_report.evaluation_id,
            'generation_metadata': {
                'request_id': evaluation_request.id,
                'source_files': [sf.filename for sf in evaluation_request.source_files],
                'analysis_depth': evaluation_request.configuration.analysis_depth.value,
                'kernel_version': evaluation_request.configuration.kernel_version
            }
        }
    
    def create_summary_report(
        self,
        evaluation_reports: List[EvaluationReport],
        output_filename: str = "summary_report"
    ) -> str:
        """
        Create a summary report from multiple evaluations.
        
        Args:
            evaluation_reports: List of evaluation reports to summarize
            output_filename: Base filename for the summary report
            
        Returns:
            Path to the generated summary report
        """
        # Calculate aggregate statistics
        total_evaluations = len(evaluation_reports)
        avg_score = sum(report.overall_score for report in evaluation_reports) / total_evaluations
        
        grade_distribution = {}
        for report in evaluation_reports:
            grade = report.grade.value
            grade_distribution[grade] = grade_distribution.get(grade, 0) + 1
        
        # Create summary data structure
        summary_data = {
            'total_evaluations': total_evaluations,
            'average_score': avg_score,
            'grade_distribution': grade_distribution,
            'reports': [report.to_dict() for report in evaluation_reports],
            'generation_timestamp': self.report_generator._prepare_report_data(
                evaluation_reports[0] if evaluation_reports else None
            ).get('generation_timestamp')
        }
        
        # Generate summary report (JSON format for now)
        output_path = Path(self.report_generator.output_dir) / f"{output_filename}.json"
        
        import json
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(summary_data, f, indent=2, ensure_ascii=False)
        
        return str(output_path)
    
    def get_report_templates_info(self) -> Dict[str, Any]:
        """
        Get information about available report templates.
        
        Returns:
            Dictionary with template information
        """
        return {
            'available_formats': ['html', 'pdf', 'json'],
            'template_features': {
                'html': [
                    'Interactive web-based report',
                    'Detailed findings with syntax highlighting',
                    'Executive summary section',
                    'Responsive design for mobile viewing',
                    'Print-friendly styling'
                ],
                'pdf': [
                    'Professional document format',
                    'Suitable for archival and sharing',
                    'Consistent formatting across platforms',
                    'Executive summary included'
                ],
                'json': [
                    'Machine-readable format',
                    'API integration friendly',
                    'Complete data structure',
                    'Programmatic access to all findings'
                ]
            },
            'customization_options': {
                'scoring_weights': 'Configurable dimension weights',
                'severity_thresholds': 'Adjustable severity classifications',
                'recommendation_rules': 'Customizable recommendation engine',
                'branding': 'Company logo and styling options'
            }
        }


class ReportConfigurationManager:
    """Manages configuration for report generation and customization."""
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the configuration manager.
        
        Args:
            config_path: Path to configuration file
        """
        self.config_path = config_path or "config/report_config.json"
        self.default_config = self._get_default_config()
        self.config = self._load_config()
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default report configuration."""
        return {
            'output_formats': ['html', 'json'],
            'include_executive_summary': True,
            'severity_colors': {
                'critical': '#e74c3c',
                'high': '#e67e22',
                'medium': '#f39c12',
                'low': '#f1c40f',
                'info': '#3498db'
            },
            'grade_thresholds': {
                'A': 90.0,
                'B': 80.0,
                'C': 70.0,
                'D': 60.0,
                'F': 0.0
            },
            'report_branding': {
                'title': 'Linux Driver Evaluation Report',
                'company_name': 'Linux Driver Evaluation Framework',
                'logo_path': None
            },
            'template_customization': {
                'show_detailed_findings': True,
                'show_recommendations': True,
                'show_metrics': True,
                'max_findings_per_page': 50
            }
        }
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from file or use defaults."""
        try:
            import json
            with open(self.config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
                # Merge with defaults
                merged_config = self.default_config.copy()
                merged_config.update(config)
                return merged_config
        except (FileNotFoundError, json.JSONDecodeError):
            return self.default_config.copy()
    
    def save_config(self, config: Dict[str, Any]) -> bool:
        """
        Save configuration to file.
        
        Args:
            config: Configuration dictionary to save
            
        Returns:
            True if save was successful, False otherwise
        """
        try:
            import json
            from pathlib import Path
            
            # Ensure directory exists
            Path(self.config_path).parent.mkdir(parents=True, exist_ok=True)
            
            with open(self.config_path, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2, ensure_ascii=False)
            
            self.config = config
            return True
        except Exception:
            return False
    
    def get_config(self) -> Dict[str, Any]:
        """Get current configuration."""
        return self.config.copy()
    
    def update_config(self, updates: Dict[str, Any]) -> bool:
        """
        Update configuration with new values.
        
        Args:
            updates: Dictionary of configuration updates
            
        Returns:
            True if update was successful, False otherwise
        """
        try:
            self.config.update(updates)
            return self.save_config(self.config)
        except Exception:
            return False