"""Real analysis pipeline integration for web interface."""

import logging
import asyncio
import tempfile
import os
from typing import List, Dict, Any, Optional
from pathlib import Path

from src.models.evaluation import (
    EvaluationRequest, EvaluationReport, SourceFile,
    DimensionScores, EvaluationSummary, Grade, Finding, Severity
)
from src.analyzers.compilation import CompilationAnalyzer
from src.analyzers.correctness_analyzer import CorrectnessAnalyzer
from src.analyzers.security_analyzer import SecurityScanner
from src.analyzers.code_quality_analyzer import CodeQualityAnalyzer
from src.analyzers.performance_analyzer import PerformanceAnalyzer
from src.analyzers.advanced_features_analyzer import AdvancedFeaturesAnalyzer
from src.analyzers.aggregator import EvaluationResultsAggregator
from src.analyzers.scoring import WeightedScoringSystem
from src.core.interfaces import AnalysisResult


class AnalysisPipeline:
    """Real analysis pipeline using actual analyzers."""
    
    def __init__(self):
        """Initialize the real analysis pipeline."""
        self.logger = logging.getLogger(__name__)
        
        # Initialize non-compilation analyzers (compilation analyzer is created dynamically)
        self.analyzers = {
            'correctness': CorrectnessAnalyzer(),
            'security': SecurityScanner(),
            'code_quality': CodeQualityAnalyzer(),
            'performance': PerformanceAnalyzer(),
            'advanced_features': AdvancedFeaturesAnalyzer()
        }
        
        # Initialize scoring and aggregation
        self.scoring_system = WeightedScoringSystem()
        self.aggregator = EvaluationResultsAggregator(self.scoring_system)
        
        # Default configuration for analyzers
        self.default_config = {
            'compilation': {
                'kernel_version': '5.15',
                'target_architecture': 'x86_64',
                'enable_warnings': True
            },
            'correctness': {
                'enable_clang_static_analyzer': True,
                'enable_pattern_matching': True
            },
            'security': {
                'enable_buffer_overflow_detection': True,
                'enable_race_condition_detection': True,
                'enable_privilege_escalation_checks': True
            },
            'code_quality': {
                'enable_style_checks': True,
                'enable_complexity_analysis': True,
                'enable_maintainability_metrics': True
            },
            'performance': {
                'enable_algorithmic_analysis': True,
                'enable_memory_usage_analysis': True
            },
            'advanced_features': {
                'check_power_management': True,
                'check_device_tree_support': True,
                'check_sysfs_interface': True
            }
        }
    
    async def evaluate_async(self, evaluation_request: EvaluationRequest, 
                           progress_callback: Optional[callable] = None) -> EvaluationReport:
        """
        Asynchronously evaluate the provided source files using real analyzers.
        
        Args:
            evaluation_request: EvaluationRequest object
            progress_callback: Optional callback for progress updates
            
        Returns:
            EvaluationReport with real analysis results
        """
        try:
            self.logger.info(f"Starting real analysis for evaluation {evaluation_request.id}")
            
            # Create temporary directory for analysis
            with tempfile.TemporaryDirectory() as temp_dir:
                # Write source files to temporary directory
                source_file_paths = await self._prepare_source_files(
                    evaluation_request.source_files, temp_dir
                )
                
                if progress_callback:
                    progress_callback(10, "Source files prepared")
                
                # Create compilation analyzer with correct architecture
                compilation_analyzer = CompilationAnalyzer(
                    kernel_version=evaluation_request.configuration.kernel_version,
                    target_architecture=evaluation_request.configuration.target_architecture
                )
                
                # Create complete analyzer list with compilation analyzer
                all_analyzers = {
                    'compilation': compilation_analyzer,
                    **self.analyzers
                }
                
                # Run analyzers sequentially with progress updates
                analysis_results = []
                total_analyzers = len(all_analyzers)
                
                for i, (analyzer_name, analyzer) in enumerate(all_analyzers.items()):
                    try:
                        self.logger.info(f"Running {analyzer_name} analyzer")
                        
                        if progress_callback:
                            progress = 10 + (i * 60 // total_analyzers)
                            progress_callback(progress, f"Running {analyzer_name} analysis...")
                        
                        # Get analyzer configuration
                        config = self.default_config.get(analyzer_name, {})
                        
                        # Add evaluation-specific configuration
                        if analyzer_name == 'compilation':
                            config['kernel_version'] = evaluation_request.configuration.kernel_version
                            config['target_architecture'] = evaluation_request.configuration.target_architecture
                        
                        # Run analyzer (in thread pool to avoid blocking)
                        result = await asyncio.get_event_loop().run_in_executor(
                            None, analyzer.analyze, source_file_paths, config
                        )

                        # print(result)
                        
                        analysis_results.append(result)
                        self.logger.info(f"Completed {analyzer_name} analyzer")
                        
                    except Exception as e:
                        self.logger.error(f"Analyzer {analyzer_name} failed: {str(e)}")
                        
                        # COMPILATION ANALYZER IS MANDATORY - FAIL IMMEDIATELY
                        if analyzer_name == 'compilation':
                            raise RuntimeError(f"Compilation analyzer failed: {str(e)}. This is mandatory for evaluation.")
                        
                        # For other analyzers, create a failure result
                        failure_result = self._create_failure_result(analyzer_name, str(e))
                        analysis_results.append(failure_result)
                
                if progress_callback:
                    progress_callback(70, "Aggregating results...")
                
                # Aggregate results
                aggregated_data = self.aggregator.aggregate(analysis_results)
                
                if progress_callback:
                    progress_callback(80, "Calculating scores...")
                
                # Generate final report
                report = await self._generate_evaluation_report(
                    evaluation_request.id, aggregated_data, analysis_results
                )
                
                if progress_callback:
                    progress_callback(100, "Evaluation completed")
                
                self.logger.info(f"Completed real analysis for evaluation {evaluation_request.id}")
                return report
                
        except Exception as e:
            self.logger.error(f"Real analysis pipeline failed: {str(e)}")
            # Re-raise the exception to fail the evaluation
            raise
    
    async def _prepare_source_files(self, source_files: List[SourceFile], 
                                  temp_dir: str) -> List[str]:
        """Prepare source files for analysis by writing them to temporary directory."""
        file_paths = []
        
        for source_file in source_files:
            file_path = os.path.join(temp_dir, source_file.filename)
            
            # Write file content
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(source_file.content)
            
            file_paths.append(file_path)
            self.logger.debug(f"Prepared source file: {file_path}")
        
        return file_paths
    
    def _create_failure_result(self, analyzer_name: str, error_message: str) -> AnalysisResult:
        """Create a failure result for an analyzer that failed."""
        return AnalysisResult(
            analyzer=analyzer_name,
            status="failure",
            findings=[Finding(
                type="analyzer_failure",
                severity=Severity.HIGH,
                file="",
                line=0,
                column=0,
                message=f"Analyzer {analyzer_name} failed: {error_message}",
                recommendation="Check system configuration and analyzer dependencies"
            )],
            metrics={"error": error_message, "analyzer_failed": True},
            score=0.0
        )
    
    async def _generate_evaluation_report(self, evaluation_id: str, 
                                        aggregated_data: Dict[str, Any],
                                        analysis_results: List[AnalysisResult]) -> EvaluationReport:
        """Generate the final evaluation report from aggregated data."""
        
        # Extract dimension scores
        dimension_scores_dict = aggregated_data.get('dimension_scores', {})
        dimension_scores = DimensionScores(
            correctness=dimension_scores_dict.get('correctness', 0.0),
            security=dimension_scores_dict.get('security', 0.0),
            code_quality=dimension_scores_dict.get('code_quality', 0.0),
            performance=dimension_scores_dict.get('performance', 0.0),
            advanced_features=dimension_scores_dict.get('advanced_features', 0.0)
        )
        
        # Extract overall score and grade
        overall_score = aggregated_data.get('overall_score', 0.0)
        grade_str = aggregated_data.get('grade', 'F')
        grade = Grade(grade_str)
        
        # Extract findings
        detailed_findings = aggregated_data.get('deduplicated_findings', [])
        
        # Create summary
        summary = EvaluationSummary(
            total_issues=aggregated_data.get('total_findings', 0),
            critical_issues=aggregated_data.get('findings_by_severity', {}).get('critical', 0),
            compilation_status=aggregated_data.get('compilation_success', False)
        )
        
        # Generate recommendations based on findings
        recommendations = self._generate_recommendations(analysis_results, detailed_findings)
        
        return EvaluationReport(
            evaluation_id=evaluation_id,
            overall_score=overall_score,
            grade=grade,
            dimension_scores=dimension_scores,
            summary=summary,
            detailed_findings=detailed_findings,
            recommendations=recommendations
        )
    
    async def _generate_failure_report(self, evaluation_id: str, 
                                     error_message: str) -> EvaluationReport:
        """Generate a failure report when the pipeline fails."""
        
        dimension_scores = DimensionScores(
            correctness=0.0,
            security=0.0,
            code_quality=0.0,
            performance=0.0,
            advanced_features=0.0
        )
        
        summary = EvaluationSummary(
            total_issues=1,
            critical_issues=1,
            compilation_status=False
        )
        
        findings = [Finding(
            type="pipeline_failure",
            severity=Severity.CRITICAL,
            file="",
            line=0,
            column=0,
            message=f"Analysis pipeline failed: {error_message}",
            recommendation="Check system configuration and try again"
        )]
        
        recommendations = [
            "Ensure all required analysis tools are installed and configured",
            "Check that Docker is available for compilation analysis",
            "Verify that source files are valid C code",
            "Contact support if the problem persists"
        ]
        
        return EvaluationReport(
            evaluation_id=evaluation_id,
            overall_score=0.0,
            grade=Grade.F,
            dimension_scores=dimension_scores,
            summary=summary,
            detailed_findings=findings,
            recommendations=recommendations
        )
    
    def _generate_recommendations(self, analysis_results: List[AnalysisResult], 
                                findings: List[Finding]) -> List[str]:
        """Generate recommendations based on analysis results and findings."""
        recommendations = []
        
        # Analyze findings by severity and type
        critical_findings = [f for f in findings if f.severity == Severity.CRITICAL]
        high_findings = [f for f in findings if f.severity == Severity.HIGH]
        
        # Compilation-specific recommendations
        compilation_results = [r for r in analysis_results if r.analyzer == 'compilation']
        if compilation_results and compilation_results[0].status == "failure":
            recommendations.append(
                "Fix compilation errors before proceeding with driver development"
            )
        
        # Security-specific recommendations
        security_findings = [f for f in findings if 'security' in f.type.lower() or 
                           'buffer' in f.type.lower() or 'overflow' in f.type.lower()]
        if security_findings:
            recommendations.append(
                "Address security vulnerabilities to prevent potential exploits"
            )
        
        # Code quality recommendations
        quality_findings = [f for f in findings if 'style' in f.type.lower() or 
                          'complexity' in f.type.lower()]
        if quality_findings:
            recommendations.append(
                "Improve code quality and maintainability by following Linux kernel coding standards"
            )
        
        # Performance recommendations
        performance_findings = [f for f in findings if 'performance' in f.type.lower() or 
                              'efficiency' in f.type.lower()]
        if performance_findings:
            recommendations.append(
                "Optimize performance-critical sections for better system efficiency"
            )
        
        # General recommendations based on severity
        if critical_findings:
            recommendations.append(
                "Critical issues found - immediate attention required before deployment"
            )
        elif high_findings:
            recommendations.append(
                "High-priority issues should be addressed to ensure driver reliability"
            )
        
        # Default recommendations if no specific issues found
        if not recommendations:
            recommendations.extend([
                "Continue following Linux kernel development best practices",
                "Consider adding comprehensive error handling",
                "Implement proper resource cleanup in all code paths",
                "Add thorough documentation for maintainability"
            ])
        
        return recommendations[:5]  # Limit to 5 recommendations
    
    def get_analyzer_status(self) -> Dict[str, Dict[str, Any]]:
        """Get status information about all analyzers."""
        status = {}
        
        for name, analyzer in self.analyzers.items():
            try:
                # Test analyzer configuration
                config = self.default_config.get(name, {})
                is_valid = analyzer.validate_config(config)
                
                status[name] = {
                    "name": analyzer.name,
                    "version": analyzer.version,
                    "configured": is_valid,
                    "available": True
                }
            except Exception as e:
                status[name] = {
                    "name": name,
                    "version": "unknown",
                    "configured": False,
                    "available": False,
                    "error": str(e)
                }
        
        return status