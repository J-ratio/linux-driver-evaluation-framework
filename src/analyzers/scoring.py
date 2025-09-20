"""
Scoring and grading system for the Linux Driver Evaluation Framework.

This module implements the weighted scoring algorithm that combines results from
multiple analyzers to produce overall quality scores and letter grades.
"""

from typing import Dict, List, Any, Tuple
from dataclasses import dataclass
import math
from src.models.evaluation import (
    AnalysisResult, Finding, Grade, DimensionScores,
    EvaluationSummary, EvaluationReport
)
from src.core.interfaces import ScoringSystem, Severity


@dataclass
class ScoringWeights:
    """Weights for different evaluation dimensions."""
    correctness: float = 0.40      # 40%
    security: float = 0.25         # 25%
    code_quality: float = 0.20     # 20%
    performance: float = 0.10      # 10%
    advanced_features: float = 0.05 # 5%
    
    def validate(self) -> bool:
        """Validate that weights sum to 1.0."""
        total = (self.correctness + self.security + self.code_quality + 
                self.performance + self.advanced_features)
        return abs(total - 1.0) < 0.001  # Allow for floating point precision


class WeightedScoringSystem(ScoringSystem):
    """
    Implements weighted scoring algorithm for driver evaluation.
    
    Combines results from multiple analyzers using predefined weights:
    - Correctness: 40%
    - Security: 25% 
    - Code Quality: 20%
    - Performance: 10%
    - Advanced Features: 5%
    """
    
    def __init__(self, weights: ScoringWeights = None):
        """Initialize with scoring weights."""
        self.scoring_weights = weights or ScoringWeights()
        if not self.scoring_weights.validate():
            raise ValueError("Scoring weights must sum to 1.0")
    
    @property
    def weights(self) -> Dict[str, float]:
        """Return the scoring weights for different dimensions."""
        return {
            "correctness": self.scoring_weights.correctness,
            "security": self.scoring_weights.security,
            "code_quality": self.scoring_weights.code_quality,
            "performance": self.scoring_weights.performance,
            "advanced_features": self.scoring_weights.advanced_features
        }
    
    def normalize_score(self, raw_score: float, max_possible: float = 100.0) -> float:
        """
        Normalize a raw score to 0-100 scale.
        
        Args:
            raw_score: Raw score from analyzer
            max_possible: Maximum possible score
            
        Returns:
            Normalized score between 0.0 and 100.0
        """
        if max_possible <= 0:
            return 0.0
        
        normalized = (raw_score / max_possible) * 100.0
        return max(0.0, min(100.0, normalized))
    
    def calculate_severity_penalty(self, findings: List[Finding]) -> float:
        """
        Calculate penalty based on finding severities.
        
        Args:
            findings: List of findings to evaluate
            
        Returns:
            Penalty score (0.0 to 100.0, where 100.0 is maximum penalty)
        """
        if not findings:
            return 0.0
        
        # Severity weights for penalty calculation
        severity_weights = {
            Severity.CRITICAL: 20.0,
            Severity.HIGH: 10.0,
            Severity.MEDIUM: 5.0,
            Severity.LOW: 0.5,
            Severity.INFO: 0.0
        }

        total_penalty = 0.0
        for finding in findings:
            print(severity_weights.get(finding.severity, 0.0))
            total_penalty += severity_weights.get(finding.severity, 0.0)
        
        # Cap penalty at 100.0
        return min(100.0, total_penalty)
    
    def calculate_dimension_score(self, analyzer_results: List[AnalysisResult], 
                                dimension: str) -> float:
        """
        Calculate score for a specific dimension.
        
        Args:
            analyzer_results: Results from analyzers for this dimension
            dimension: Dimension name (correctness, security, etc.)
            
        Returns:
            Dimension score (0.0 to 100.0)
        """
        if not analyzer_results:
            return 0.0
        
        # Filter results for this dimension
        relevant_results = [r for r in analyzer_results if self._is_relevant_analyzer(r.analyzer, dimension)]
        
        if not relevant_results:
            return 0.0
        
        total_score = 0.0
        total_weight = 0.0
        for result in relevant_results:
            print(result.analyzer)
            # Base score starts at 100 and is reduced by penalties
            base_score = 100.0
            # Apply penalty based on findings
            penalty = self.calculate_severity_penalty(result.findings)
            score = max(0.0, base_score - penalty)
            # print(result.findings)
            # Weight by analyzer importance for this dimension
            analyzer_weight = self._get_analyzer_weight(result.analyzer, dimension)
            total_score += score * analyzer_weight
            total_weight += analyzer_weight
        
        if total_weight == 0:
            return 0.0
        
        return total_score / total_weight
    
    def _is_relevant_analyzer(self, analyzer_name: str, dimension: str) -> bool:
        """Check if analyzer is relevant for a dimension."""
        analyzer_dimensions = {
            "compilation": ["correctness"],

            "correctness": ["correctness"],
            "security": ["security"],
            "code_quality": ["code_quality"],
            "performance": ["performance"],
            "advanced_features": ["advanced_features"]
        }
        
        return dimension in analyzer_dimensions.get(analyzer_name, [])
    
    def _get_analyzer_weight(self, analyzer_name: str, dimension: str) -> float:
        """Get weight of analyzer for specific dimension."""
        # Define analyzer weights for each dimension
        weights = {
            "correctness": {
                "compilation": 0.4,

                "correctness": 0.3
            },
            "security": {
                "security": 1.0
            },
            "code_quality": {
                "code_quality": 1.0
            },
            "performance": {
                "performance": 1.0
            },
            "advanced_features": {
                "advanced_features": 1.0
            }
        }
        
        return weights.get(dimension, {}).get(analyzer_name, 0.0)
    
    def get_dimension_scores(self, analyzer_results: List[AnalysisResult]) -> DimensionScores:
        """
        Get scores for individual evaluation dimensions.
        
        Args:
            analyzer_results: List of analysis results
            
        Returns:
            DimensionScores object with scores for each dimension
        """
        return DimensionScores(
            correctness=self.calculate_dimension_score(analyzer_results, "correctness"),
            security=self.calculate_dimension_score(analyzer_results, "security"),
            code_quality=self.calculate_dimension_score(analyzer_results, "code_quality"),
            performance=self.calculate_dimension_score(analyzer_results, "performance"),
            advanced_features=self.calculate_dimension_score(analyzer_results, "advanced_features")
        )
    
    def calculate_score(self, analyzer_results: List[AnalysisResult]) -> float:
        """
        Calculate overall weighted score from analyzer results.
        
        Args:
            analyzer_results: List of analysis results
            
        Returns:
            Overall score (0.0 to 100.0)
        """
        dimension_scores = self.get_dimension_scores(analyzer_results)
        
        # Calculate weighted average
        overall_score = (
            dimension_scores.correctness * self.scoring_weights.correctness +
            dimension_scores.security * self.scoring_weights.security +
            dimension_scores.code_quality * self.scoring_weights.code_quality +
            dimension_scores.performance * self.scoring_weights.performance +
            dimension_scores.advanced_features * self.scoring_weights.advanced_features
        )
        
        return round(overall_score, 2)
    
    def assign_grade(self, score: float) -> Grade:
        """
        Assign letter grade based on overall score.
        
        Grade boundaries:
        - A: 90-100
        - B: 80-89
        - C: 70-79
        - D: 60-69
        - F: 0-59
        
        Args:
            score: Overall score (0.0 to 100.0)
            
        Returns:
            Grade enum value
        """
        if score >= 90.0:
            return Grade.A
        elif score >= 80.0:
            return Grade.B
        elif score >= 70.0:
            return Grade.C
        elif score >= 60.0:
            return Grade.D
        else:
            return Grade.F
    
    def create_evaluation_summary(self, analyzer_results: List[AnalysisResult], 
                                compilation_success: bool = True) -> EvaluationSummary:
        """
        Create evaluation summary from analyzer results.
        
        Args:
            analyzer_results: List of analysis results
            compilation_success: Whether compilation was successful
            
        Returns:
            EvaluationSummary object
        """
        all_findings = []
        for result in analyzer_results:
            all_findings.extend(result.findings)
        
        critical_issues = len([f for f in all_findings if f.severity == Severity.CRITICAL])
        
        return EvaluationSummary(
            total_issues=len(all_findings),
            critical_issues=critical_issues,
            compilation_status=compilation_success
        )
    
    def generate_recommendations(self, analyzer_results: List[AnalysisResult]) -> List[str]:
        """
        Generate recommendations based on analysis results.
        
        Args:
            analyzer_results: List of analysis results
            
        Returns:
            List of recommendation strings
        """
        recommendations = []
        
        # Collect all findings
        all_findings = []
        for result in analyzer_results:
            all_findings.extend(result.findings)
        
        # Count issues by severity
        severity_counts = {severity: 0 for severity in Severity}
        for finding in all_findings:
            severity_counts[finding.severity] += 1
        
        # Generate recommendations based on findings
        if severity_counts[Severity.CRITICAL] > 0:
            recommendations.append(
                f"Address {severity_counts[Severity.CRITICAL]} critical issues immediately. "
                "These may cause system crashes or security vulnerabilities."
            )
        
        if severity_counts[Severity.HIGH] > 0:
            recommendations.append(
                f"Fix {severity_counts[Severity.HIGH]} high-priority issues. "
                "These affect code reliability and maintainability."
            )
        
        if severity_counts[Severity.MEDIUM] > 5:
            recommendations.append(
                "Consider addressing medium-priority issues to improve code quality. "
                "Focus on the most frequent issue types first."
            )
        
        # Add specific recommendations based on analyzer types
        analyzer_names = {result.analyzer for result in analyzer_results}
        
        if "security" in analyzer_names:
            security_findings = [f for result in analyzer_results 
                               if result.analyzer == "security" for f in result.findings]
            if security_findings:
                recommendations.append(
                    "Review security findings carefully. Consider using safer alternatives "
                    "for flagged functions and validate all user inputs."
                )
        
        if "code_quality" in analyzer_names:
            quality_findings = [f for result in analyzer_results 
                              if result.analyzer == "code_quality" for f in result.findings]
            if len(quality_findings) > 10:
                recommendations.append(
                    "Improve code style consistency by following Linux kernel coding standards. "
                    "Consider using automated formatting tools."
                )
        
        return recommendations