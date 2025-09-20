"""
Results aggregation engine for the Linux Driver Evaluation Framework.

This module implements result collection, normalization, and conflict resolution
for combining outputs from multiple static analysis tools into a unified report.
"""

from typing import Dict, List, Any, Set, Tuple, Optional
from dataclasses import dataclass, field
from collections import defaultdict
import hashlib
from src.models.evaluation import (
    AnalysisResult, Finding, Severity, EvaluationReport, 
    DimensionScores, EvaluationSummary, Grade
)
from src.core.interfaces import ResultAggregator
from .scoring import WeightedScoringSystem


@dataclass
class ConflictResolutionRule:
    """Rule for resolving conflicts between overlapping findings."""
    priority_order: List[str] = field(default_factory=lambda: [
        "compilation", "security", "correctness", "code_quality", "performance"
    ])
    merge_similar: bool = True
    similarity_threshold: float = 0.8


class EvaluationResultsAggregator(ResultAggregator):
    """
    Aggregates and normalizes results from multiple analyzers.
    
    Handles conflict resolution for overlapping findings and provides
    comprehensive scoring with detailed breakdowns.
    """
    
    def __init__(self, scoring_system: WeightedScoringSystem = None,
                 conflict_rules: ConflictResolutionRule = None):
        """Initialize aggregator with scoring system and conflict resolution rules."""
        self.scoring_system = scoring_system or WeightedScoringSystem()
        self.conflict_rules = conflict_rules or ConflictResolutionRule()
    
    def aggregate(self, results: List[AnalysisResult]) -> Dict[str, Any]:
        """
        Aggregate results from multiple analyzers.
        
        Args:
            results: List of analysis results to aggregate
            
        Returns:
            Aggregated results dictionary with normalized data
        """
        if not results:
            return {
                "analyzers": [],
                "total_findings": 0,
                "findings_by_severity": {s.value: 0 for s in Severity},
                "findings_by_analyzer": {},
                "compilation_success": True,
                "dimension_scores": {},
                "overall_score": 0.0,
                "grade": Grade.F.value
            }
        
        # Resolve conflicts and deduplicate findings
        deduplicated_findings = self.resolve_conflicts(results)
        
        # Calculate dimension scores
        dimension_scores = self.scoring_system.get_dimension_scores(results)
        
        # Calculate overall score and grade
        overall_score = self.scoring_system.calculate_score(results)
        grade = self.scoring_system.assign_grade(overall_score)
        
        # Aggregate findings by severity and analyzer
        findings_by_severity = self._count_findings_by_severity(deduplicated_findings)
        findings_by_analyzer = self._group_findings_by_analyzer(results)
        
        # Check compilation status
        compilation_success = self._check_compilation_success(results)
        
        return {
            "analyzers": [r.analyzer for r in results],
            "total_findings": len(deduplicated_findings),
            "findings_by_severity": findings_by_severity,
            "findings_by_analyzer": findings_by_analyzer,
            "compilation_success": compilation_success,
            "dimension_scores": dimension_scores.to_dict(),
            "overall_score": overall_score,
            "grade": grade.value,
            "deduplicated_findings": deduplicated_findings
        }
    
    def resolve_conflicts(self, results: List[AnalysisResult]) -> List[Finding]:
        """
        Resolve conflicts between overlapping findings from different analyzers.
        
        Args:
            results: List of analysis results with potential conflicts
            
        Returns:
            Deduplicated list of findings with conflicts resolved
        """
        if not results:
            return []
        
        # Collect all findings with their source analyzer
        all_findings = []
        for result in results:
            for finding in result.findings:
                all_findings.append((finding, result.analyzer))
        
        if not all_findings:
            return []
        
        # Group similar findings
        finding_groups = self._group_similar_findings(all_findings)
        
        # Resolve conflicts within each group
        resolved_findings = []
        for group in finding_groups:
            resolved_finding = self._resolve_finding_group(group)
            if resolved_finding:
                resolved_findings.append(resolved_finding)
        
        return resolved_findings
    
    def _group_similar_findings(self, findings_with_analyzer: List[Tuple[Finding, str]]) -> List[List[Tuple[Finding, str]]]:
        """Group similar findings together for conflict resolution."""
        groups = []
        used_indices = set()
        
        for i, (finding1, analyzer1) in enumerate(findings_with_analyzer):
            if i in used_indices:
                continue
            
            # Start a new group with this finding
            group = [(finding1, analyzer1)]
            used_indices.add(i)
            
            # Find similar findings
            for j, (finding2, analyzer2) in enumerate(findings_with_analyzer):
                if j in used_indices or i == j:
                    continue
                
                if self._are_findings_similar(finding1, finding2):
                    group.append((finding2, analyzer2))
                    used_indices.add(j)
            
            groups.append(group)
        
        return groups
    
    def _are_findings_similar(self, finding1: Finding, finding2: Finding) -> bool:
        """Check if two findings are similar enough to be considered duplicates."""
        # Same file and close line numbers
        if (finding1.file == finding2.file and 
            abs(finding1.line - finding2.line) <= 2):
            
            # Similar message content or same type
            similarity = self._calculate_message_similarity(finding1.message, finding2.message)
            same_type = finding1.type == finding2.type
            
            return similarity >= self.conflict_rules.similarity_threshold or same_type
        
        return False
    
    def _calculate_message_similarity(self, msg1: str, msg2: str) -> float:
        """Calculate similarity between two messages using simple word overlap."""
        words1 = set(msg1.lower().split())
        words2 = set(msg2.lower().split())
        
        if not words1 and not words2:
            return 1.0
        if not words1 or not words2:
            return 0.0
        
        intersection = words1.intersection(words2)
        
        # Use Jaccard similarity but with a bias toward common important words
        important_words = {'buffer', 'overflow', 'error', 'warning', 'critical', 'security', 'vulnerability'}
        important_intersection = intersection.intersection(important_words)
        
        # Boost similarity if important words match
        base_similarity = len(intersection) / len(words1.union(words2))
        if important_intersection:
            base_similarity = min(1.0, base_similarity + 0.3)
        
        return base_similarity
    
    def _resolve_finding_group(self, group: List[Tuple[Finding, str]]) -> Optional[Finding]:
        """Resolve conflicts within a group of similar findings."""
        if not group:
            return None
        
        if len(group) == 1:
            return group[0][0]
        
        # Sort by analyzer priority
        priority_map = {analyzer: i for i, analyzer in enumerate(self.conflict_rules.priority_order)}
        group.sort(key=lambda x: priority_map.get(x[1], len(self.conflict_rules.priority_order)))
        
        # Take the finding from the highest priority analyzer
        primary_finding, primary_analyzer = group[0]
        
        # Merge information from other findings if beneficial
        merged_finding = self._merge_findings([f for f, a in group], primary_finding)
        
        return merged_finding
    
    def _merge_findings(self, findings: List[Finding], primary: Finding) -> Finding:
        """Merge multiple findings into a single comprehensive finding."""
        # Use primary finding as base
        merged = Finding(
            type=primary.type,
            severity=primary.severity,
            file=primary.file,
            line=primary.line,
            column=primary.column,
            message=primary.message,
            recommendation=primary.recommendation
        )
        
        # Enhance with information from other findings
        all_recommendations = set()
        highest_severity = primary.severity
        
        for finding in findings:
            if finding.recommendation:
                all_recommendations.add(finding.recommendation)
            
            # Use highest severity
            if self._severity_level(finding.severity) > self._severity_level(highest_severity):
                highest_severity = finding.severity
        
        merged.severity = highest_severity
        
        # Combine recommendations
        if all_recommendations:
            merged.recommendation = "; ".join(sorted(all_recommendations))
        
        return merged
    
    def _severity_level(self, severity: Severity) -> int:
        """Convert severity to numeric level for comparison."""
        levels = {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4
        }
        return levels.get(severity, 0)
    
    def _count_findings_by_severity(self, findings: List[Finding]) -> Dict[str, int]:
        """Count findings by severity level."""
        counts = {severity.value: 0 for severity in Severity}
        for finding in findings:
            counts[finding.severity.value] += 1
        return counts
    
    def _group_findings_by_analyzer(self, results: List[AnalysisResult]) -> Dict[str, Dict[str, Any]]:
        """Group findings and metrics by analyzer."""
        grouped = {}
        for result in results:
            grouped[result.analyzer] = {
                "status": result.status.value,
                "finding_count": len(result.findings),
                "findings_by_severity": self._count_findings_by_severity(result.findings),
                "metrics": result.metrics
            }
        return grouped
    
    def _check_compilation_success(self, results: List[AnalysisResult]) -> bool:
        """Check if compilation was successful based on analyzer results."""
        for result in results:
            if result.analyzer == "compilation":
                # Compilation is successful if it's SUCCESS or WARNING (warnings are OK)
                return result.status.value in ["success", "warning"]
        return True  # Assume success if no compilation analyzer present
    
    def create_comprehensive_report(self, evaluation_id: str, 
                                  results: List[AnalysisResult]) -> EvaluationReport:
        """
        Create a comprehensive evaluation report from analyzer results.
        
        Args:
            evaluation_id: Unique identifier for this evaluation
            results: List of analysis results
            
        Returns:
            Complete EvaluationReport object
        """
        # Aggregate results
        aggregated = self.aggregate(results)
        
        # Create dimension scores object
        dimension_scores = DimensionScores.from_dict(aggregated["dimension_scores"])
        
        # Create summary
        summary = EvaluationSummary(
            total_issues=aggregated["total_findings"],
            critical_issues=aggregated["findings_by_severity"].get("critical", 0),
            compilation_status=aggregated["compilation_success"]
        )
        
        # Generate recommendations
        recommendations = self.scoring_system.generate_recommendations(results)
        
        # Create final report
        report = EvaluationReport(
            evaluation_id=evaluation_id,
            overall_score=aggregated["overall_score"],
            grade=Grade(aggregated["grade"]),
            dimension_scores=dimension_scores,
            summary=summary,
            detailed_findings=aggregated.get("deduplicated_findings", []),
            recommendations=recommendations
        )
        
        return report
    
    def get_detailed_breakdown(self, results: List[AnalysisResult]) -> Dict[str, Any]:
        """
        Get detailed breakdown of scoring and analysis results.
        
        Args:
            results: List of analysis results
            
        Returns:
            Detailed breakdown dictionary
        """
        aggregated = self.aggregate(results)
        
        # Calculate per-analyzer contributions
        analyzer_contributions = {}
        for result in results:
            analyzer_contributions[result.analyzer] = {
                "findings": len(result.findings),
                "critical_findings": len([f for f in result.findings if f.severity == Severity.CRITICAL]),
                "weight_in_scoring": self._calculate_analyzer_weight(result.analyzer),
                "status": result.status.value
            }
        
        # Calculate dimension breakdowns
        dimension_breakdown = {}
        dimension_scores = DimensionScores.from_dict(aggregated["dimension_scores"])
        
        for dimension, score in dimension_scores.to_dict().items():
            weight = self.scoring_system.weights[dimension]
            contribution = score * weight
            dimension_breakdown[dimension] = {
                "score": score,
                "weight": weight,
                "contribution_to_overall": contribution,
                "grade": self.scoring_system.assign_grade(score).value
            }
        
        return {
            "overall_score": aggregated["overall_score"],
            "overall_grade": aggregated["grade"],
            "dimension_breakdown": dimension_breakdown,
            "analyzer_contributions": analyzer_contributions,
            "conflict_resolution_stats": {
                "original_findings": sum(len(r.findings) for r in results),
                "deduplicated_findings": aggregated["total_findings"],
                "conflicts_resolved": sum(len(r.findings) for r in results) - aggregated["total_findings"]
            }
        }
    
    def _calculate_analyzer_weight(self, analyzer_name: str) -> float:
        """Calculate the overall weight of an analyzer in the scoring system."""
        # This is a simplified calculation - in practice, this would be more complex
        analyzer_dimension_map = {
            "compilation": ["correctness"],

            "correctness": ["correctness"],
            "security": ["security"],
            "code_quality": ["code_quality"],
            "performance": ["performance"],
            "advanced_features": ["advanced_features"]
        }
        
        dimensions = analyzer_dimension_map.get(analyzer_name, [])
        total_weight = 0.0
        
        for dimension in dimensions:
            total_weight += self.scoring_system.weights.get(dimension, 0.0)
        
        return total_weight