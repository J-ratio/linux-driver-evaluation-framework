"""
Result Aggregation System

This module implements the result aggregation engine that collects and
normalizes results from multiple analyzers, resolves conflicts, and
prepares data for scoring.
"""

import logging
from typing import Dict, List, Any, Set, Tuple
from collections import defaultdict
from dataclasses import dataclass

from ..core.interfaces import (
    ResultAggregator, AnalysisResult, Finding, Severity, AnalysisStatus
)


@dataclass
class AggregationConfig:
    """Configuration for result aggregation."""
    enable_deduplication: bool = True
    merge_similar_findings: bool = True
    similarity_threshold: float = 0.8
    severity_weights: Dict[Severity, float] = None
    
    def __post_init__(self):
        if self.severity_weights is None:
            self.severity_weights = {
                Severity.CRITICAL: 1.0,
                Severity.HIGH: 0.8,
                Severity.MEDIUM: 0.6,
                Severity.LOW: 0.4,
                Severity.INFO: 0.2
            }


class StandardResultAggregator(ResultAggregator):
    """
    Standard implementation of result aggregation.
    
    This aggregator collects results from multiple analyzers, deduplicates
    findings, resolves conflicts, and normalizes scores.
    """
    
    def __init__(self, config: AggregationConfig = None):
        self.config = config or AggregationConfig()
        self.logger = logging.getLogger(__name__)
    
    def aggregate(self, results: List[AnalysisResult]) -> Dict[str, Any]:
        """
        Aggregate results from multiple analyzers.
        
        Args:
            results: List of analysis results to aggregate
            
        Returns:
            Aggregated results dictionary
        """
        if not results:
            return self._create_empty_aggregation()
        
        self.logger.info(f"Aggregating results from {len(results)} analyzers")
        
        # Separate successful and failed results
        successful_results = [r for r in results if r.status == AnalysisStatus.SUCCESS]
        failed_results = [r for r in results if r.status == AnalysisStatus.FAILURE]
        warning_results = [r for r in results if r.status == AnalysisStatus.WARNING]
        
        # Collect all findings
        all_findings = []
        for result in successful_results + warning_results:
            all_findings.extend(result.findings)
        
        # Resolve conflicts and deduplicate
        deduplicated_findings = self.resolve_conflicts(results)
        
        # Aggregate metrics
        aggregated_metrics = self._aggregate_metrics(results)
        
        # Calculate summary statistics
        summary_stats = self._calculate_summary_stats(deduplicated_findings, results)
        
        # Organize findings by category
        categorized_findings = self._categorize_findings(deduplicated_findings)
        
        aggregation = {
            "total_analyzers": len(results),
            "successful_analyzers": len(successful_results),
            "failed_analyzers": len(failed_results),
            "warning_analyzers": len(warning_results),
            "total_findings": len(deduplicated_findings),
            "findings": deduplicated_findings,
            "categorized_findings": categorized_findings,
            "metrics": aggregated_metrics,
            "summary": summary_stats,
            "analyzer_results": {r.analyzer: r for r in results}
        }
        
        self.logger.info(f"Aggregation complete: {len(deduplicated_findings)} findings")
        return aggregation
    
    def resolve_conflicts(self, results: List[AnalysisResult]) -> List[Finding]:
        """
        Resolve conflicts between overlapping findings from different analyzers.
        
        Args:
            results: List of analysis results with potential conflicts
            
        Returns:
            Deduplicated list of findings
        """
        if not self.config.enable_deduplication:
            # Return all findings without deduplication
            all_findings = []
            for result in results:
                all_findings.extend(result.findings)
            return all_findings
        
        # Group findings by location (file, line, column)
        location_groups = defaultdict(list)
        for result in results:
            for finding in result.findings:
                location_key = (finding.file, finding.line, finding.column)
                location_groups[location_key].append((finding, result.analyzer))
        
        deduplicated_findings = []
        
        for location_key, findings_with_analyzers in location_groups.items():
            if len(findings_with_analyzers) == 1:
                # No conflict, add the finding as-is
                finding, analyzer = findings_with_analyzers[0]
                deduplicated_findings.append(finding)
            else:
                # Multiple findings at same location, resolve conflict
                resolved_finding = self._resolve_location_conflict(findings_with_analyzers)
                deduplicated_findings.append(resolved_finding)
        
        return deduplicated_findings
    
    def _resolve_location_conflict(
        self, 
        findings_with_analyzers: List[Tuple[Finding, str]]
    ) -> Finding:
        """Resolve conflict when multiple findings exist at the same location."""
        findings = [f for f, _ in findings_with_analyzers]
        analyzers = [a for _, a in findings_with_analyzers]
        
        # If findings are similar, merge them
        if self.config.merge_similar_findings and self._are_findings_similar(findings):
            return self._merge_similar_findings(findings, analyzers)
        
        # Otherwise, keep the finding with highest severity
        highest_severity_finding = max(findings, key=lambda f: self._severity_priority(f.severity))
        
        # Add note about multiple analyzers detecting this issue
        if len(set(analyzers)) > 1:
            highest_severity_finding.message += f" (Detected by: {', '.join(set(analyzers))})"
        
        return highest_severity_finding
    
    def _are_findings_similar(self, findings: List[Finding]) -> bool:
        """Check if findings are similar enough to merge."""
        if len(findings) < 2:
            return True
        
        # Check if all findings have the same type
        types = set(f.type for f in findings)
        if len(types) > 1:
            return False
        
        # Check message similarity (simple approach)
        messages = [f.message.lower() for f in findings]
        base_message = messages[0]
        
        for message in messages[1:]:
            similarity = self._calculate_message_similarity(base_message, message)
            if similarity < self.config.similarity_threshold:
                return False
        
        return True
    
    def _calculate_message_similarity(self, msg1: str, msg2: str) -> float:
        """Calculate similarity between two messages (simple implementation)."""
        words1 = set(msg1.split())
        words2 = set(msg2.split())
        
        if not words1 and not words2:
            return 1.0
        if not words1 or not words2:
            return 0.0
        
        intersection = words1.intersection(words2)
        union = words1.union(words2)
        
        return len(intersection) / len(union)
    
    def _merge_similar_findings(self, findings: List[Finding], analyzers: List[str]) -> Finding:
        """Merge similar findings into a single finding."""
        # Use the finding with highest severity as base
        base_finding = max(findings, key=lambda f: self._severity_priority(f.severity))
        
        # Combine messages and recommendations
        unique_messages = list(dict.fromkeys(f.message for f in findings))
        unique_recommendations = list(dict.fromkeys(f.recommendation for f in findings if f.recommendation))
        
        merged_message = "; ".join(unique_messages)
        merged_recommendation = "; ".join(unique_recommendations)
        
        # Add analyzer information
        unique_analyzers = list(dict.fromkeys(analyzers))
        if len(unique_analyzers) > 1:
            merged_message += f" (Detected by: {', '.join(unique_analyzers)})"
        
        return Finding(
            type=base_finding.type,
            severity=base_finding.severity,
            file=base_finding.file,
            line=base_finding.line,
            column=base_finding.column,
            message=merged_message,
            recommendation=merged_recommendation
        )
    
    def _severity_priority(self, severity: Severity) -> int:
        """Get numeric priority for severity (higher = more severe)."""
        priority_map = {
            Severity.CRITICAL: 5,
            Severity.HIGH: 4,
            Severity.MEDIUM: 3,
            Severity.LOW: 2,
            Severity.INFO: 1
        }
        return priority_map.get(severity, 0)
    
    def _aggregate_metrics(self, results: List[AnalysisResult]) -> Dict[str, Any]:
        """Aggregate metrics from all analyzer results."""
        aggregated = {
            "analyzer_scores": {},
            "execution_times": {},
            "total_execution_time": 0.0,
            "analyzer_metrics": {}
        }
        
        for result in results:
            analyzer_name = result.analyzer
            aggregated["analyzer_scores"][analyzer_name] = result.score
            
            if "execution_time" in result.metrics:
                exec_time = result.metrics["execution_time"]
                aggregated["execution_times"][analyzer_name] = exec_time
                aggregated["total_execution_time"] += exec_time
            
            # Store analyzer-specific metrics
            aggregated["analyzer_metrics"][analyzer_name] = result.metrics
        
        return aggregated
    
    def _calculate_summary_stats(
        self, 
        findings: List[Finding], 
        results: List[AnalysisResult]
    ) -> Dict[str, Any]:
        """Calculate summary statistics for the aggregated results."""
        severity_counts = defaultdict(int)
        type_counts = defaultdict(int)
        file_counts = defaultdict(int)
        
        for finding in findings:
            severity_counts[finding.severity.value] += 1
            type_counts[finding.type] += 1
            file_counts[finding.file] += 1
        
        # Calculate weighted severity score
        weighted_severity_score = 0.0
        total_findings = len(findings)
        
        if total_findings > 0:
            for finding in findings:
                weight = self.config.severity_weights.get(finding.severity, 0.0)
                weighted_severity_score += weight
            weighted_severity_score /= total_findings
        
        return {
            "total_findings": total_findings,
            "severity_counts": dict(severity_counts),
            "type_counts": dict(type_counts),
            "files_with_issues": len(file_counts),
            "file_issue_counts": dict(file_counts),
            "weighted_severity_score": weighted_severity_score,
            "most_common_issue_type": max(type_counts.items(), key=lambda x: x[1])[0] if type_counts else None,
            "most_problematic_file": max(file_counts.items(), key=lambda x: x[1])[0] if file_counts else None
        }
    
    def _categorize_findings(self, findings: List[Finding]) -> Dict[str, List[Finding]]:
        """Organize findings by category/type."""
        categories = defaultdict(list)
        
        for finding in findings:
            # Categorize by type
            categories[finding.type].append(finding)
            
            # Also categorize by severity
            severity_category = f"severity_{finding.severity.value}"
            categories[severity_category].append(finding)
        
        return dict(categories)
    
    def _create_empty_aggregation(self) -> Dict[str, Any]:
        """Create empty aggregation result when no results are provided."""
        return {
            "total_analyzers": 0,
            "successful_analyzers": 0,
            "failed_analyzers": 0,
            "warning_analyzers": 0,
            "total_findings": 0,
            "findings": [],
            "categorized_findings": {},
            "metrics": {
                "analyzer_scores": {},
                "execution_times": {},
                "total_execution_time": 0.0,
                "analyzer_metrics": {}
            },
            "summary": {
                "total_findings": 0,
                "severity_counts": {},
                "type_counts": {},
                "files_with_issues": 0,
                "file_issue_counts": {},
                "weighted_severity_score": 0.0,
                "most_common_issue_type": None,
                "most_problematic_file": None
            },
            "analyzer_results": {}
        }